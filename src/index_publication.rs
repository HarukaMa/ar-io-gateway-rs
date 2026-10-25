//! Index Sharing publisher (protocol version 1, ar-io-node r85/r86).
//!
//! Serves the bands under `AR_IO_INDEXES_DIR/<index>/<band>/` as a signed
//! publication, with deterministic hybrid torrents, a WebSeed and RSS feeds.
//! Only `cdb64-root-tx` bands are published. Hashing runs on a dedicated
//! thread; HTTP handlers only read the current immutable view.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use axum::body::Bytes;
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};

const SIGNING_PREFIX: &[u8] = b"ar-io-index-publication/v1\n";
const KIND: &str = "cdb64-root-tx";
const MANIFEST_FILE: &str = "manifest.json";
const STATE_DIR: &str = ".state";
const PIECE_LENGTH: u64 = 256 * 1024;
const BLOCK: usize = 16 * 1024;
const TTL: Duration = Duration::from_secs(24 * 60 * 60);
const SCAN_INTERVAL: Duration = Duration::from_secs(60);
const MAX_INDEXES: usize = 64;
const MAX_BANDS: usize = 1024;
const MAX_FILES: usize = 1024;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const FEED_TTL_MINUTES: u32 = 30;
const FEED_NAMESPACE: &str = "urn:ar-io:index-feed:1";
// Object.prototype members, refused as names by upstream readers.
const RESERVED: &[&str] = &[
    "__proto__",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
];

pub(crate) fn valid_index_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !RESERVED.contains(&value)
}

pub(crate) fn valid_path_segment(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !value.contains("..")
        && value != "."
        && !RESERVED.contains(&value)
}

/// RFC 8785 canonical JSON. Only integers are accepted as numbers.
pub(crate) fn canonical_json(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => {
            ensure!(
                number.is_u64() || number.is_i64(),
                "canonical JSON supports only integers"
            );
            out.push_str(&number.to_string());
        }
        Value::String(text) => out.push_str(&serde_json::to_string(text)?),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                write_canonical(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

enum Bencode {
    Int(u64),
    Bytes(Vec<u8>),
    List(Vec<Bencode>),
    Dict(BTreeMap<Vec<u8>, Bencode>),
}

impl Bencode {
    fn text(value: &str) -> Self {
        Self::Bytes(value.as_bytes().to_vec())
    }

    fn dict<const N: usize>(entries: [(&str, Bencode); N]) -> Self {
        Self::Dict(
            entries
                .into_iter()
                .map(|(key, value)| (key.as_bytes().to_vec(), value))
                .collect(),
        )
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Int(value) => out.extend_from_slice(format!("i{value}e").as_bytes()),
            Self::Bytes(bytes) => {
                out.extend_from_slice(format!("{}:", bytes.len()).as_bytes());
                out.extend_from_slice(bytes);
            }
            Self::List(items) => {
                out.push(b'l');
                for item in items {
                    item.encode(out);
                }
                out.push(b'e');
            }
            Self::Dict(entries) => {
                out.push(b'd');
                for (key, value) in entries {
                    Self::Bytes(key.clone()).encode(out);
                    value.encode(out);
                }
                out.push(b'e');
            }
        }
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Upstream `torrentNameForFiles`: publishers of the same bytes share it.
fn torrent_name(files: &[CachedFile]) -> String {
    let mut sorted: Vec<_> = files.iter().collect();
    sorted.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let mut hash = Sha256::new();
    for file in sorted {
        hash.update(format!("{}\0{}\0{}\n", file.name, file.size, file.sha256).as_bytes());
    }
    hex(&hash.finalize())[..16].to_owned()
}

struct V1Pieces {
    hashes: Vec<u8>,
    hash: Sha1,
    filled: u64,
    piece_length: u64,
}

impl V1Pieces {
    fn update(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let take = ((self.piece_length - self.filled) as usize).min(bytes.len());
            self.hash.update(&bytes[..take]);
            self.filled += take as u64;
            bytes = &bytes[take..];
            if self.filled == self.piece_length {
                self.flush();
            }
        }
    }

    fn flush(&mut self) {
        let hash = std::mem::replace(&mut self.hash, Sha1::new());
        self.hashes.extend_from_slice(&hash.finalize());
        self.filled = 0;
    }

    fn finish(mut self) -> Vec<u8> {
        if self.filled > 0 {
            self.flush();
        }
        self.hashes
    }
}

/// BEP 52 file tree root and, for files longer than a piece, the piece layer.
/// Mirrors upstream `merkle`, which matches libtorrent 2.0.13.
fn merkle(mut layer: Vec<[u8; 32]>, length: u64, piece_length: u64) -> ([u8; 32], Option<Vec<u8>>) {
    let per_piece = piece_length as usize / BLOCK;
    layer.resize(layer.len().next_power_of_two(), [0; 32]);
    let mut covered = 1;
    let mut piece_layer = (covered == per_piece).then(|| layer.clone());
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|pair| {
                let mut hash = Sha256::new();
                hash.update(pair[0]);
                hash.update(pair[1]);
                hash.finalize().into()
            })
            .collect();
        covered *= 2;
        if covered == per_piece {
            piece_layer = Some(layer.clone());
        }
    }
    if length <= piece_length {
        return (layer[0], None);
    }
    let pieces = length.div_ceil(piece_length) as usize;
    let piece_layer = piece_layer
        .unwrap_or_default()
        .into_iter()
        .take(pieces)
        .flatten()
        .collect();
    (layer[0], Some(piece_layer))
}

struct Built {
    files: Vec<CachedFile>,
    torrent_name: String,
    infohash_v1: String,
    infohash_v2: String,
    torrent: Vec<u8>,
}

/// Hash every file once and build the band's deterministic hybrid torrent,
/// named by its files unless `name` is given.
fn build_torrent(
    dir: &Path,
    files: &[(String, u64, u64)],
    piece_length: u64,
    fixed_name: Option<&str>,
) -> Result<Built> {
    let mut v1 = V1Pieces {
        hashes: Vec::new(),
        hash: Sha1::new(),
        filled: 0,
        piece_length,
    };
    let mut described = Vec::with_capacity(files.len());
    let mut list = Vec::new();
    let mut tree = BTreeMap::new();
    let mut layers = BTreeMap::new();
    let mut buffer = vec![0; 1024 * 1024];
    for (name, size, modified_ns) in files {
        let mut file =
            fs::File::open(dir.join(name)).with_context(|| format!("cannot open {name}"))?;
        let mut whole = Sha256::new();
        let mut block = Sha256::new();
        let mut in_block = 0;
        let mut leaves = Vec::new();
        let mut length = 0_u64;
        loop {
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).with_context(|| format!("cannot read {name}")),
            };
            let mut chunk = &buffer[..read];
            whole.update(chunk);
            v1.update(chunk);
            length += read as u64;
            while !chunk.is_empty() {
                let take = (BLOCK - in_block).min(chunk.len());
                block.update(&chunk[..take]);
                in_block += take;
                chunk = &chunk[take..];
                if in_block == BLOCK {
                    leaves.push(
                        std::mem::replace(&mut block, Sha256::new())
                            .finalize()
                            .into(),
                    );
                    in_block = 0;
                }
            }
        }
        ensure!(length == *size, "{name} changed while it was hashed");
        if in_block > 0 || leaves.is_empty() {
            leaves.push(block.finalize().into());
        }
        described.push(CachedFile {
            name: name.clone(),
            size: length,
            modified_ns: *modified_ns,
            sha256: hex(&whole.finalize()),
        });
        list.push(Bencode::dict([
            ("length", Bencode::Int(length)),
            ("path", Bencode::List(vec![Bencode::text(name)])),
        ]));
        let mut entry = BTreeMap::from([(b"length".to_vec(), Bencode::Int(length))]);
        if length > 0 {
            let (root, layer) = merkle(leaves, length, piece_length);
            entry.insert(b"pieces root".to_vec(), Bencode::Bytes(root.to_vec()));
            if let Some(layer) = layer {
                layers.insert(root.to_vec(), Bencode::Bytes(layer));
            }
        }
        tree.insert(
            name.as_bytes().to_vec(),
            Bencode::Dict(BTreeMap::from([(Vec::new(), Bencode::Dict(entry))])),
        );
        let remainder = length % piece_length;
        if remainder != 0 {
            let pad = piece_length - remainder;
            v1.update(&vec![0; pad as usize]);
            list.push(Bencode::dict([
                ("attr", Bencode::text("p")),
                ("length", Bencode::Int(pad)),
                (
                    "path",
                    Bencode::List(vec![Bencode::text(".pad"), Bencode::text(&pad.to_string())]),
                ),
            ]));
        }
    }
    let torrent_name = fixed_name.map_or_else(|| torrent_name(&described), str::to_owned);
    let info = Bencode::dict([
        ("file tree", Bencode::Dict(tree)),
        ("files", Bencode::List(list)),
        ("meta version", Bencode::Int(2)),
        ("name", Bencode::text(&torrent_name)),
        ("piece length", Bencode::Int(piece_length)),
        ("pieces", Bencode::Bytes(v1.finish())),
    ])
    .to_vec();
    let infohash_v1 = hex(&Sha1::digest(&info));
    let infohash_v2 = hex(&Sha256::digest(&info));
    // The info dictionary is spliced in as encoded, so the infohashes hold.
    let mut torrent = b"d4:info".to_vec();
    torrent.extend_from_slice(&info);
    torrent.extend_from_slice(b"12:piece layers");
    Bencode::Dict(layers).encode(&mut torrent);
    torrent.push(b'e');
    Ok(Built {
        files: described,
        torrent_name,
        infohash_v1,
        infohash_v2,
        torrent,
    })
}

/// The torrent as served: the stored one plus this gateway's WebSeed.
fn with_web_seed(torrent: &[u8], web_seed: &str) -> Vec<u8> {
    let mut out = torrent[..torrent.len() - 1].to_vec();
    // "url-list" sorts after "info" and "piece layers", the only other keys.
    out.extend_from_slice(b"8:url-listl");
    Bencode::text(web_seed).encode(&mut out);
    out.extend_from_slice(b"ee");
    out
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CachedFile {
    name: String,
    size: u64,
    modified_ns: u64,
    sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedBand {
    files: Vec<CachedFile>,
    torrent_name: String,
    infohash_v1: String,
    infohash_v2: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    bands: BTreeMap<String, CachedBand>,
    issued_ms: u64,
}

pub(crate) struct PublishedFile {
    pub(crate) path: PathBuf,
    pub(crate) size: u64,
    pub(crate) modified_ns: u64,
    pub(crate) sha256: String,
}

pub(crate) struct Served {
    pub(crate) body: Bytes,
    pub(crate) sha256: String,
}

/// One publication and everything it names.
pub(crate) struct View {
    pub(crate) document: Bytes,
    pub(crate) sha256: String,
    pub(crate) names: Vec<String>,
    pub(crate) files: HashMap<String, Arc<PublishedFile>>,
    pub(crate) blobs: HashMap<String, Arc<PublishedFile>>,
    pub(crate) web_seeds: HashMap<String, Arc<PublishedFile>>,
    pub(crate) torrents: HashMap<String, Served>,
    pub(crate) feeds: HashMap<String, Served>,
}

struct Band {
    id: String,
    dir: PathBuf,
    cached: CachedBand,
    height_range: Option<Value>,
    records: u64,
}

pub(crate) struct Publisher {
    dir: PathBuf,
    origin: String,
    host: String,
    wallet: String,
    key: SigningKey,
    view: RwLock<Option<Arc<View>>>,
}

impl Publisher {
    pub(crate) fn start(
        dir: PathBuf,
        host: &str,
        wallet: &str,
        key: SigningKey,
    ) -> Result<Arc<Self>> {
        ensure!(
            dir.is_dir(),
            "AR_IO_INDEXES_DIR {} is not a directory",
            dir.display()
        );
        fs::create_dir_all(dir.join(STATE_DIR).join("torrents"))
            .context("cannot create the index publication state directory")?;
        let publisher = Arc::new(Self {
            origin: format!("https://{host}"),
            host: host.to_owned(),
            wallet: wallet.to_owned(),
            key,
            dir,
            view: RwLock::new(None),
        });
        let worker = Arc::clone(&publisher);
        std::thread::Builder::new()
            .name("index-publisher".into())
            .spawn(move || {
                loop {
                    if let Err(error) = worker.publish_once(SystemTime::now()) {
                        eprintln!("index publication failed: {error:#}");
                    }
                    std::thread::sleep(SCAN_INTERVAL);
                }
            })
            .context("cannot start the index publisher")?;
        Ok(publisher)
    }

    pub(crate) fn view(&self) -> Option<Arc<View>> {
        self.view.read().clone()
    }

    fn state_path(&self, name: &str) -> PathBuf {
        self.dir.join(STATE_DIR).join(name)
    }

    fn publish_once(&self, now: SystemTime) -> Result<()> {
        let mut state: State = match fs::read(self.state_path("state.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("invalid publisher state")?,
            Err(error) if error.kind() == ErrorKind::NotFound => State::default(),
            Err(error) => return Err(error).context("cannot read publisher state"),
        };
        let mut indexes: BTreeMap<String, Vec<Band>> = BTreeMap::new();
        for (name, dir) in subdirectories(&self.dir)? {
            if !valid_index_name(&name) {
                continue;
            }
            let mut bands = Vec::new();
            for (id, band_dir) in subdirectories(&dir)? {
                if !valid_path_segment(&id) {
                    continue;
                }
                let key = format!("{name}/{id}");
                match self.describe(&id, &band_dir, state.bands.get(&key)) {
                    Ok(band) => bands.push(band),
                    Err(error) => eprintln!("index band {key} is not publishable: {error:#}"),
                }
            }
            ensure!(bands.len() <= MAX_BANDS, "index {name} has too many bands");
            if !bands.is_empty() {
                indexes.insert(name, bands);
            }
        }
        ensure!(indexes.len() <= MAX_INDEXES, "too many indexes");
        state.bands = indexes
            .iter()
            .flat_map(|(name, bands)| {
                bands
                    .iter()
                    .map(move |band| (format!("{name}/{}", band.id), band.cached.clone()))
            })
            .collect();
        if indexes.is_empty() {
            *self.view.write() = None;
            return write_atomic(&self.state_path("state.json"), &serde_json::to_vec(&state)?);
        }

        let entries = Value::Array(
            indexes
                .iter()
                .map(|(name, bands)| {
                    json!({
                        "name": name,
                        "kind": KIND,
                        "bands": bands.iter().map(|band| self.band_entry(name, band)).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        );
        let current = match fs::read(self.state_path("publication.json")) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("cannot read the current publication"),
        };
        let current_document = current
            .as_deref()
            .map(serde_json::from_slice::<Value>)
            .transpose()
            .context("invalid current publication")?;
        let now_ms = unix_ms(now)?;
        let unchanged = current_document.as_ref().is_some_and(|document| {
            document["publisher"] == self.wallet.as_str()
                && document["signature"]["keyId"] == self.key_id().as_str()
                && canonical_json(&document["indexes"]).ok() == canonical_json(&entries).ok()
                && now_ms.saturating_sub(state.issued_ms) < TTL.as_millis() as u64 / 2
        });
        let document = if unchanged {
            current.expect("an unchanged publication exists")
        } else {
            let sequence = current_document
                .as_ref()
                .and_then(|document| document["sequence"].as_u64())
                .unwrap_or(0)
                + 1;
            let previous = current.as_deref().map(|bytes| hex(&Sha256::digest(bytes)));
            let document = self.sign(sequence, previous, now, entries)?;
            write_atomic(&self.state_path("publication.json"), &document)?;
            state.issued_ms = now_ms;
            eprintln!("published index manifest sequence={sequence}");
            document
        };
        write_atomic(&self.state_path("state.json"), &serde_json::to_vec(&state)?)?;
        let view = self.build_view(&indexes, document, state.issued_ms)?;
        *self.view.write() = Some(Arc::new(view));
        self.remove_unlisted_torrents(&indexes);
        Ok(())
    }

    fn key_id(&self) -> String {
        bs58::encode(self.key.verifying_key().as_bytes()).into_string()
    }

    fn describe(&self, id: &str, dir: &Path, cached: Option<&CachedBand>) -> Result<Band> {
        let manifest_path = dir.join(MANIFEST_FILE);
        let length = fs::metadata(&manifest_path)
            .context("band has no manifest.json")?
            .len();
        ensure!(length <= MAX_MANIFEST_BYTES, "manifest.json is too large");
        let manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path)?).context("invalid manifest.json")?;
        let mut names = BTreeSet::from([MANIFEST_FILE.to_owned()]);
        for partition in manifest["partitions"]
            .as_array()
            .context("manifest.json has no partitions")?
        {
            let location = &partition["location"];
            ensure!(
                location["type"] == "file",
                "a published band may only carry local partition files"
            );
            let filename = location["filename"]
                .as_str()
                .context("partition has no filename")?;
            ensure!(
                valid_path_segment(filename),
                "invalid partition filename {filename}"
            );
            names.insert(filename.to_owned());
        }
        ensure!(
            names.len() > 1,
            "manifest.json names no local partition files"
        );
        ensure!(names.len() <= MAX_FILES, "band has too many files");
        let records = manifest["totalRecords"]
            .as_u64()
            .context("manifest.json has no totalRecords")?;
        let height_range = match &manifest["metadata"]["heightRange"] {
            Value::Null => None,
            range @ Value::Array(items)
                if items.len() == 2
                    && items[0].is_u64()
                    && (items[1].is_u64() || items[1].is_null()) =>
            {
                Some(range.clone())
            }
            _ => bail!("invalid heightRange in manifest.json"),
        };
        let mut stats = Vec::with_capacity(names.len());
        for name in names {
            let metadata = fs::symlink_metadata(dir.join(&name))
                .with_context(|| format!("band names {name}, which is not present"))?;
            ensure!(metadata.is_file(), "{name} is not a regular file");
            stats.push((name, metadata.len(), modified_ns(&metadata)?));
        }
        let reusable = cached.filter(|cached| {
            cached.files.len() == stats.len()
                && cached
                    .files
                    .iter()
                    .zip(&stats)
                    .all(|(file, (name, size, modified))| {
                        &file.name == name && file.size == *size && file.modified_ns == *modified
                    })
                && self
                    .state_path("torrents")
                    .join(format!("{}.torrent", cached.infohash_v1))
                    .is_file()
        });
        let cached = match reusable {
            Some(cached) => cached.clone(),
            None => {
                eprintln!("hashing index band {}", dir.display());
                let built = build_torrent(dir, &stats, PIECE_LENGTH, None)?;
                write_atomic(
                    &self
                        .state_path("torrents")
                        .join(format!("{}.torrent", built.infohash_v1)),
                    &built.torrent,
                )?;
                CachedBand {
                    files: built.files,
                    torrent_name: built.torrent_name,
                    infohash_v1: built.infohash_v1,
                    infohash_v2: built.infohash_v2,
                }
            }
        };
        Ok(Band {
            id: id.to_owned(),
            dir: dir.to_owned(),
            cached,
            height_range,
            records,
        })
    }

    fn band_entry(&self, index: &str, band: &Band) -> Value {
        let cached = &band.cached;
        let mut entry = json!({
            "id": band.id,
            "files": cached.files.iter().map(|file| json!({
                "name": file.name,
                "size": file.size,
                "sha256": file.sha256,
            })).collect::<Vec<_>>(),
            "records": band.records,
            "http": { "baseUrl": format!("/ar-io/indexes/{index}/{}/", band.id) },
            "torrent": {
                "infohashV1": cached.infohash_v1,
                "infohashV2": cached.infohash_v2,
                "magnet": format!(
                    "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}&dn={}",
                    cached.infohash_v1, cached.infohash_v2, cached.torrent_name
                ),
                "torrentUrl": format!("/ar-io/indexes/torrents/{}.torrent", cached.infohash_v1),
            },
        });
        if let Some(range) = &band.height_range {
            entry["heightRange"] = range.clone();
        }
        entry
    }

    fn sign(
        &self,
        sequence: u64,
        previous: Option<String>,
        now: SystemTime,
        indexes: Value,
    ) -> Result<Vec<u8>> {
        let mut document = json!({
            "version": 1,
            "publisher": self.wallet,
            "sequence": sequence,
            "previousManifestSha256": previous,
            "issuedAt": crate::server::iso_utc_date(now)?,
            "expiresAt": crate::server::iso_utc_date(now + TTL)?,
            "indexes": indexes,
        });
        let mut message = SIGNING_PREFIX.to_vec();
        message.extend_from_slice(canonical_json(&document)?.as_bytes());
        let signature = self.key.sign(&message);
        document["signature"] = json!({
            "alg": "ed25519",
            "keyId": self.key_id(),
            "sig": STANDARD.encode(signature.to_bytes()),
        });
        Ok(canonical_json(&document)?.into_bytes())
    }

    fn build_view(
        &self,
        indexes: &BTreeMap<String, Vec<Band>>,
        document: Vec<u8>,
        issued_ms: u64,
    ) -> Result<View> {
        let parsed: Value = serde_json::from_slice(&document)?;
        let sha256 = hex(&Sha256::digest(&document));
        let web_seed = format!("{}/ar-io/indexes/webseed/", self.origin);
        let mut view = View {
            document: Bytes::from(document),
            sha256,
            names: indexes.keys().cloned().collect(),
            files: HashMap::new(),
            blobs: HashMap::new(),
            web_seeds: HashMap::new(),
            torrents: HashMap::new(),
            feeds: HashMap::new(),
        };
        for (name, bands) in indexes {
            for band in bands {
                let cached = &band.cached;
                for file in &cached.files {
                    let published = Arc::new(PublishedFile {
                        path: band.dir.join(&file.name),
                        size: file.size,
                        modified_ns: file.modified_ns,
                        sha256: file.sha256.clone(),
                    });
                    view.files.insert(
                        format!("{name}/{}/{}", band.id, file.name),
                        Arc::clone(&published),
                    );
                    view.web_seeds.insert(
                        format!("{}/{}", cached.torrent_name, file.name),
                        Arc::clone(&published),
                    );
                    view.blobs.insert(file.sha256.clone(), published);
                }
                let stored = fs::read(
                    self.state_path("torrents")
                        .join(format!("{}.torrent", cached.infohash_v1)),
                )
                .context("cannot read a band torrent")?;
                let body = with_web_seed(&stored, &web_seed);
                view.torrents.insert(
                    cached.infohash_v1.clone(),
                    Served {
                        sha256: hex(&Sha256::digest(&body)),
                        body: Bytes::from(body),
                    },
                );
            }
            let feed = self.render_feed(name, bands, &parsed, &view, issued_ms)?;
            view.feeds.insert(
                name.clone(),
                Served {
                    sha256: hex(&Sha256::digest(&feed)),
                    body: Bytes::from(feed),
                },
            );
        }
        Ok(view)
    }

    /// RSS 2.0 laid out as upstream `rss2` renders `buildIndexBandFeed`.
    fn render_feed(
        &self,
        index: &str,
        bands: &[Band],
        document: &Value,
        view: &View,
        issued_ms: u64,
    ) -> Result<Vec<u8>> {
        let date = http_date(issued_ms)?;
        let origin = &self.origin;
        let mut lines = vec![
            r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_owned(),
            format!(r#"<rss version="2.0" xmlns:ario="{FEED_NAMESPACE}">"#),
            "  <channel>".to_owned(),
            element("    ", "title", &format!("{}: {index}", self.host)),
            element("    ", "link", &format!("{origin}/ar-io/indexes")),
            element(
                "    ",
                "description",
                &format!(
                    "Bands of the {index} index ({KIND}) published by gateway {}, one torrent each. Verify them against the signed publication at {origin}/ar-io/indexes.",
                    self.wallet
                ),
            ),
            element("    ", "lastBuildDate", &date),
            element("    ", "ttl", &FEED_TTL_MINUTES.to_string()),
            element("    ", "ario:publisher", &self.wallet),
            element(
                "    ",
                "ario:sequence",
                &document["sequence"].as_u64().unwrap_or(0).to_string(),
            ),
            element("    ", "ario:publication", &view.sha256),
            element("    ", "ario:index", index),
            element("    ", "ario:kind", KIND),
        ];
        let mut sorted: Vec<&Band> = bands.iter().collect();
        sorted.sort_by(|left, right| {
            let range = |band: &Band| {
                band.height_range.as_ref().map(|range| {
                    (
                        range[0].as_u64().unwrap_or(0),
                        range[1].as_u64().unwrap_or(u64::MAX),
                    )
                })
            };
            match (range(left), range(right)) {
                (Some(left_range), Some(right_range)) if left_range != right_range => {
                    right_range.cmp(&left_range)
                }
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                _ => left.id.cmp(&right.id),
            }
        });
        for band in sorted {
            let cached = &band.cached;
            let heights = band.height_range.as_ref().map_or(String::new(), |range| {
                let end = range[1]
                    .as_u64()
                    .map_or_else(|| "tip".to_owned(), |end| end.to_string());
                format!(" (heights {} to {end})", range[0])
            });
            let size: u64 = cached.files.iter().map(|file| file.size).sum();
            let torrent = view
                .torrents
                .get(&cached.infohash_v1)
                .context("feed band has no torrent")?;
            let item = "      ";
            lines.push("    <item>".to_owned());
            lines.push(element(item, "title", &format!("{}{heights}", band.id)));
            lines.push(format!(
                r#"{item}<guid isPermaLink="false">urn:btih:{}</guid>"#,
                cached.infohash_v1
            ));
            lines.push(element(
                item,
                "description",
                &format!(
                    "{} files, {}, saved in folder {}",
                    cached.files.len(),
                    format_bytes(size),
                    cached.torrent_name
                ),
            ));
            lines.push(element(item, "pubDate", &date));
            lines.push(element(
                item,
                "link",
                &format!(
                    "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}&dn={}",
                    cached.infohash_v1, cached.infohash_v2, cached.torrent_name
                ),
            ));
            lines.push(format!(
                r#"{item}<enclosure url="{}" length="{}" type="application/x-bittorrent"/>"#,
                escape_attribute(&format!(
                    "{origin}/ar-io/indexes/torrents/{}.torrent",
                    cached.infohash_v1
                )),
                torrent.body.len()
            ));
            lines.push(element(item, "ario:band", &band.id));
            lines.push(element(item, "ario:torrentName", &cached.torrent_name));
            lines.push(element(item, "ario:infohashV2", &cached.infohash_v2));
            if let Some(range) = &band.height_range {
                lines.push(element(item, "ario:heightFrom", &range[0].to_string()));
                if let Some(end) = range[1].as_u64() {
                    lines.push(element(item, "ario:heightTo", &end.to_string()));
                }
            }
            lines.push("    </item>".to_owned());
        }
        lines.extend([
            "  </channel>".to_owned(),
            "</rss>".to_owned(),
            String::new(),
        ]);
        Ok(lines.join("\n").into_bytes())
    }

    fn remove_unlisted_torrents(&self, indexes: &BTreeMap<String, Vec<Band>>) {
        let listed: HashSet<String> = indexes
            .values()
            .flatten()
            .map(|band| format!("{}.torrent", band.cached.infohash_v1))
            .collect();
        let Ok(entries) = fs::read_dir(self.state_path("torrents")) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".torrent") && !listed.contains(&name) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

fn subdirectories(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Ok(name) = entry.file_name().into_string() {
            found.push((name, entry.path()));
        }
    }
    found.sort();
    Ok(found)
}

pub(crate) fn modified_ns(metadata: &fs::Metadata) -> Result<u64> {
    Ok(u64::try_from(
        metadata
            .modified()?
            .duration_since(UNIX_EPOCH)
            .context("file time is before Unix epoch")?
            .as_nanos(),
    )?)
}

fn unix_ms(time: SystemTime) -> Result<u64> {
    Ok(u64::try_from(
        time.duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_millis(),
    )?)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary)
        .with_context(|| format!("cannot write {}", temporary.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path).with_context(|| format!("cannot replace {}", path.display()))
}

/// RFC 822 as JavaScript's `toUTCString` writes it.
fn http_date(unix_ms: u64) -> Result<String> {
    let iso = crate::server::iso_utc_date(UNIX_EPOCH + Duration::from_millis(unix_ms))?;
    let month: usize = iso[5..7].parse()?;
    let weekday = (unix_ms / 86_400_000 + 4) % 7;
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    Ok(format!(
        "{}, {} {} {} {} GMT",
        DAYS[weekday as usize],
        &iso[8..10],
        MONTHS[month - 1],
        &iso[0..4],
        &iso[11..19]
    ))
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn escape_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#13;")
}

fn escape_attribute(text: &str) -> String {
    escape_text(text)
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('\n', "&#10;")
        .replace('\t', "&#9;")
}

fn element(indent: &str, name: &str, value: &str) -> String {
    format!("{indent}<{name}>{}</{name}>", escape_text(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys_and_rejects_fractions() {
        let value = json!({"b": [1, "\u{1}\u{e9}"], "a": null, "B": true});
        assert_eq!(
            canonical_json(&value).unwrap(),
            "{\"B\":true,\"a\":null,\"b\":[1,\"\\u0001\u{e9}\"]}"
        );
        assert!(canonical_json(&serde_json::from_str("1.5").unwrap()).is_err());
    }

    /// Infohashes libtorrent 2.0.13 produced for upstream's torrent fixture
    /// (ar-io-node r86 src/index-swarm/torrent.test.ts).
    #[test]
    fn torrents_match_libtorrent() {
        let dir = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for (name, size) in [
            ("a.bin", 1),
            ("b.bin", 16384),
            ("c.bin", 32768),
            ("d.bin", 32769),
            ("e.bin", 100000),
            ("f.bin", 131072),
        ] {
            let bytes: Vec<u8> = (0..usize::div_ceil(size, 32))
                .flat_map(|index| Sha256::digest(format!("{name}:{index}")))
                .take(size)
                .collect();
            fs::write(dir.path().join(name), bytes).unwrap();
            files.push((name.to_owned(), size as u64, 0));
        }
        for (piece_length, v1, v2) in [
            (
                32768,
                "a56bfa2b216a200f068e8b2eee06f4d544c6264d",
                "957642eb4b9046c3e342c500c957bc39cb76dce5574ad7fd27b2279f12178930",
            ),
            (
                16384,
                "32da521f851a555edc043b938baeaf07b58a1c2e",
                "9e5c0d48fd77f26a633562874599531ecc71fe0e8f565b0ea1f28d70db816ba1",
            ),
        ] {
            let built = build_torrent(dir.path(), &files, piece_length, Some("fixture")).unwrap();
            assert_eq!(
                (built.infohash_v1.as_str(), built.infohash_v2.as_str()),
                (v1, v2)
            );
        }
    }

    #[test]
    fn sequence_moves_only_for_new_content_or_age() {
        let root = tempfile::tempdir().unwrap();
        let band = root.path().join("root-tx-index").join("band-a");
        fs::create_dir_all(&band).unwrap();
        fs::create_dir_all(root.path().join(STATE_DIR).join("torrents")).unwrap();
        fs::write(
            band.join(MANIFEST_FILE),
            r#"{"version":1,"totalRecords":1,"metadata":{"heightRange":[10,19]},
               "partitions":[{"prefix":"00","location":{"type":"file","filename":"00.cdb"}}]}"#,
        )
        .unwrap();
        fs::write(band.join("00.cdb"), vec![7; 300_000]).unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        let publisher = Publisher {
            dir: root.path().to_owned(),
            origin: "https://gateway.test".into(),
            host: "gateway.test".into(),
            wallet: bs58::encode(key.verifying_key().as_bytes()).into_string(),
            key: key.clone(),
            view: RwLock::new(None),
        };
        let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let publish = |offset: u64| {
            publisher
                .publish_once(start + Duration::from_secs(offset))
                .unwrap();
            let view = publisher.view().unwrap();
            let document: Value = serde_json::from_slice(&view.document).unwrap();
            (view, document)
        };

        let (first, document) = publish(0);
        assert_eq!(document["sequence"], 1);
        assert_eq!(document["previousManifestSha256"], Value::Null);
        assert_eq!(
            document["indexes"][0]["bands"][0]["heightRange"],
            json!([10, 19])
        );
        let mut unsigned = document.clone();
        let signature = unsigned
            .as_object_mut()
            .unwrap()
            .remove("signature")
            .unwrap();
        let mut message = SIGNING_PREFIX.to_vec();
        message.extend_from_slice(canonical_json(&unsigned).unwrap().as_bytes());
        let sig = STANDARD.decode(signature["sig"].as_str().unwrap()).unwrap();
        key.verifying_key()
            .verify_strict(
                &message,
                &ed25519_dalek::Signature::from_slice(&sig).unwrap(),
            )
            .unwrap();

        let (again, _) = publish(60);
        assert_eq!(
            again.document, first.document,
            "an unchanged scan must not republish"
        );

        fs::write(band.join("00.cdb"), vec![8; 300_001]).unwrap();
        let (changed, document) = publish(120);
        assert_eq!(document["sequence"], 2);
        assert_eq!(document["previousManifestSha256"], first.sha256.as_str());
        let file = &changed.files["root-tx-index/band-a/00.cdb"];
        assert_eq!(file.size, 300_001);
        assert_eq!(file.sha256, hex(&Sha256::digest(vec![8; 300_001])));

        let (_, document) = publish(13 * 60 * 60);
        assert_eq!(
            document["sequence"], 3,
            "a document halfway through its TTL is renewed"
        );
    }
}
