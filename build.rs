fn main() {
    // ArweaveTeam/RandomX eef4dc86485473457ee42e39d88a78caaf4c9035, with RX2 constants.
    println!("cargo:rerun-if-changed=native");
    let directory = cmake::Config::new("native").profile("Release").build();
    println!("cargo:rustc-link-search=native={}/lib", directory.display());
    println!("cargo:rustc-link-lib=static=ario_packing");
    println!("cargo:rustc-link-lib=static=randomx");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if std::env::var("CARGO_CFG_TARGET_ENV").unwrap() != "msvc" {
        println!(
            "cargo:rustc-link-lib={}",
            if target_os == "macos" {
                "c++"
            } else {
                "stdc++"
            }
        );
        println!("cargo:rustc-link-lib=m");
    }
}
