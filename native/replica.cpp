#include <algorithm>
#include <array>
#include <cfenv>
#include <cstring>
#include <memory>
#include <new>
#include <immintrin.h>
#include "randomx.h"
#include "virtual_machine.hpp"
#include "blake2/blake2.h"

#define API extern "C"

namespace {
constexpr size_t scratchpad_size = 2097152;
constexpr size_t sub_chunk_size = 8192;

struct State {
    randomx_cache* cache = nullptr;
    std::array<randomx_vm*, 8> machines{};
    ~State() {
        for (auto machine : machines) {
            if (machine) randomx_destroy_vm(machine);
        }
        if (cache) randomx_release_cache(cache);
    }
};

void mix_near(randomx_vm* machine) {
    auto words = static_cast<uint32_t*>(const_cast<void*>(machine->getScratchpad()));
    uint32_t state = ~uint32_t(0);
    for (size_t i = 0; i < scratchpad_size / 4; i += 2) {
        state = ~_mm_crc32_u32(state, words[i]);
        words[i] ^= state;
    }
    for (size_t i = 1; i < scratchpad_size / 4; i += 2) {
        state = ~_mm_crc32_u32(state, words[i]);
        words[i] ^= state;
    }
}

void copy_cross_lane(randomx_vm** source, randomx_vm** destination,
                     size_t start, size_t output, size_t length) {
    while (length) {
        const size_t source_lane = start / scratchpad_size;
        const size_t source_offset = start % scratchpad_size;
        const size_t destination_lane = output / scratchpad_size;
        const size_t destination_offset = output % scratchpad_size;
        const size_t count = std::min(length, std::min(scratchpad_size - source_offset,
                                                     scratchpad_size - destination_offset));
        const auto input = reinterpret_cast<const unsigned char*>(source[source_lane]->getScratchpad());
        auto target = static_cast<unsigned char*>(const_cast<void*>(destination[destination_lane]->getScratchpad()));
        std::memcpy(target + destination_offset, input + source_offset, count);
        start += count;
        output += count;
        length -= count;
    }
}

void mix_far(randomx_vm** source, randomx_vm** destination) {
    constexpr size_t block_size = 6;
    constexpr size_t blocks = scratchpad_size / block_size;
    size_t output = 0;
    for (size_t block = 0; block < blocks; ++block) {
        for (size_t lane = 0; lane < 4; ++lane) {
            copy_cross_lane(source, destination, lane * scratchpad_size + block * block_size,
                            output, block_size);
            output += block_size;
        }
    }
    for (size_t lane = 0; lane < 4; ++lane) {
        copy_cross_lane(source, destination, lane * scratchpad_size + blocks * block_size,
                        output, scratchpad_size % block_size);
        output += scratchpad_size % block_size;
    }
}

struct FloatingEnvironment {
    fenv_t previous;
    FloatingEnvironment() { std::fegetenv(&previous); }
    ~FloatingEnvironment() { std::fesetenv(&previous); }
};
}

API State* ar_io_replica_create() {
    try {
        auto state = std::unique_ptr<State>(new State);
        auto flags = randomx_get_flags();
        if (flags & RANDOMX_FLAG_JIT) flags |= RANDOMX_FLAG_SECURE;
        state->cache = randomx_alloc_cache(flags);
        if (!state->cache) return nullptr;
        const char key[] = "default arweave 2.5 pack key";
        randomx_init_cache(state->cache, key, sizeof(key) - 1);
        for (auto& machine : state->machines) {
            machine = randomx_create_vm(flags, state->cache, nullptr);
            if (!machine) return nullptr;
        }
        return state.release();
    } catch (...) {
        return nullptr;
    }
}

API void ar_io_replica_destroy(State* state) {
    delete state;
}

// Arweave RX2: four lanes, three rounds of six programs, six-byte far-mix blocks.
// Lane seeds are SHA-256(entropy_key || lane_number), with lane numbers 1 through 4.
API int ar_io_replica_slice(State* state, const unsigned char* seeds,
                            size_t slice_index, unsigned char* output) {
    if (!state || !seeds || !output || slice_index >= 1024) return 0;
    try {
        FloatingEnvironment floating_environment;
        struct alignas(16) Hash { uint64_t words[8]; } hashes[4];
        for (size_t lane = 0; lane < 4; ++lane) {
            if (randomx_blake2b(hashes[lane].words, 64, seeds + lane * 32, 32,
                               nullptr, 0) != 0) return 0;
            state->machines[lane]->initScratchpad(hashes[lane].words);
        }
        for (size_t round = 0; round < 3; ++round) {
            const size_t input = round % 2 == 0 ? 0 : 4;
            const size_t target = round % 2 == 0 ? 4 : 0;
            for (size_t lane = 0; lane < 4; ++lane) {
                auto machine = state->machines[input + lane];
                machine->resetRoundingMode();
                for (size_t program = 0; program < 6; ++program) {
                    machine->run(hashes[lane].words);
                    if (randomx_blake2b(hashes[lane].words, 64, machine->getRegisterFile(),
                                       sizeof(randomx::RegisterFile), nullptr, 0) != 0) return 0;
                }
                mix_near(machine);
            }
            mix_far(state->machines.data() + input, state->machines.data() + target);
        }
        const size_t position = slice_index * sub_chunk_size;
        const auto scratchpad = reinterpret_cast<const unsigned char*>(
            state->machines[4 + position / scratchpad_size]->getScratchpad());
        std::memcpy(output, scratchpad + position % scratchpad_size, sub_chunk_size);
        return 1;
    } catch (...) {
        return 0;
    }
}
