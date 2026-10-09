cmake_minimum_required(VERSION 3.15)
project(ArIoPacking LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(RX_SOURCE randomx/src)
add_library(randomx STATIC
    ${RX_SOURCE}/aes_hash.cpp
    ${RX_SOURCE}/argon2_ref.c
    ${RX_SOURCE}/argon2_ssse3.c
    ${RX_SOURCE}/argon2_avx2.c
    ${RX_SOURCE}/bytecode_machine.cpp
    ${RX_SOURCE}/cpu.cpp
    ${RX_SOURCE}/dataset.cpp
    ${RX_SOURCE}/soft_aes.cpp
    ${RX_SOURCE}/virtual_memory.c
    ${RX_SOURCE}/vm_interpreted.cpp
    ${RX_SOURCE}/allocator.cpp
    ${RX_SOURCE}/assembly_generator_x86.cpp
    ${RX_SOURCE}/instruction.cpp
    ${RX_SOURCE}/randomx.cpp
    ${RX_SOURCE}/superscalar.cpp
    ${RX_SOURCE}/vm_compiled.cpp
    ${RX_SOURCE}/vm_interpreted_light.cpp
    ${RX_SOURCE}/argon2_core.c
    ${RX_SOURCE}/blake2_generator.cpp
    ${RX_SOURCE}/instructions_portable.cpp
    ${RX_SOURCE}/reciprocal.c
    ${RX_SOURCE}/virtual_machine.cpp
    ${RX_SOURCE}/vm_compiled_light.cpp
    ${RX_SOURCE}/blake2/blake2b.c
    ${RX_SOURCE}/jit_compiler_x86.cpp
)
target_include_directories(randomx PUBLIC ${RX_SOURCE})
target_compile_definitions(randomx PUBLIC
    RANDOMX_ARGON_MEMORY=524288
    RANDOMX_DATASET_BASE_SIZE=2147483648
    RANDOMX_SCRATCHPAD_L1=2097152
    RANDOMX_SCRATCHPAD_L2=2097152
    RANDOMX_SCRATCHPAD_L3=2097152
)
if(MSVC)
    enable_language(ASM_MASM)
    target_sources(randomx PRIVATE ${RX_SOURCE}/jit_compiler_x86_static.asm)
    target_compile_options(randomx PRIVATE $<$<COMPILE_LANGUAGE:ASM_MASM>:/I${CMAKE_CURRENT_SOURCE_DIR}/randomx/src>)
    set_source_files_properties(${RX_SOURCE}/argon2_avx2.c PROPERTIES COMPILE_OPTIONS /arch:AVX2)
else()
    enable_language(ASM)
    target_sources(randomx PRIVATE ${RX_SOURCE}/jit_compiler_x86_static.S)
    target_compile_options(randomx PRIVATE -maes)
    set_source_files_properties(${RX_SOURCE}/argon2_ssse3.c PROPERTIES COMPILE_OPTIONS -mssse3)
    set_source_files_properties(${RX_SOURCE}/argon2_avx2.c PROPERTIES COMPILE_OPTIONS -mavx2)
endif()
add_library(ario_packing STATIC replica.cpp)
target_link_libraries(ario_packing PRIVATE randomx)
if(NOT MSVC)
    target_compile_options(ario_packing PRIVATE -msse4.2 -fno-strict-aliasing)
endif()

install(TARGETS ario_packing randomx ARCHIVE DESTINATION lib)
