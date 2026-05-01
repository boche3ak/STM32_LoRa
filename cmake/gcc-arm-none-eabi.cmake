set(CMAKE_SYSTEM_NAME               Generic)
set(CMAKE_SYSTEM_PROCESSOR          arm)

set(CMAKE_C_COMPILER_ID             GNU)
set(CMAKE_CXX_COMPILER_ID           GNU)

set(TOOLCHAIN_PREFIX                arm-none-eabi-)
set(CMAKE_C_COMPILER                ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_ASM_COMPILER              ${CMAKE_C_COMPILER})
set(CMAKE_CXX_COMPILER              ${TOOLCHAIN_PREFIX}g++)
set(CMAKE_LINKER                    ${TOOLCHAIN_PREFIX}g++)
set(CMAKE_OBJCOPY                   ${TOOLCHAIN_PREFIX}objcopy)
set(CMAKE_OBJDUMP                   ${TOOLCHAIN_PREFIX}objdump)
set(CMAKE_NM                        ${TOOLCHAIN_PREFIX}nm)
set(CMAKE_SIZE                      ${TOOLCHAIN_PREFIX}size)

set(CMAKE_EXECUTABLE_SUFFIX_ASM     ".elf")
set(CMAKE_EXECUTABLE_SUFFIX_C       ".elf")
set(CMAKE_EXECUTABLE_SUFFIX_CXX     ".elf")

set(CMAKE_TRY_COMPILE_TARGET_TYPE   STATIC_LIBRARY)

# CPU flag: must reach every compilation unit in the project, including
# third-party OBJECT libraries (e.g. STM32_Drivers). Setting it in
# CMAKE_C/CXX_FLAGS is the only way to guarantee that — target_compile_options
# on the executable alone would leave libraries without it.
set(CMAKE_C_FLAGS   "-mcpu=cortex-m3")
set(CMAKE_CXX_FLAGS "-mcpu=cortex-m3")

# ASM flags: assembler-specific, not inherited by C/C++ targets
set(CMAKE_ASM_FLAGS "-mcpu=cortex-m3 -x assembler-with-cpp -MMD -MP")

# Linker flags: global by nature, must be set here
set(CMAKE_EXE_LINKER_FLAGS
    "-mcpu=cortex-m3 \
    -T \"${CMAKE_SOURCE_DIR}/STM32F103C8TX_FLASH.ld\" \
    --specs=nano.specs \
    -Wl,-Map=${CMAKE_PROJECT_NAME}.map \
    -Wl,--gc-sections \
    -Wl,--print-memory-usage"
)

set(TOOLCHAIN_LINK_LIBRARIES "m")
