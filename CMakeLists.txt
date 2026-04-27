cmake_minimum_required(VERSION 3.22)

# ---------------------------------------------------------------------------
# Toolchain selection
# Pass on the command line:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/gcc-arm-none-eabi.cmake -B build
# Or uncomment to bake in the default toolchain:
# set(CMAKE_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/cmake/gcc-arm-none-eabi.cmake CACHE STRING "")
# ---------------------------------------------------------------------------

project(STM32_Lora C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)   # required for GNU extensions used by HAL/CMSIS

# Create the main executable target.
# Sources are added by cmake/stm32cubemx/CMakeLists.txt via add_subdirectory.
add_executable(${CMAKE_PROJECT_NAME})

# ---------------------------------------------------------------------------
# CubeMX-managed HAL drivers and generated application sources.
# NOTE: do not add user sources here - CubeMX regenerates this subdirectory.
# ---------------------------------------------------------------------------
add_subdirectory(cmake/stm32cubemx)

# ---------------------------------------------------------------------------
# User-added sources and libraries (not managed by CubeMX)
# ---------------------------------------------------------------------------

# LoRa driver
target_sources(${CMAKE_PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/LoRa/LoRa.c
)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/LoRa
)

# STM32 Cryptographic middleware (pre-compiled static library for Cortex-M3)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/Middlewares/STM32_Cryptographic/include
)
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/Middlewares/STM32_Cryptographic/lib
)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE STM32Cryptographic_CM3)
