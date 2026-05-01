## Document References

[STM32F103 Datasheet](https://www.st.com/resource/en/datasheet/stm32f103c8.pdf)

[Semtec SX1278 Datasheet](https://cdn-shop.adafruit.com/product-files/3179/sx1276_77_78_79.pdf)

## Code Guidelines

We align with the basic [Google C++ Code Style Guide](https://google.github.io/styleguide/cppguide.html)
Any deviation shall be documented in this section.

## Feature development workflow

✅Ticket as a task -> separate branch -> commit with ticket reference

❌ Direct commits in master are not allowed, please create a branch.

## Merge strategy:

Gate: at least one peer review approval **and** buildable code

Git merge: fast forward with rebase - *this will create a strait main branch with no dubious merge commits.*

## Howto build:

This is a cmake project. Use the following commands to generate and build:

`cmake -DCMAKE_TOOLCHAIN_FILE=cmake/gcc-arm-none-eabi.cmake -DCMAKE_BUILD_TYPE=Debug -B build`

`cmake --build build`

