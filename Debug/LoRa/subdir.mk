################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (13.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../LoRa/LoRa.c 

C_DEPS += \
./LoRa/LoRa.d 

OBJS += \
./LoRa/LoRa.o 


# Each subdirectory must supply rules for building sources it contributes
LoRa/%.o LoRa/%.su LoRa/%.cyclo: ../LoRa/%.c LoRa/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m3 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32F103xB -c -I../Core/Inc -I../Drivers/STM32F1xx_HAL_Driver/Inc/Legacy -I../Drivers/STM32F1xx_HAL_Driver/Inc -I../Drivers/CMSIS/Device/ST/STM32F1xx/Include -I../Drivers/CMSIS/Include -I/home/serhii/STM32CubeIDE/workspace_1.19.2/STM_LoRa/LoRa -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfloat-abi=soft -mthumb -o "$@"

clean: clean-LoRa

clean-LoRa:
	-$(RM) ./LoRa/LoRa.cyclo ./LoRa/LoRa.d ./LoRa/LoRa.o ./LoRa/LoRa.su

.PHONY: clean-LoRa

