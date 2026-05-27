/**
  ******************************************************************************
  * @file    usart.h
  * @brief   USART1 bare-register initialisation / de-initialisation.
  *
  *          PA9  = USART1_TX  (AF push-pull, 50 MHz)
  *          PA10 = USART1_RX  (input floating)
  *          9600 baud, 8N1, polling.
  ******************************************************************************
  */

#ifndef __USART_H
#define __USART_H

#ifdef __cplusplus
extern "C" {
#endif

#include "main.h"

void MX_USART1_UART_Init(void);
void MX_USART1_UART_DeInit(void);

#ifdef __cplusplus
}
#endif

#endif /* __USART_H */
