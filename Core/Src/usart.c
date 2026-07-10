/**
  ******************************************************************************
  * @file    usart.c
  * @brief   USART1 initialisation via direct register access.
  *
  *          Avoids the HAL UART driver entirely to minimise flash footprint.
  *          Used exclusively by the uart_prov provisioning module.
  *
  *  GPIO mapping (no AFIO remap needed for USART1 default pins):
  *    PA9  — USART1_TX : alternate-function push-pull, 50 MHz
  *    PA10 — USART1_RX : input with internal pull-up (holds RX idle-high when disconnected)
  ******************************************************************************
  */

#include "usart.h"

void MX_USART1_UART_Init(void)
{
    /* Enable USART1 and GPIOA clocks on APB2 */
    RCC->APB2ENR |= RCC_APB2ENR_USART1EN | RCC_APB2ENR_IOPAEN;

    /*
     * Configure PA9 (USART1_TX) in CRH:
     *   bits [7:4] → MODE9[1:0] = 11 (50 MHz), CNF9[1:0] = 10 (AF push-pull)
     *   nibble value: 0b1011 = 0xB
     */
    GPIOA->CRH = (GPIOA->CRH & ~(0xFu << 4u)) | (0xBu << 4u);

    /*
     * Configure PA10 (USART1_RX) in CRH:
     *   bits [11:8] → MODE10[1:0] = 00 (input), CNF10[1:0] = 10 (input with pull-up/down)
     *   nibble value: 0b1000 = 0x8
     * ODR10 = 1 selects pull-UP, holding RX high (= UART idle) when nothing is connected.
     * This prevents the floating pin from registering noise as false start bits.
     */
    GPIOA->CRH = (GPIOA->CRH & ~(0xFu << 8u)) | (0x8u << 8u);
    GPIOA->ODR |= (1u << 10u);   /* pull-up on PA10 */

    /* Baud rate: fPCLK2 / 9600  (BRR integer+fractional division) */
    USART1->BRR = (uint16_t)(HAL_RCC_GetPCLK2Freq() / 9600u);

    /* 8 data bits, no parity, 1 stop bit (CR2 reset = 1 stop bit) */
    USART1->CR2 = 0u;
    USART1->CR3 = 0u;  /* no flow control, no DMA */

    /* Enable USART, transmitter, and receiver */
    USART1->CR1 = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
}

void MX_USART1_UART_DeInit(void)
{
    USART1->CR1 = 0u;                                 /* disable USART      */
    RCC->APB2ENR &= ~RCC_APB2ENR_USART1EN;           /* gate off clock     */

    /* Restore PA9 and PA10 to floating inputs */
    GPIOA->CRH = (GPIOA->CRH & ~(0xFu << 4u)) | (0x4u << 4u);   /* PA9  */
    GPIOA->CRH = (GPIOA->CRH & ~(0xFu << 8u)) | (0x4u << 8u);   /* PA10 */
}
