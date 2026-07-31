/**
  ******************************************************************************
  * @file    board.h
  * @brief   Central board pin map and status-LED action macros.
  *
  *          Single source of truth for the application-facing pins (status
  *          LEDs and the Challenger/Transponder select switch) so they are
  *          not duplicated across translation units.
  *
  *          CubeMX-owned peripheral pins (DIO0, NSS, RST, ...) remain defined
  *          in the generated main.h, which is included below; do not move them
  *          here. The physical pin configuration itself lives in
  *          MX_GPIO_Init() (gpio.c).
  ******************************************************************************
  */

#ifndef BOARD_H
#define BOARD_H

#include "main.h"   /* CubeMX-generated peripheral pins: DIO0_*, NSS_*, RST_* */

/* ---------------------------------------------------------------------------
 * Application pins (must match the schematics and MX_GPIO_Init in gpio.c)
 * ------------------------------------------------------------------------- */
/* PA8 - physical switch to select Challenger or Transponder */
#define WHOAMI_PORT          GPIOA
#define WHOAMI_PIN           GPIO_PIN_8

/* PA2 - external LED, FRIEND/FOE indication, e.g. in front of the POV cam */
#define FOF_LED_PORT         GPIOA
#define FOF_LED_PIN          GPIO_PIN_2

/* PA3 - external LED, power-on / provisioning indication */
#define POWERON_LED_PORT     GPIOA
#define POWERON_LED_PIN      GPIO_PIN_3

/* PC13 - standard bluepill on-board LED, heartbeat / debug only (active low) */
#define HEARTBEAT_LED_PORT   GPIOC
#define HEARTBEAT_LED_PIN    GPIO_PIN_13

/* ---------------------------------------------------------------------------
 * Semantic action macros
 * ------------------------------------------------------------------------- */
#define PIN_READ_WHOAMI                  HAL_GPIO_ReadPin(WHOAMI_PORT, WHOAMI_PIN)
#define PIN_WRITE_STAT_FRIEND_FOF(state) HAL_GPIO_WritePin(FOF_LED_PORT, FOF_LED_PIN, (state))
#define PIN_WRITE_STAT_POWERON(state)    HAL_GPIO_WritePin(POWERON_LED_PORT, POWERON_LED_PIN, (state))
#define PIN_WRITE_STAT_HEARTBEAT(state)  HAL_GPIO_WritePin(HEARTBEAT_LED_PORT, HEARTBEAT_LED_PIN, (state))

/* FRIEND/FOE polarity on the FoF LED */
#define STAT_FRIEND                      GPIO_PIN_SET
#define STAT_FOE                         GPIO_PIN_RESET

#endif /* BOARD_H */
