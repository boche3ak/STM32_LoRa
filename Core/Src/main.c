/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 Oleksandr Kotenkov and Sergij Boshe.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "spi.h"
#include "gpio.h"
#include "cmox_crypto.h"

/* Private includes ----------------------------------------------------------*/
#include "stdio.h"
#include "string.h"
#include "LoRa.h"

/* Private typedef -----------------------------------------------------------*/


/* Private define ------------------------------------------------------------*/
/**
 * Abstraction challenger - Transponder definitions
 */
enum {
  Challenger = 0,
  Transponder = 1
};

/**
 * Abstraction Challenge requested/not requested definitions
 */
enum {
  ChallengeNotRequested = 0,
  ChallengeRequested    = 1
};

/**
 * Abstraction function response OK/NOK
 */
enum {
  OK  = 0,
  NOK = 1
};

/* Private macro -------------------------------------------------------------*/

/* pin definitions according to the current schematics*/
#define PIN_READ_WHOAMI                  HAL_GPIO_ReadPin(GPIOA, GPIO_PIN_8)           /* PA8 */
#define PIN_WRITE_STAT_FRIEND_FOF(state) HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, (state)) /* PA2 */
#define PIN_WRITE_STAT_POWERON(state)    HAL_GPIO_WritePin(GPIOA, GPIO_PIN_3, (state)) /* PA3 */
#define STAT_FRIEND                     GPIO_PIN_SET
#define STAT_FOE                        GPIO_PIN_RESET


/* predefined parameters*/
#define TXRX_BUFFER_MAX_LENGTH        128u
#define MAGIC_PATTERN_LEN              4u
#define CHALLENGE_PACKET_LEN          (MAGIC_PATTERN_LEN + 4u + 16u)      /* magic(4) | counter(4) | HMAC(16) */
#define RESPONSE_PACKET_LEN           (MAGIC_PATTERN_LEN + 4u + 4u + 16u) /* magic(4) | echo_counter(4) | rx_ts(4) | HMAC(16) */

#define ECC_WORKING_BUFFER_SIZE        2000u

/* ---------------------------------------------------------------------------
 * Watchdog configuration
 *
 * Comment out WATCHDOG_ENABLED to disable the IWDG (e.g. during debugging).
 * Timeout and delay tolerance are runtime-configurable via the .fof_config
 * flash section (Cfg_WatchdogTimeoutMs, Cfg_ResponseDelayToleranceMs).
 *
 * The IWDG is clocked by the LSI oscillator (~40 kHz on STM32F1).
 * With prescaler /32 each tick is 0.8 ms; maximum timeout ≈ 3276 ms.
 * Reload formula: Cfg_WatchdogTimeoutMs × 40 / 32 − 1
 * ---------------------------------------------------------------------------*/
//#define WATCHDOG_ENABLED
#define WATCHDOG_PRESCALER             IWDG_PRESCALER_32
#define WATCHDOG_RELOAD               ((Cfg_WatchdogTimeoutMs * 40u / 32u) - 1u)

#ifdef WATCHDOG_ENABLED
  #define WATCHDOG_REFRESH()           HAL_IWDG_Refresh(&hiwdg)
#else
  #define WATCHDOG_REFRESH()           ((void)0)
#endif

/* Private variables ---------------------------------------------------------*/
LoRa loRa;
uint8_t TxBuffer[TXRX_BUFFER_MAX_LENGTH];
uint8_t RxBuffer[TXRX_BUFFER_MAX_LENGTH];

uint8_t oldChallengeRequested = ChallengeNotRequested;
static uint8_t stayActive = 1u;
static volatile uint8_t loRaRxReady = 0u;

#ifdef WATCHDOG_ENABLED
static IWDG_HandleTypeDef hiwdg;
#endif

/* ECC context and working buffer */
cmox_ecc_handle_t Ecc_Ctx;
uint8_t Working_Buffer[ECC_WORKING_BUFFER_SIZE];

/**
 * @brief LoRa transmit timeout in milliseconds.
 *        Located in .fof_config for field configurability.
 */
__attribute__((section(".fof_config")))
const uint32_t Cfg_TxTimeoutMs = 500u;

/**
 * @brief Main loop cycle period in microseconds.
 *        Located in .fof_config for field configurability.
 */
__attribute__((section(".fof_config")))
const uint32_t Cfg_MainCycleDelayUs = 2000u;

/**
 * @brief Maximum acceptable challenge–response round-trip time in milliseconds.
 *        Located in .fof_config so a provisioning tool can update it without
 *        reflashing the application.
 */
__attribute__((section(".fof_config")))
const uint32_t Cfg_ResponseDelayToleranceMs = 500u;

/**
 * @brief IWDG timeout in milliseconds.  Used to compute the reload register
 *        value at startup.  Located in .fof_config for field configurability.
 */
__attribute__((section(".fof_config")))
const uint32_t Cfg_WatchdogTimeoutMs = 1000u;

/**
 * @brief This private key shall be located in the NVRAM so the setup device can rewrite it
 */
__attribute__((section(".fof_private_key")))
const uint8_t Private_Key[] =
{
  0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
  0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e, 0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34
};
/**
 * @brief This public key of the counterpart shall be located in the NVRAM so the setup device can rewrite it
 */
__attribute__((section(".fof_remote_public_key")))
const uint8_t Remote_Public_Key[] =
{
  0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
  0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
  0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
  0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac
};

/* Computed data buffer */
uint8_t Computed_Secret[CMOX_ECC_SECP256R1_SECRET_LEN];

/* Magic pattern — section attribute prepares this symbol for placement at a
 * dedicated flash address via the linker script (.fof_magic region). */
__attribute__((section(".fof_magic")))
static const uint8_t Magic_Pattern[MAGIC_PATTERN_LEN] = { 0xF0, 0x0F, 0xDE, 0xAD };

/* ============================================================================
 * TIMING & CLOCK CALIBRATION
 * ============================================================================
 */

// Measure actual HCLK at runtime
static uint32_t hclk_freq = 0u;
static uint32_t hclk_freq_div_mio; //pre-calculated us factor

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);

// Send output to SWO
int _write(int fd, char *ptr, int len) {
  for (int i = 0; i < len; i++) {
    ITM_SendChar(ptr[i]); /* core_cm4.h */
  }
  return len;
}

static void init_timing(void) {
    hclk_freq = HAL_RCC_GetHCLKFreq();
    hclk_freq_div_mio = hclk_freq / 1000000UL;
    // Typical: 72,000,000 Hz for STM32F103 at full speed
    //but we currently use 8MHz to spare energy. Likely to change it for RSA though...
}

/**
  * @brief  This function provides delay (in nanoseconds) based on CPU cycles method.
  * @param  us: specifies the delay time in nanoseconds.
  * @retval None
  */

void delay_us_precise(uint32_t us) {
    // Enable DWT CYCCNT (cycle counter)
    if (!(CoreDebug->DEMCR & CoreDebug_DEMCR_TRCENA_Msk)) {
        CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    }
    if (!(DWT->CTRL & CoreDebug_DEMCR_TRCENA_Msk)) {
        DWT->CTRL |= CoreDebug_DEMCR_TRCENA_Msk;
    }

    DWT->CYCCNT = 0;
    uint32_t target = hclk_freq_div_mio * us;
    while (DWT->CYCCNT < target);
}

/**
 * @brief Fault indicator: flashes STAT_POWERON LED and blocks forever.
 *
 * @details Intended for catastrophic startup failures where further execution
 *          must be prevented. Produces a repeating pattern of 3 fast flashes
 *          (100 ms on / 100 ms off) followed by a 1 s pause, then repeats.
 *          The watchdog is refreshed at the end of every flash and every 500 ms
 *          during the pause so the reset timer never fires and the pattern
 *          continues indefinitely.
 *
 * @note    This function never returns.
 */
static void FaultBlinkHalt(void) {
  while(1) {
    for(uint8_t i = 0u; i < 3u; i++) {
      PIN_WRITE_STAT_POWERON(GPIO_PIN_SET);
      HAL_Delay(100u);
      PIN_WRITE_STAT_POWERON(GPIO_PIN_RESET);
      HAL_Delay(100u);
      WATCHDOG_REFRESH();
    }
    HAL_Delay(500u);
    WATCHDOG_REFRESH();
    HAL_Delay(500u);
    WATCHDOG_REFRESH();
  }
}

/**
 * @brief wrapper to readout GPIO switch for the device assignment
 *
 * @retval Enum Challenger or Transponder
 *
 * @note according to the schematics we use PA5 pin for the switch
 *       active   - Challenger
 *       inactive - Transponder
 *
 * @note IMPORTANT - check that your pin initialization enables pin pull-up!
 *
 */
static uint8_t WhoAmI() {
  return ((PIN_READ_WHOAMI == GPIO_PIN_SET)?Challenger:Transponder);
}

/**
 * @brief  Encode a challenge packet into the transmit buffer.
 *
 * Packet layout: | Magic(4) | Counter(4) | HMAC-SHA256[0:15](16) |
 *
 * The 32-bit counter is incremented on every call and serialised big-endian.
 * The HMAC is computed over (Magic || Counter) using the first 32 bytes of
 * the ECDH shared secret (x-coordinate of the shared point) as the key.
 * The tag is truncated to 16 bytes to minimise air-time.
 *
 * @param  buffer  Pointer to the transmit buffer.  Must be at least
 *                 CHALLENGE_PACKET_LEN bytes long.
 * @param  length  Usable length of @p buffer in bytes.
 * @retval OK      Packet encoded successfully.
 * @retval NOK     Buffer too short or HMAC computation failed.
 */
static uint8_t EncodeChallengePackage(uint8_t* buffer, uint16_t length){
  if(length < CHALLENGE_PACKET_LEN) return NOK;

  static uint32_t challengeCounter = 0u;
  challengeCounter++;

  /* [0 .. MAGIC_PATTERN_LEN-1] : magic pattern */
  memcpy(buffer, Magic_Pattern, MAGIC_PATTERN_LEN);

  /* [MAGIC_PATTERN_LEN .. +3] : 32-bit counter big-endian (replay-protection nonce) */
  buffer[MAGIC_PATTERN_LEN + 0u] = (uint8_t)(challengeCounter >> 24);
  buffer[MAGIC_PATTERN_LEN + 1u] = (uint8_t)(challengeCounter >> 16);
  buffer[MAGIC_PATTERN_LEN + 2u] = (uint8_t)(challengeCounter >>  8);
  buffer[MAGIC_PATTERN_LEN + 3u] = (uint8_t)(challengeCounter);

  /* [MAGIC_PATTERN_LEN+4 .. +19] : HMAC-SHA256 over (magic || counter), key = ECDH secret x-coord.
   * Tag truncated to 16 bytes to keep air-time short. */
  size_t tagLen = 0u;
  cmox_mac_retval_t ret = cmox_mac_compute(
      CMOX_HMAC_SHA256_ALGO,
      buffer, MAGIC_PATTERN_LEN + 4u,
      Computed_Secret, 32u,
      NULL, 0u,
      &buffer[MAGIC_PATTERN_LEN + 4u], 16u,
      &tagLen);

  return (ret == CMOX_MAC_SUCCESS) ? OK : NOK;
}

/**
 * @brief  Verify a received challenge packet on the Transponder side.
 *
 * Checks the magic pattern prefix, then recomputes the HMAC over
 * (Magic || Counter) and compares it against the tag carried in the packet.
 * On success the embedded challenge counter is written to @p outCounter so
 * the Transponder can echo it back in the response.
 *
 * @param  buffer      Pointer to the received data buffer.
 * @param  length      Number of valid bytes in @p buffer.  Must be at least
 *                     CHALLENGE_PACKET_LEN.
 * @param  outCounter  Output: challenge counter extracted from the packet.
 *                     Written only when the function returns OK.
 * @retval OK          Magic and HMAC verified successfully.
 * @retval NOK         Buffer too short, magic mismatch, or HMAC failure.
 */
static uint8_t DecodeChallengePackage(uint8_t* buffer, uint16_t length, uint32_t* outCounter){
  if(length < CHALLENGE_PACKET_LEN) return NOK;

  if(memcmp(buffer, Magic_Pattern, MAGIC_PATTERN_LEN) != 0) return NOK;

  uint8_t expectedTag[16];
  size_t  tagLen = 0u;
  cmox_mac_retval_t ret = cmox_mac_compute(
      CMOX_HMAC_SHA256_ALGO,
      buffer, MAGIC_PATTERN_LEN + 4u,
      Computed_Secret, 32u,
      NULL, 0u,
      expectedTag, 16u,
      &tagLen);

  if(ret != CMOX_MAC_SUCCESS) return NOK;
  if(memcmp(&buffer[MAGIC_PATTERN_LEN + 4u], expectedTag, 16u) != 0) return NOK;

  *outCounter = ((uint32_t)buffer[MAGIC_PATTERN_LEN + 0u] << 24) |
                ((uint32_t)buffer[MAGIC_PATTERN_LEN + 1u] << 16) |
                ((uint32_t)buffer[MAGIC_PATTERN_LEN + 2u] <<  8) |
                ((uint32_t)buffer[MAGIC_PATTERN_LEN + 3u]);
  return OK;
}

/**
 * @brief  Encode the Transponder response packet into the transmit buffer.
 *
 * Packet layout: | Magic(4) | EchoCounter(4) | RxTimestamp(4) | HMAC-SHA256[0:15](16) |
 *
 * The challenge counter received from the Challenger is echoed back verbatim
 * so the Challenger can match the response to its outstanding request.
 * The Transponder's local receive timestamp (HAL_GetTick(), ms) is included
 * so the Challenger has visibility into the one-way propagation component of
 * the round-trip time.
 * The HMAC is computed over (Magic || EchoCounter || RxTimestamp) using the
 * first 32 bytes of the ECDH shared secret as the key.
 *
 * @param  buffer       Pointer to the transmit buffer.  Must be at least
 *                      RESPONSE_PACKET_LEN bytes long.
 * @param  length       Usable length of @p buffer in bytes.
 * @param  echoCounter  Challenge counter value copied from the received packet.
 * @param  rxTimestamp  Local timestamp (ms) recorded when the challenge arrived.
 * @retval OK           Packet encoded successfully.
 * @retval NOK          Buffer too short or HMAC computation failed.
 */
static uint8_t EncodeResponsePackage(uint8_t* buffer, uint16_t length,
                                     uint32_t echoCounter, uint32_t rxTimestamp){
  if(length < RESPONSE_PACKET_LEN) return NOK;

  memcpy(buffer, Magic_Pattern, MAGIC_PATTERN_LEN);

  buffer[MAGIC_PATTERN_LEN + 0u] = (uint8_t)(echoCounter >> 24);
  buffer[MAGIC_PATTERN_LEN + 1u] = (uint8_t)(echoCounter >> 16);
  buffer[MAGIC_PATTERN_LEN + 2u] = (uint8_t)(echoCounter >>  8);
  buffer[MAGIC_PATTERN_LEN + 3u] = (uint8_t)(echoCounter);

  buffer[MAGIC_PATTERN_LEN + 4u] = (uint8_t)(rxTimestamp >> 24);
  buffer[MAGIC_PATTERN_LEN + 5u] = (uint8_t)(rxTimestamp >> 16);
  buffer[MAGIC_PATTERN_LEN + 6u] = (uint8_t)(rxTimestamp >>  8);
  buffer[MAGIC_PATTERN_LEN + 7u] = (uint8_t)(rxTimestamp);

  /* HMAC over magic || echo_counter || rx_timestamp */
  size_t tagLen = 0u;
  cmox_mac_retval_t ret = cmox_mac_compute(
      CMOX_HMAC_SHA256_ALGO,
      buffer, MAGIC_PATTERN_LEN + 4u + 4u,
      Computed_Secret, 32u,
      NULL, 0u,
      &buffer[MAGIC_PATTERN_LEN + 4u + 4u], 16u,
      &tagLen);

  return (ret == CMOX_MAC_SUCCESS) ? OK : NOK;
}

/**
 * @brief  Verify a Transponder response packet on the Challenger side.
 *
 * Checks the magic pattern prefix, then recomputes the HMAC over
 * (Magic || EchoCounter || RxTimestamp) and compares it against the tag in
 * the packet.  On success the echo counter and the Transponder's receive
 * timestamp are written to the output parameters.
 *
 * The Challenger must additionally verify that the echo counter matches the
 * counter it sent and that the measured round-trip time is within the
 * configured tolerance (Cfg_ResponseDelayToleranceMs).
 *
 * @param  buffer           Pointer to the received data buffer.
 * @param  length           Number of valid bytes in @p buffer.  Must be at
 *                          least RESPONSE_PACKET_LEN.
 * @param  outEchoCounter   Output: challenge counter echoed by the Transponder.
 *                          Written only when the function returns OK.
 * @param  outRxTimestamp   Output: Transponder local receive timestamp (ms).
 *                          Written only when the function returns OK.
 * @retval OK               Magic and HMAC verified successfully.
 * @retval NOK              Buffer too short, magic mismatch, or HMAC failure.
 */
static uint8_t DecodeResponsePackage(uint8_t* buffer, uint16_t length,
                                     uint32_t* outEchoCounter, uint32_t* outRxTimestamp){
  if(length < RESPONSE_PACKET_LEN) return NOK;

  if(memcmp(buffer, Magic_Pattern, MAGIC_PATTERN_LEN) != 0) return NOK;

  uint8_t expectedTag[16];
  size_t  tagLen = 0u;
  cmox_mac_retval_t ret = cmox_mac_compute(
      CMOX_HMAC_SHA256_ALGO,
      buffer, MAGIC_PATTERN_LEN + 4u + 4u,
      Computed_Secret, 32u,
      NULL, 0u,
      expectedTag, 16u,
      &tagLen);

  if(ret != CMOX_MAC_SUCCESS) return NOK;
  if(memcmp(&buffer[MAGIC_PATTERN_LEN + 4u + 4u], expectedTag, 16u) != 0) return NOK;

  *outEchoCounter  = ((uint32_t)buffer[MAGIC_PATTERN_LEN + 0u] << 24) |
                     ((uint32_t)buffer[MAGIC_PATTERN_LEN + 1u] << 16) |
                     ((uint32_t)buffer[MAGIC_PATTERN_LEN + 2u] <<  8) |
                     ((uint32_t)buffer[MAGIC_PATTERN_LEN + 3u]);

  *outRxTimestamp  = ((uint32_t)buffer[MAGIC_PATTERN_LEN + 4u] << 24) |
                     ((uint32_t)buffer[MAGIC_PATTERN_LEN + 5u] << 16) |
                     ((uint32_t)buffer[MAGIC_PATTERN_LEN + 6u] <<  8) |
                     ((uint32_t)buffer[MAGIC_PATTERN_LEN + 7u]);
  return OK;
}

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* Configure the system clock */
  SystemClock_Config();
  /* SysInit */
  init_timing(); //now we're set up to use systicks etc.

  //crypto init
  cmox_init_arg_t init_target = {CMOX_INIT_TARGET_AUTO, NULL};

  /* Initialize cryptographic library */
  if (cmox_initialize(&init_target) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_SPI1_Init();

#ifdef WATCHDOG_ENABLED
  hiwdg.Instance       = IWDG;
  hiwdg.Init.Prescaler = WATCHDOG_PRESCALER;
  hiwdg.Init.Reload    = WATCHDOG_RELOAD;
  if(HAL_IWDG_Init(&hiwdg) != HAL_OK){
    Error_Handler();
  }
#endif

  uint8_t devType = WhoAmI();//this check once on init - the switch is hided in the case

  /* initialize and start LoRa */
  loRa = newLoRa();
  loRa.CS_port         = NSS_GPIO_Port;
  loRa.CS_pin          = NSS_Pin;
  loRa.reset_port      = RST_GPIO_Port;
  loRa.reset_pin       = RST_Pin;
  loRa.DIO0_port       = DIO0_GPIO_Port;
  loRa.DIO0_pin        = DIO0_Pin;
  loRa.hSPIx           = &hspi1;

  int returnCode = LoRa_init(&loRa);

  if(returnCode != 200) {
    FaultBlinkHalt();
  }

  PIN_WRITE_STAT_POWERON(GPIO_PIN_SET);
  LoRa_startReceiving(&loRa);

  /** main loop **/
  switch(devType){
    case Challenger: {
      size_t secretLen = 0u;
      cmox_ecc_construct(&Ecc_Ctx, CMOX_MATH_FUNCS_SMALL, Working_Buffer, sizeof(Working_Buffer));
      cmox_ecdh(&Ecc_Ctx, CMOX_ECC_SECP256R1_LOWMEM,
                Private_Key,       sizeof(Private_Key),
                Remote_Public_Key, sizeof(Remote_Public_Key),
                Computed_Secret,   &secretLen);
      cmox_ecc_cleanup(&Ecc_Ctx);

      while(stayActive){
        if(EncodeChallengePackage(TxBuffer, TXRX_BUFFER_MAX_LENGTH) == OK){
          /* Read back the counter we just packed so we can validate the echo */
          uint32_t sentCounter = ((uint32_t)TxBuffer[MAGIC_PATTERN_LEN + 0u] << 24) |
                                 ((uint32_t)TxBuffer[MAGIC_PATTERN_LEN + 1u] << 16) |
                                 ((uint32_t)TxBuffer[MAGIC_PATTERN_LEN + 2u] <<  8) |
                                 ((uint32_t)TxBuffer[MAGIC_PATTERN_LEN + 3u]);

          uint32_t txTimestamp = HAL_GetTick();
          LoRa_transmit(&loRa, TxBuffer, CHALLENGE_PACKET_LEN, Cfg_TxTimeoutMs);

          loRaRxReady = 0u;
          LoRa_startReceiving(&loRa);
          uint32_t rxStart = HAL_GetTick();
          while((HAL_GetTick() - rxStart) < 1000u && !loRaRxReady){
            delay_us_precise(Cfg_MainCycleDelayUs);
            WATCHDOG_REFRESH();
          }

          if(!loRaRxReady){
            PIN_WRITE_STAT_FRIEND_FOF(STAT_FOE); /* timeout — no reply or foe */
          } else {
            uint32_t roundTripMs   = HAL_GetTick() - txTimestamp;
            uint32_t echoCounter   = 0u;
            uint32_t transponderTs = 0u;

            if(DecodeResponsePackage(RxBuffer, RESPONSE_PACKET_LEN,
                                     &echoCounter, &transponderTs) == OK
               && echoCounter == sentCounter
               && roundTripMs <= Cfg_ResponseDelayToleranceMs){
              PIN_WRITE_STAT_FRIEND_FOF(STAT_FRIEND);
            } else {
              PIN_WRITE_STAT_FRIEND_FOF(STAT_FOE); /* bad HMAC, counter mismatch, or delay exceeded */
            }
          }
        }
        delay_us_precise(Cfg_MainCycleDelayUs);
        WATCHDOG_REFRESH();
      }//while stay active ** Challenger main loop **
    } break;

    case Transponder: {
      size_t secretLen = 0u;
      cmox_ecc_construct(&Ecc_Ctx, CMOX_MATH_FUNCS_SMALL, Working_Buffer, sizeof(Working_Buffer));
      cmox_ecdh(&Ecc_Ctx, CMOX_ECC_SECP256R1_LOWMEM,
                Private_Key,       sizeof(Private_Key),
                Remote_Public_Key, sizeof(Remote_Public_Key),
                Computed_Secret,   &secretLen);
      cmox_ecc_cleanup(&Ecc_Ctx);

      LoRa_startReceiving(&loRa); /* silent listen; reception is IRQ-driven */

      while(stayActive){
        if(loRaRxReady){
          uint32_t rxTimestamp = HAL_GetTick(); /* capture arrival time before any processing */
          loRaRxReady = 0u;

          uint32_t echoCounter = 0u;
          if(DecodeChallengePackage(RxBuffer, CHALLENGE_PACKET_LEN, &echoCounter) == OK){
            if(EncodeResponsePackage(TxBuffer, TXRX_BUFFER_MAX_LENGTH, echoCounter, rxTimestamp) == OK){
              LoRa_transmit(&loRa, TxBuffer, RESPONSE_PACKET_LEN, Cfg_TxTimeoutMs);
              LoRa_startReceiving(&loRa); /* return to silent listen after reply */
            }
          }
        }
        delay_us_precise(Cfg_MainCycleDelayUs);
        WATCHDOG_REFRESH();
      }//while stay active ** Transponder main loop **
    } break;
    default:
      //this branch shall be never reached - error case
      Error_Handler();
  }
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
}

void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin)
{
  if (GPIO_Pin == DIO0_Pin) {
    LoRa_receive(&loRa, RxBuffer, 128);
    loRaRxReady = 1u;
  }
}


/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
    //in release version we are aiming device reset
  }
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
}
#endif /* USE_FULL_ASSERT */
