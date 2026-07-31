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
#include "keys.h"
#include "uart_prov.h"
#ifdef WATCHDOG_ENABLED
  #include "stm32f1xx_hal_iwdg.h"
#endif

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
#define PIN_READ_WHOAMI                  HAL_GPIO_ReadPin(GPIOA, GPIO_PIN_8)           /* PA8 physical switch to select Challenger or Receiver*/
#define PIN_WRITE_STAT_FRIEND_FOF(state) HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, (state)) /* PA2 external LED, FRIEND/FOE indication, e.g. in front of the POV cam*/
#define PIN_WRITE_STAT_POWERON(state)    HAL_GPIO_WritePin(GPIOA, GPIO_PIN_3, (state)) /* PA3 external LED, POWERON indication*/
#define PIN_WRITE_STAT_HEARTBEAT(state)  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_13, (state))/* PC13 - standard bluepill available LED ->only for debug purposes */
#define STAT_FRIEND                      GPIO_PIN_SET
#define STAT_FOE                         GPIO_PIN_RESET


/* ---------------------------------------------------------------------------
 * Test ping mode
 *
 * Uncomment TEST_PING_MODE to replace the cryptographic challenge-response
 * protocol with a plain connectivity test: the Challenger transmits a fixed
 * 4-byte telegram, the Transponder replies with the same bytes inverted.
 * The Challenger stores the reply in the Dbg_Ping* variables for inspection
 * in the debugger; no pin indication logic is involved.
 * ---------------------------------------------------------------------------*/
//#define TEST_PING_MODE
#define TEST_PING_LEN                  4u

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

/* Clamp a poll/pause chunk so it never exceeds 1/10 of the watchdog window.
 * Short watchdog timeout -> chunk shrinks automatically (no manual checkups);
 * long watchdog timeout  -> chunk stays at the desired value instead of growing. */
#define WATCHDOG_SAFE_POLL_MS(desired)  ((desired) < (Cfg_WatchdogTimeoutMs / 10u) \
                                          ? (desired) : (Cfg_WatchdogTimeoutMs / 10u))

/* Private variables ---------------------------------------------------------*/
LoRa loRa;
uint8_t TxBuffer[TXRX_BUFFER_MAX_LENGTH];
uint8_t RxBuffer[TXRX_BUFFER_MAX_LENGTH];

uint8_t oldChallengeRequested = ChallengeNotRequested;
static uint8_t stayActive = 1u;
static volatile uint8_t loRaRxReady = 0u;

/* Debug: individual RegModemStat bits, refreshed once per main loop cycle.
 * Watch these directly in the debugger instead of decoding LoRa_getModemStatusEval()'s
 * packed return value by hand. */
static volatile uint8_t Dbg_ModemRxOngoing      = 0u;
static volatile uint8_t Dbg_ModemSignalSync     = 0u;
static volatile uint8_t Dbg_ModemSignalDetected = 0u;

/* Debug: individual RegIrqFlags bits, refreshed once per main loop cycle.
 * Read non-destructively via LoRa_getIrqFlags() - does not clear any flags. */
static volatile uint8_t Dbg_IrqRxTimeout         = 0u;
static volatile uint8_t Dbg_IrqRxDone            = 0u;
static volatile uint8_t Dbg_IrqPayloadCrcError   = 0u;
static volatile uint8_t Dbg_IrqValidHeader       = 0u;
static volatile uint8_t Dbg_IrqTxDone            = 0u;
static volatile uint8_t Dbg_IrqCadDone           = 0u;
static volatile uint8_t Dbg_IrqFhssChangeChannel = 0u;
static volatile uint8_t Dbg_IrqCadDetected       = 0u;
static volatile uint32_t Dbg_IrqGeneriFire       = 0u; /* counter for entering in the EXTI1 IRQ handler */

#ifdef TEST_PING_MODE
/* Fixed test telegram with distinctive mixed bit patterns.
 * Expected inverted reply: 0x5A 0xA5 0x3C 0xC3 */
static const uint8_t Test_Ping_Telegram[TEST_PING_LEN] = { 0xA5, 0x5A, 0xC3, 0x3C };

/* Debug: test ping observability, watch in the debugger.
 * Challenger side: response bytes, counters, match flag.
 * Transponder side: received telegram bytes, reply counter. */
static volatile uint8_t  Dbg_PingRxData[TEST_PING_LEN] = { 0u };
static volatile uint32_t Dbg_PingTxCount   = 0u; /* telegrams / replies sent */
static volatile uint32_t Dbg_PingRxCount   = 0u; /* packets received */
static volatile uint8_t  Dbg_PingRxMatch   = 0u; /* 1 = last reply was the correctly inverted telegram (Challenger only) */
#endif

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
 * @brief Main loop cycle period in milliseconds (Transponder poll rate).
 *        Located in .fof_config for field configurability.
 */
__attribute__((section(".fof_config")))
const uint32_t Cfg_TransponderMainCycleMs = 2u;//2 ms

/**
 * @brief Challenger repetition cycle in milliseconds: pause between the end of
 *        one challenge exchange and the start of the next. The Transponder is
 *        purely reactive and keeps polling at Cfg_ChallengerMainCycleMs.
 *        Located in .fof_config for field configurability.
 */
__attribute__((section(".fof_config")))
const uint32_t Cfg_ChallengerMainCycleMs = 1000u;

/**
 * @brief Poll granularity in milliseconds while the Challenger waits for the
 *        response. Bounds both the reaction latency to loRaRxReady and the
 *        quantization error added to the measured round-trip time.
 *        Located in .fof_config for field configurability.
 */
__attribute__((section(".fof_config")))
const uint32_t Cfg_ResponseWaitCycleDelayMs = 10u;

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
 * @brief LoRa TX output power in dBm via PA_BOOST pin (5..20 dBm).
 *        Applied to the SX1278 RegPaConfig register before LoRa_init().
 *        Formula: RegPaConfig = 0xF0 | (Cfg_TxPowerDbm - 5).
 *        Located in .fof_config for field configurability.
 */
__attribute__((section(".fof_config")))
const uint32_t Cfg_TxPowerDbm = 14u;

/**
 * @brief LNA gain setting for the SX1278 receiver.
 *        0 = AGC automatic (hardware selects gain dynamically).
 *        1 = G1 maximum sensitivity … 6 = G6 minimum sensitivity.
 *        Located in .fof_config for field configurability.
 */
__attribute__((section(".fof_config")))
const uint32_t Cfg_LnaGain = 1u;

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
      HAL_Delay(500u);
      PIN_WRITE_STAT_POWERON(GPIO_PIN_RESET);
      HAL_Delay(300u);
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
 * @note according to the schematics we use PA8 pin for the switch
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
 * @brief Refresh the Dbg_Modem* globals from the radio's current modem status.
 *
 * @details Splits the packed LoRa_getModemStatusEval() return value into its
 *          three individual bits (RxOngoing, SignalSynchronized, SignalDetected)
 *          so each can be watched separately in the debugger without manual
 *          bit-masking. Intended to be called once per main loop cycle.
 *
 * @retval None
 */
static void UpdateModemStatusDebug(void) {
  uint8_t status = LoRa_getModemStatusEval(&loRa);
  Dbg_ModemRxOngoing      = (status >> 2) & 0x01u;
  Dbg_ModemSignalSync     = (status >> 1) & 0x01u;
  Dbg_ModemSignalDetected = (status >> 0) & 0x01u;
}

/**
 * @brief Refresh the Dbg_Irq* globals from the radio's current RegIrqFlags.
 *
 * @details Splits the raw, non-destructively read RegIrqFlags value into its
 *          8 individual bits so each can be watched separately in the
 *          debugger. Uses LoRa_getIrqFlags(), which does not clear any flags,
 *          so calling this has no effect on protocol logic. Intended to be
 *          called once per main loop cycle.
 *
 * @retval None
 */
static void UpdateIrqFlagsDebug(void) {
  uint8_t flags = LoRa_getIrqFlags(&loRa);
  Dbg_IrqRxTimeout         = (flags >> 7) & 0x01u;
  Dbg_IrqRxDone            = (flags >> 6) & 0x01u;
  Dbg_IrqPayloadCrcError   = (flags >> 5) & 0x01u;
  Dbg_IrqValidHeader       = (flags >> 4) & 0x01u;
  Dbg_IrqTxDone            = (flags >> 3) & 0x01u;
  Dbg_IrqCadDone           = (flags >> 2) & 0x01u;
  Dbg_IrqFhssChangeChannel = (flags >> 1) & 0x01u;
  Dbg_IrqCadDetected       = (flags >> 0) & 0x01u;
}

#ifndef TEST_PING_MODE /* packet codecs are unused in test ping mode */
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
#endif /* !TEST_PING_MODE */

/**
 * @brief Pause between two challenge exchanges (Challenger only).
 *
 * @details Waits Cfg_ChallengerMainCycleMs in chunks of at most 1/10 of the
 *          watchdog window (capped at 100 ms), feeding the watchdog after each
 *          chunk. A shorter provisioned watchdog timeout shrinks the chunks
 *          automatically; a longer one does not slow the pause granularity.
 */
static void ChallengerCyclePause(void) {
  uint32_t start = HAL_GetTick();
  while((HAL_GetTick() - start) < Cfg_ChallengerMainCycleMs){
    HAL_Delay(WATCHDOG_SAFE_POLL_MS(100u));
    WATCHDOG_REFRESH();
  }
}

#ifdef TEST_PING_MODE

/**
 * @brief Challenger connectivity-test loop (TEST_PING_MODE). Never returns.
 *
 * @details Transmits the fixed test telegram, then waits up to 1 s for the
 *          Transponder's reply. A reply matching the bitwise-inverted telegram
 *          is indicated by a short negative LED blink; all observability data
 *          lands in the Dbg_Ping* variables.
 */
static void ChallengerTestLoop(void) {
// # 1 Preparation
//   empty in the test scenario
  while(stayActive){


    // # 2 Prepare the message
    memcpy(TxBuffer, Test_Ping_Telegram, TEST_PING_LEN);


    // # 3 Transmit the challenge and start rx listening
    PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);// toggle TX (on)
    LoRa_transmit(&loRa, TxBuffer, TEST_PING_LEN, Cfg_TxTimeoutMs);
    Dbg_PingTxCount++;

    loRaRxReady = 0u;
    LoRa_startReceiving(&loRa);
    uint32_t rxStart = HAL_GetTick();
    /* Response window = half the repetition cycle, so a timed-out exchange
     * (wait + pause) never exceeds 1.5x Cfg_ChallengerMainCycleMs. */
    while((HAL_GetTick() - rxStart) < (Cfg_ChallengerMainCycleMs / 2u) && !loRaRxReady){
      HAL_Delay(WATCHDOG_SAFE_POLL_MS(Cfg_ResponseWaitCycleDelayMs));
      WATCHDOG_REFRESH();
    }

    PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_SET);// Toggle TX (off)
    if(!loRaRxReady){
      PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);/* timeout — no reply or foe */
      HAL_Delay(50u);
      PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_SET);
      HAL_Delay(50u);
      PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);
      HAL_Delay(50u);
      PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_SET);
      HAL_Delay(50u);
    } else {
      LoRa_receive(&loRa, RxBuffer, TXRX_BUFFER_MAX_LENGTH);
      Dbg_PingRxCount++;
      uint8_t match = 1u;
      for(uint8_t i = 0u; i < TEST_PING_LEN; i++){
        Dbg_PingRxData[i] = RxBuffer[i];
        if(RxBuffer[i] != (uint8_t)~Test_Ping_Telegram[i]){
          match = 0u;
        }
      }
      if(match == 1u)
      {
        PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);// indicate RX
        HAL_Delay(100u);
        PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_SET);// indicate RX
        HAL_Delay(100u);
        PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);// indicate RX
      }
      Dbg_PingRxMatch = match;
    }

    UpdateModemStatusDebug();
    UpdateIrqFlagsDebug();
    ChallengerCyclePause();
  }//while stay active ** Challenger test ping loop **
}

/**
 * @brief Transponder connectivity-test loop (TEST_PING_MODE). Never returns.
 *
 * @details Listens silently; on any received packet, replies with its first
 *          TEST_PING_LEN bytes bitwise-inverted, then indicates the exchange
 *          with a triple negative LED flash before returning to listen mode.
 */
static void TransponderTestLoop(void) {
  PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);
  LoRa_startReceiving(&loRa);
  uint8_t ledState = GPIO_PIN_RESET;
  while(stayActive){
    if(loRaRxReady){
      loRaRxReady = 0u;
      /* reply only to complete, CRC-clean frames */
      if(LoRa_receive(&loRa, RxBuffer, TXRX_BUFFER_MAX_LENGTH) < TEST_PING_LEN){
        continue;
      }
      Dbg_PingRxCount++;

      for(uint8_t i = 0u; i < TEST_PING_LEN; i++){
        Dbg_PingRxData[i] = RxBuffer[i];
        TxBuffer[i] = (uint8_t)~RxBuffer[i];
      }
      //little delay to avoid collision with the end of the reception
      HAL_Delay(10u);

      LoRa_transmit(&loRa, TxBuffer, TEST_PING_LEN, Cfg_TxTimeoutMs);
      Dbg_PingTxCount++;
      LoRa_startReceiving(&loRa); /* return to silent listen after reply */

      /* Negative-flash 3x to indicate a telegram was received, inverted and
       * sent back. The LED is normally lit while receiving (PC13: RESET = on),
       * so each flash is a short dark pulse: SET = off, RESET = back on. */
      for(uint8_t i = 0u; i < 3u; i++){
        PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_SET);   /* dark pulse */
        HAL_Delay(50u);
        PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET); /* back to lit */
        HAL_Delay(50u);
        WATCHDOG_REFRESH();
      }
    }

    UpdateModemStatusDebug();
    UpdateIrqFlagsDebug();
    HAL_Delay(WATCHDOG_SAFE_POLL_MS(Cfg_TransponderMainCycleMs));
    PIN_WRITE_STAT_HEARTBEAT(ledState^=1u); /* toggle LED to indicate the transponder is alive */
    WATCHDOG_REFRESH();
  }//while stay active ** Transponder test ping loop **
}

#else /* !TEST_PING_MODE */

/**
 * @brief Compute the ECDH shared secret into Computed_Secret.
 *
 * @details One-time key agreement over SECP256R1 using the provisioned
 *          Private_Key and Remote_Public_Key. Executed once before entering
 *          the protocol loop; both Challenger and Transponder derive the same
 *          secret, which keys the HMAC of every packet.
 */
static void ComputeSharedSecret(void) {
  size_t secretLen = 0u;
  cmox_ecc_construct(&Ecc_Ctx, CMOX_MATH_FUNCS_SMALL, Working_Buffer, sizeof(Working_Buffer));
  cmox_ecdh(&Ecc_Ctx, CMOX_ECC_SECP256R1_LOWMEM,
            Private_Key,       sizeof(Private_Key),
            Remote_Public_Key, sizeof(Remote_Public_Key),
            Computed_Secret,   &secretLen);
  cmox_ecc_cleanup(&Ecc_Ctx);
}

/**
 * @brief Challenger protocol loop. Never returns.
 *
 * @details Periodically transmits an HMAC-authenticated challenge and waits
 *          up to 1 s for the response. STAT_FRIEND is signalled only when the
 *          response passes HMAC verification, echoes the sent counter, and
 *          arrives within Cfg_ResponseDelayToleranceMs; any other outcome
 *          (timeout, bad HMAC, stale counter, excessive delay) signals STAT_FOE.
 */
static void ChallengerLoop(void) {
// # 1 Preparation
  ComputeSharedSecret();

  while(stayActive){


    // # 2 Prepare the message
    if(EncodeChallengePackage(TxBuffer, TXRX_BUFFER_MAX_LENGTH) == OK){
      /* Read back the counter we just packed so we can validate the echo */
      uint32_t sentCounter = ((uint32_t)TxBuffer[MAGIC_PATTERN_LEN + 0u] << 24) |
                             ((uint32_t)TxBuffer[MAGIC_PATTERN_LEN + 1u] << 16) |
                             ((uint32_t)TxBuffer[MAGIC_PATTERN_LEN + 2u] <<  8) |
                             ((uint32_t)TxBuffer[MAGIC_PATTERN_LEN + 3u]);

      uint32_t txTimestamp = HAL_GetTick();


      // # 3 Transmit the challenge and start rx listening
      PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);// toggle TX (on)
      LoRa_transmit(&loRa, TxBuffer, CHALLENGE_PACKET_LEN, Cfg_TxTimeoutMs);

      loRaRxReady = 0u;
      LoRa_startReceiving(&loRa);
      uint32_t rxStart = HAL_GetTick();
      /* Response window = half the repetition cycle, so a timed-out exchange
       * (wait + pause) never exceeds 1.5x Cfg_ChallengerMainCycleMs. */
      while((HAL_GetTick() - rxStart) < (Cfg_ChallengerMainCycleMs / 2u) && !loRaRxReady){
        HAL_Delay(WATCHDOG_SAFE_POLL_MS(Cfg_ResponseWaitCycleDelayMs));
        WATCHDOG_REFRESH();
      }

      PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_SET);// Toggle TX (off)
      if(!loRaRxReady){
        PIN_WRITE_STAT_FRIEND_FOF(STAT_FOE); /* timeout — no reply or foe */
        /* LED indication: double blink on timeout (test-style, to be replaced) */
        PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);
        HAL_Delay(50u);
        PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_SET);
        HAL_Delay(50u);
        PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);
        HAL_Delay(50u);
        PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_SET);
        HAL_Delay(50u);
      } else {
        uint32_t roundTripMs   = HAL_GetTick() - txTimestamp;
        uint32_t echoCounter   = 0u;
        uint32_t transponderTs = 0u;
        uint8_t  rxLen = LoRa_receive(&loRa, RxBuffer, TXRX_BUFFER_MAX_LENGTH);

        if(rxLen >= RESPONSE_PACKET_LEN
           && DecodeResponsePackage(RxBuffer, RESPONSE_PACKET_LEN,
                                    &echoCounter, &transponderTs) == OK
           && echoCounter == sentCounter
           && roundTripMs <= Cfg_ResponseDelayToleranceMs){
          PIN_WRITE_STAT_FRIEND_FOF(STAT_FRIEND);
          /* LED indication: friend confirmed (test-style, to be replaced) */
          PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);
          HAL_Delay(100u);
          PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_SET);
          HAL_Delay(100u);
          PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET);
        } else {
          PIN_WRITE_STAT_FRIEND_FOF(STAT_FOE); /* bad HMAC, counter mismatch, or delay exceeded */
        }
      }
    }
    UpdateModemStatusDebug();
    UpdateIrqFlagsDebug();
    ChallengerCyclePause();
  }//while stay active ** Challenger main loop **
}

/**
 * @brief Transponder protocol loop. Never returns.
 *
 * @details Listens silently (IRQ-driven reception). On a valid challenge
 *          (magic + HMAC verified) it echoes the challenge counter together
 *          with its local receive timestamp in an HMAC-authenticated response,
 *          then returns to silent listening. Invalid packets are ignored.
 */
static void TransponderLoop(void) {
  ComputeSharedSecret();

  PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET); /* LED on: listening */
  LoRa_startReceiving(&loRa); /* silent listen; reception is IRQ-driven */
  uint8_t ledState = GPIO_PIN_RESET;

  while(stayActive){
    if(loRaRxReady){
      uint32_t rxTimestamp = HAL_GetTick(); /* capture arrival time before any processing */
      loRaRxReady = 0u;
      /* process only complete, CRC-clean frames; skips HMAC work on noise */
      if(LoRa_receive(&loRa, RxBuffer, TXRX_BUFFER_MAX_LENGTH) < CHALLENGE_PACKET_LEN){
        continue;
      }

      uint32_t echoCounter = 0u;
      if(DecodeChallengePackage(RxBuffer, CHALLENGE_PACKET_LEN, &echoCounter) == OK){
        if(EncodeResponsePackage(TxBuffer, TXRX_BUFFER_MAX_LENGTH, echoCounter, rxTimestamp) == OK){
          /* little delay so the Challenger has completed its TX->RX turnaround */
          HAL_Delay(10u);
          LoRa_transmit(&loRa, TxBuffer, RESPONSE_PACKET_LEN, Cfg_TxTimeoutMs);
          LoRa_startReceiving(&loRa); /* return to silent listen after reply */

          /* LED indication: negative-flash 3x after a valid challenge was
           * answered (test-style, to be replaced) */
          for(uint8_t i = 0u; i < 3u; i++){
            PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_SET);   /* dark pulse */
            HAL_Delay(50u);
            PIN_WRITE_STAT_HEARTBEAT(GPIO_PIN_RESET); /* back to lit */
            HAL_Delay(50u);
            WATCHDOG_REFRESH();
          }
        }
      }
    }
    UpdateModemStatusDebug();
    UpdateIrqFlagsDebug();
    HAL_Delay(WATCHDOG_SAFE_POLL_MS(Cfg_TransponderMainCycleMs));
    PIN_WRITE_STAT_HEARTBEAT(ledState^=1u); /* toggle LED to indicate the transponder is alive */
    WATCHDOG_REFRESH();
  }//while stay active ** Transponder main loop **
}

#endif /* TEST_PING_MODE */

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
  MX_SPI1_Init(); //SPI1 is used for LoRa module

  /* Field provisioning via UART (PA9/PA10, 9600 8N1).
   * Runs only when a provisioning counterpart is present on startup.
   * Keys and config are written to NVRAM; the call is a no-op if no
   * counterpart is detected within the detection window. */
  uart_prov_run();

  /* Indicating power on state*/
  PIN_WRITE_STAT_POWERON(GPIO_PIN_SET);

#ifdef WATCHDOG_ENABLED
  hiwdg.Instance       = IWDG;
  hiwdg.Init.Prescaler = WATCHDOG_PRESCALER;
  hiwdg.Init.Reload    = WATCHDOG_RELOAD;
  if(HAL_IWDG_Init(&hiwdg) != HAL_OK){
    Error_Handler();
  }
#endif
  //this check once on init - the switch is hided in the case
  uint8_t devType = WhoAmI();//1 - Challenger, 0 - Transponder

  /* initialize and start LoRa */
  loRa = newLoRa();
  loRa.CS_port         = NSS_GPIO_Port;
  loRa.CS_pin          = NSS_Pin;
  loRa.reset_port      = RST_GPIO_Port;
  loRa.reset_pin       = RST_Pin;
  loRa.DIO0_port       = DIO0_GPIO_Port;
  loRa.DIO0_pin        = DIO0_Pin;
  loRa.hSPIx           = &hspi1;

  /* Apply NVRAM-provisioned RF parameters; guard against unprogrammed flash (0xFF…). */
  if (Cfg_TxPowerDbm >= 5u && Cfg_TxPowerDbm <= 20u)
    loRa.power   = 0xF0u | (uint8_t)(Cfg_TxPowerDbm - 5u);
  if (Cfg_LnaGain <= 6u)
    loRa.lnaGain = (uint8_t)Cfg_LnaGain;

  int returnCode = LoRa_init(&loRa);

  if(returnCode != 200) {
    FaultBlinkHalt();
  }

  /** main loop — never returns from the selected loop function **/
  switch(devType){
    case Challenger:
#ifdef TEST_PING_MODE
      ChallengerTestLoop();
#else
      ChallengerLoop();
#endif
      break;
    case Transponder:
#ifdef TEST_PING_MODE
      TransponderTestLoop();
#else
      TransponderLoop();
#endif
      break;

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
    loRaRxReady = 1u;
    Dbg_IrqGeneriFire++;
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
