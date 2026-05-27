/**
  ******************************************************************************
  * @file    uart_prov.h
  * @brief   UART field-provisioning protocol definitions and API.
  *
  * ---------------------------------------------------------------------------
  * PROTOCOL OVERVIEW
  * ---------------------------------------------------------------------------
  *
  * Physical layer : USART1, 9600 8N1, PA9(TX) / PA10(RX)
  *
  * Control bytes (device → counterpart):
  *   PROV_READY  0xAA  — device is ready to receive the next packet
  *   PROV_ACK    0x06  — packet accepted (standard ASCII ACK)
  *   PROV_NAK    0x15  — packet rejected, please retransmit (standard ASCII NAK)
  *
  * Control byte (counterpart → device):
  *   PROV_EOT    0x04  — end of transmission, no more packets (standard ASCII EOT)
  *
  * Packet frame (counterpart → device):
  * ┌────────┬────────┬────────┬─────────────────┬───────────────────┐
  * │ SOF    │ TYPE   │ LEN    │ PAYLOAD         │ CRC16             │
  * │ 1 byte │ 1 byte │ 1 byte │ LEN bytes       │ 2 bytes (HI, LO)  │
  * └────────┴────────┴────────┴─────────────────┴───────────────────┘
  *
  *   SOF  = 0x55  (alternating-bit sync byte, 01010101)
  *   TYPE : identifies the payload kind (see below)
  *   LEN  : payload byte count (fixed per type; receiver validates)
  *   CRC16: CRC-16/CCITT (poly 0x1021, init 0xFFFF, no reflection)
  *           computed over SOF || TYPE || LEN || PAYLOAD
  *
  * Packet types and payload sizes:
  *   PROV_TYPE_PRIVKEY  0xB1  32 bytes  — SECP256R1 private key scalar
  *   PROV_TYPE_PUBKEY   0xB2  64 bytes  — SECP256R1 public key (x||y uncompressed)
  *   PROV_TYPE_CONFIG   0xB3  16 bytes  — 4 × uint32_t little-endian:
  *                                         [0] TxTimeoutMs
  *                                         [1] MainCycleDelayUs
  *                                         [2] ResponseDelayToleranceMs
  *                                         [3] WatchdogTimeoutMs
  *
  * Packet sizes (total bytes on wire):
  *   Private key : 1+1+1+32+2 = 37 bytes  (~38 ms @ 9600 baud)
  *   Public key  : 1+1+1+64+2 = 69 bytes  (~72 ms @ 9600 baud)
  *   Config      : 1+1+1+16+2 = 21 bytes  (~22 ms @ 9600 baud)
  *
  * Session flow:
  *   Device                          Counterpart
  *     |--- PROV_READY (0xAA) ------->|
  *     |<-- SOF|TYPE|LEN|PAYLOAD|CRC -|  (packet N)
  *     |  [verify CRC]                |
  *     |--- PROV_ACK (0x06) --------->|  OK  → store; counterpart sends next
  *     |--- PROV_NAK (0x15) --------->|  bad → counterpart retransmits (max 3×)
  *     |      ...                     |
  *     |<-- PROV_EOT (0x04) ----------|  no more packets
  *     |--- PROV_ACK (0x06) --------->|
  *     |  [write flash NVRAM]         |
  *
  *   Counterpart may send any subset of the three packets in any order.
  *   The device sends PROV_READY only once; after that each ACK/NAK acts as
  *   the implicit "ready" signal for the counterpart.
  *
  * LED feedback (PA2 — STAT_FRIEND_FOF):
  *   Searching for counterpart : 250 ms on / 250 ms off  (slow blink)
  *   Communication in progress : 50 ms on  / 50 ms off   (fast blink)
  *   Provisioning complete     : constant ON
  *   Unrecoverable error       : SOS Morse pattern, then OFF
  * ---------------------------------------------------------------------------
  */

#ifndef UART_PROV_H
#define UART_PROV_H

#ifdef __cplusplus
extern "C" {
#endif

/* Control bytes */
#define PROV_READY          0xAAu
#define PROV_ACK            0x06u
#define PROV_NAK            0x15u
#define PROV_EOT            0x04u

/* Packet frame constants */
#define PROV_SOF            0x55u
#define PROV_TYPE_PRIVKEY   0xB1u
#define PROV_TYPE_PUBKEY    0xB2u
#define PROV_TYPE_CONFIG    0xB3u

/* Payload lengths (bytes) */
#define PROV_PRIVKEY_LEN    32u
#define PROV_PUBKEY_LEN     64u
#define PROV_CONFIG_LEN     16u   /* 4 × uint32_t */

typedef enum {
    UART_PROV_NO_COUNTERPART = 0, /* no counterpart detected — normal cold start */
    UART_PROV_OK,                 /* all received packets stored to NVRAM */
    UART_PROV_PARTIAL,            /* at least one packet stored; others not sent */
    UART_PROV_ERROR,              /* unrecoverable: CRC retries exhausted or flash fail */
} UartProvResult;

/**
 * @brief  Run one UART provisioning session.
 *
 * @details Initialises USART1, attempts to detect a counterpart by sending
 *          PROV_READY.  If no counterpart replies within the detection window,
 *          returns UART_PROV_NO_COUNTERPART immediately.  Otherwise receives
 *          and stores whichever key/config packets the counterpart sends,
 *          verifying each with CRC-16/CCITT.  Received data is written to the
 *          NVRAM flash page atomically on EOT.  USART1 is de-initialised before
 *          returning regardless of outcome.
 *
 * @retval UART_PROV_NO_COUNTERPART  Proceed normally with existing NVRAM data.
 * @retval UART_PROV_OK              Keys/config updated; device may proceed.
 * @retval UART_PROV_PARTIAL         Partial update; device may proceed.
 * @retval UART_PROV_ERROR           Provisioning failed; existing NVRAM preserved.
 */
UartProvResult uart_prov_run(void);

#ifdef __cplusplus
}
#endif

#endif /* UART_PROV_H */
