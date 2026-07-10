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
  *   PROV_TYPE_CONFIG   0xB3  24 bytes  — 6 × uint32_t little-endian:
  *                                         [0] TxTimeoutMs
  *                                         [1] TransponderMainCycleMs
  *                                         [2] ChallengerMainCycleMs
  *                                         [3] ResponseWaitCycleDelayMs
  *                                         [4] ResponseDelayToleranceMs
  *                                         [5] WatchdogTimeoutMs
  *   PROV_GET_CONFIG    0xB4   0 bytes  — query: read back current NVRAM config
  *                                         device replies with a PROV_TYPE_CONFIG packet
  *   PROV_GET_PRIVKEY   0xB5   0 bytes  — query: read back stored private key
  *                                         device replies with a PROV_TYPE_PRIVKEY packet
  *   PROV_GET_PUBKEY    0xB6   0 bytes  — query: read back stored public key
  *                                         device replies with a PROV_TYPE_PUBKEY packet
  *
  * Control byte (device → counterpart, response to unsupported request):
  *   PROV_RJCT   0xFF  — request not supported by this device firmware
  *
  * Packet sizes (total bytes on wire):
  *   Private key  : 1+1+1+32+2 = 37 bytes  (~38 ms @ 9600 baud)
  *   Public key   : 1+1+1+64+2 = 69 bytes  (~72 ms @ 9600 baud)
  *   Config write : 1+1+1+24+2 = 29 bytes  (~30 ms @ 9600 baud)
  *   Get config   : 1+1+1+ 0+2 =  5 bytes  (< 1 ms @ 9600 baud)
  *   Get privkey  : 1+1+1+ 0+2 =  5 bytes  (< 1 ms @ 9600 baud)
  *   Get pubkey   : 1+1+1+ 0+2 =  5 bytes  (< 1 ms @ 9600 baud)
  *
  * Session flow:
  *   Device                          Counterpart
  *     |--- PROV_READY (0xAA) ------->|
  *     |<-- PROV_PING (0x05)  --------|  keepalive (ignored, resets idle timer)
  *     |<-- SOF|TYPE|LEN|PAYLOAD|CRC -|  (packet N)
  *     |  [verify CRC]                |
  *     |--- PROV_ACK (0x06) --------->|  OK  → store; counterpart sends next
  *     |--- PROV_NAK (0x15) --------->|  bad → counterpart retransmits (max 3×)
  *     |<-- PROV_PING …               |  keepalive during operator menu navigation
  *     |      ...                     |
  *     |<-- PROV_EOT (0x04) ----------|  end of session (commits flash write)
  *     |--- PROV_ACK (0x06) --------->|
  *     |  [write flash NVRAM]         |
  *
  *   Counterpart may send any subset of the write packets in any order,
  *   optionally preceded by a PROV_GET_CONFIG query.  PROV_PING bytes sent
  *   between packets keep the device in the session loop
  *   (SESSION_IDLE_TIMEOUT_MS = 5000 ms >> 1 s ping interval).  Flash is
  *   written atomically only when PROV_EOT is received.
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
#define PROV_EOT            0x04u   /* end of transmission — commits flash write  */
#define PROV_PING           0x05u   /* keepalive from counterpart (ASCII ENQ); ignored by packet loop */
#define PROV_RJCT           0xFFu   /* request not supported by this firmware     */

/* Packet frame constants */
#define PROV_SOF            0x55u
#define PROV_TYPE_PRIVKEY   0xB1u
#define PROV_TYPE_PUBKEY    0xB2u
#define PROV_TYPE_CONFIG    0xB3u
#define PROV_GET_CONFIG     0xB4u
#define PROV_GET_PRIVKEY    0xB5u
#define PROV_GET_PUBKEY     0xB6u

/* Payload lengths (bytes) */
#define PROV_PRIVKEY_LEN    32u
#define PROV_PUBKEY_LEN     64u
#define PROV_CONFIG_LEN     24u   /* 6 × uint32_t */

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
