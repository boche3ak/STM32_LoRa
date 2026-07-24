/**
 * @file    dtc.h
 * @brief   Diagnostic Trouble Code (DTC) framework.
 *
 * DTCs are accumulated in a RAM ring buffer during operation and persisted
 * to a dedicated 1 KB flash page (DTC_FLASH_BASE) on clean shutdown or
 * every DTC_FLUSH_INTERVAL_MS milliseconds.  Reset cause is read from
 * RCC_CSR at init so a watchdog reset is captured without needing a
 * persistent flag.
 *
 * Flash page layout:
 *   [0]   magic      (4 B)  — DTC_MAGIC when page is valid
 *   [4]   fw_version (4 B)  — FW_VERSION_WORD: (MAJOR<<16)|(MINOR<<8)|PATCH
 *   [8]   count      (4 B)  — number of stored entries
 *   [12]  entries[]  (8 B × count) — DTC_Entry records
 */

#ifndef DTC_H
#define DTC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* ── Flash location ────────────────────────────────────────────────────────── */
#define DTC_FLASH_BASE      0x0800F800UL  /* 1 KB page immediately before NVRAM */
#define DTC_MAGIC           0xD1A6C0DEu

/* ── Capacity ──────────────────────────────────────────────────────────────── */
#define DTC_MAX_ENTRIES     30u           /* 1 + 30×8 = 241 B ≤ 255 B UART LEN */
#define DTC_ENTRY_SIZE      8u            /* sizeof(DTC_Entry) */

/* ── Periodic flush interval ───────────────────────────────────────────────── */
#define DTC_FLUSH_INTERVAL_MS  600000u    /* 10 minutes */

/* ── DTC identifiers ───────────────────────────────────────────────────────── */
#define DTC_RESET                  0x01u
#define DTC_SW_FAILURE             0x02u
#define DTC_HW_FAILURE             0x03u
#define DTC_LORA_RX_TIMEOUT        0x04u
#define DTC_LORA_CRC_ERROR         0x05u
#define DTC_LORA_HMAC_FAILURE      0x06u
#define DTC_LORA_TX_TIMEOUT        0x07u
#define DTC_LORA_INIT_FAILURE      0x08u
#define DTC_CHALLENGE_RTT_EXCEEDED 0x09u

/* ── Reset causes (DTC_RESET ev1) ─────────────────────────────────────────── */
#define DTC_RST_POWER_ON    0x01u
#define DTC_RST_WATCHDOG    0x02u
#define DTC_RST_SOFTWARE    0x03u
#define DTC_RST_PIN         0x04u
#define DTC_RST_BROWNOUT    0x05u

/* ── HW IDs (DTC_HW_FAILURE ev1) ──────────────────────────────────────────── */
#define DTC_HW_LORA_SPI     0x01u
#define DTC_HW_FLASH        0x02u

/* ── Entry structure ───────────────────────────────────────────────────────── */
typedef struct {
    uint8_t  id;           /* DTC identifier (DTC_xxx) */
    uint8_t  ev1;          /* event data 1: sub-type or high byte of a value */
    uint8_t  ev2;          /* event data 2: extra data or low byte of a value */
    uint8_t  _pad;         /* reserved, always 0 */
    uint32_t timestamp_s;  /* seconds since boot (HAL_GetTick() / 1000) */
} DTC_Entry;               /* 8 bytes, word-aligned */

/* ── API ───────────────────────────────────────────────────────────────────── */

/**
 * @brief Load existing DTCs from flash, read RCC_CSR for reset cause, and
 *        log a DTC_RESET entry.  Must be called before uart_prov_run().
 */
void dtc_init(void);

/**
 * @brief Append a DTC entry to the RAM buffer.  If the buffer is full the
 *        oldest entry is silently discarded (ring behaviour).
 */
void dtc_log(uint8_t id, uint8_t ev1, uint8_t ev2);

/**
 * @brief Persist the RAM buffer to the DTC flash page (erase + rewrite).
 *        Safe to call from both provisioning and main-loop contexts.
 */
void dtc_flush(void);

/**
 * @brief Clear the RAM buffer and erase the DTC flash page.
 */
void dtc_clear(void);

/** @brief Return current number of entries in the RAM buffer. */
uint8_t           dtc_get_count(void);

/** @brief Return pointer to the RAM buffer (read-only). */
const DTC_Entry  *dtc_get_entries(void);

/**
 * @brief Call once per main-loop iteration.  Calls dtc_flush() when
 *        DTC_FLUSH_INTERVAL_MS has elapsed since the last flush.
 */
void dtc_tick(void);

#ifdef __cplusplus
}
#endif

#endif /* DTC_H */
