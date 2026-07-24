/**
 * @file  dtc.c
 * @brief Diagnostic Trouble Code framework — RAM buffer + flash persistence.
 */

#include "dtc.h"
#include "version.h"
#include "stm32f1xx_hal.h"
#include <string.h>

/* ── Internal state ──────────────────────────────────────────────────────── */
#define DTC_HDR_SIZE  12u  /* magic (4 B) + fw_version (4 B) + count (4 B) */

static DTC_Entry s_buf[DTC_MAX_ENTRIES];
static uint8_t   s_count = 0u;
static uint32_t  s_last_flush_tick = 0u;

/* ── Flash helpers ───────────────────────────────────────────────────────── */
static void flash_write_page(const uint8_t *data, uint32_t len)
{
    HAL_FLASH_Unlock();

    FLASH_EraseInitTypeDef erase = {
        .TypeErase   = FLASH_TYPEERASE_PAGES,
        .PageAddress = DTC_FLASH_BASE,
        .NbPages     = 1u,
    };
    uint32_t page_error = 0u;
    if (HAL_FLASHEx_Erase(&erase, &page_error) != HAL_OK) {
        HAL_FLASH_Lock();
        return;
    }

    /* STM32F1: minimum program unit is a 16-bit half-word */
    for (uint32_t i = 0u; i < len; i += 2u) {
        uint16_t hw = (uint16_t)data[i] | ((uint16_t)data[i + 1u] << 8u);
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_HALFWORD, DTC_FLASH_BASE + i, hw);
        IWDG->KR = 0xAAAAu;   /* keep watchdog happy during long writes */
    }

    HAL_FLASH_Lock();
}

/* ── Public API ──────────────────────────────────────────────────────────── */

void dtc_init(void)
{
    /* Load existing entries from flash if the page is valid */
    const uint32_t magic = *(volatile const uint32_t *)(DTC_FLASH_BASE + 0u);
    /* fw_version at offset 4 — read but not validated (future use) */
    const uint32_t cnt   = *(volatile const uint32_t *)(DTC_FLASH_BASE + 8u);

    if (magic == DTC_MAGIC && cnt <= DTC_MAX_ENTRIES) {
        s_count = (uint8_t)cnt;
        memcpy(s_buf,
               (const void *)(DTC_FLASH_BASE + DTC_HDR_SIZE),
               (uint32_t)s_count * DTC_ENTRY_SIZE);
    } else {
        s_count = 0u;
    }

    /* Determine reset cause from hardware flags — no persistent flag needed */
    uint32_t csr = RCC->CSR;
    RCC->CSR |= RCC_CSR_RMVF;   /* clear all reset-source flags */

    uint8_t cause;
    if      (csr & RCC_CSR_IWDGRSTF)  cause = DTC_RST_WATCHDOG;
    else if (csr & RCC_CSR_PORRSTF)   cause = DTC_RST_POWER_ON;
    else if (csr & RCC_CSR_SFTRSTF)   cause = DTC_RST_SOFTWARE;
    else if (csr & RCC_CSR_PINRSTF)   cause = DTC_RST_PIN;
    else if (csr & RCC_CSR_LPWRRSTF)  cause = DTC_RST_BROWNOUT;
    else                               cause = DTC_RST_POWER_ON;

    dtc_log(DTC_RESET, cause, 0u);

    s_last_flush_tick = HAL_GetTick();
}

void dtc_log(uint8_t id, uint8_t ev1, uint8_t ev2)
{
    if (s_count >= DTC_MAX_ENTRIES) {
        /* Ring: drop the oldest entry to make room */
        memmove(&s_buf[0], &s_buf[1],
                (uint32_t)(DTC_MAX_ENTRIES - 1u) * DTC_ENTRY_SIZE);
        s_count = DTC_MAX_ENTRIES - 1u;
    }
    DTC_Entry *e = &s_buf[s_count++];
    e->id          = id;
    e->ev1         = ev1;
    e->ev2         = ev2;
    e->_pad        = 0u;
    e->timestamp_s = HAL_GetTick() / 1000u;
}

void dtc_flush(void)
{
    /* Build header + entries into a local buffer, then write as one page */
    uint8_t buf[DTC_HDR_SIZE + DTC_MAX_ENTRIES * DTC_ENTRY_SIZE];
    uint32_t used = DTC_HDR_SIZE + (uint32_t)s_count * DTC_ENTRY_SIZE;

    uint32_t ver = FW_VERSION_WORD;
    /* magic (little-endian) */
    buf[0] = (uint8_t)(DTC_MAGIC);
    buf[1] = (uint8_t)(DTC_MAGIC >>  8u);
    buf[2] = (uint8_t)(DTC_MAGIC >> 16u);
    buf[3] = (uint8_t)(DTC_MAGIC >> 24u);
    /* fw_version (little-endian: PATCH, MINOR, MAJOR, 0) */
    buf[4] = (uint8_t)( ver        & 0xFFu);
    buf[5] = (uint8_t)((ver >>  8u) & 0xFFu);
    buf[6] = (uint8_t)((ver >> 16u) & 0xFFu);
    buf[7] = 0u;
    /* count */
    buf[8]  = s_count;
    buf[9]  = 0u;
    buf[10] = 0u;
    buf[11] = 0u;
    /* entries */
    memcpy(buf + DTC_HDR_SIZE, s_buf, (uint32_t)s_count * DTC_ENTRY_SIZE);

    flash_write_page(buf, used % 2u ? used + 1u : used); /* keep even for halfword writes */

    s_last_flush_tick = HAL_GetTick();
}

void dtc_clear(void)
{
    s_count = 0u;

    HAL_FLASH_Unlock();
    FLASH_EraseInitTypeDef erase = {
        .TypeErase   = FLASH_TYPEERASE_PAGES,
        .PageAddress = DTC_FLASH_BASE,
        .NbPages     = 1u,
    };
    uint32_t page_error = 0u;
    HAL_FLASHEx_Erase(&erase, &page_error);
    HAL_FLASH_Lock();
}

uint8_t dtc_get_count(void)
{
    return s_count;
}

const DTC_Entry *dtc_get_entries(void)
{
    return s_buf;
}

void dtc_tick(void)
{
    if ((HAL_GetTick() - s_last_flush_tick) >= DTC_FLUSH_INTERVAL_MS) {
        dtc_flush();
    }
}
