/**
  ******************************************************************************
  * @file    uart_prov.c
  * @brief   UART field-provisioning — receives private key, public key, and
  *          configuration data from a provisioning counterpart and persists
  *          them to the NVRAM flash page.
  *
  * See uart_prov.h for the full protocol description.
  *
  * UART I/O uses USART1 registers directly (no HAL UART driver) to keep the
  * flash footprint minimal.
  ******************************************************************************
  */

#include "uart_prov.h"
#include "usart.h"
#include "main.h"
#include <string.h>
#include <stdbool.h>

/* ============================================================================
 * NVRAM layout (must mirror STM32F103C8TX_FLASH.ld)
 * ============================================================================ */
#define NVRAM_BASE_ADDR    0x0800FC00UL
#define NVRAM_SIZE         1024u
#define NVRAM_PRIVKEY_OFF  4u    /* 32 bytes after 4-byte magic */
#define NVRAM_PUBKEY_OFF   36u   /* 64 bytes                     */
#define NVRAM_CONFIG_OFF   100u  /* 32 bytes = 8 × uint32_t      */

/* ============================================================================
 * Timing
 * ============================================================================ */
#define DETECT_TIMEOUT_MS       2000u  /* per READY attempt (detection phase)         */
#define SESSION_IDLE_TIMEOUT_MS 5000u  /* between packets in an active session        */
#define DETECT_ATTEMPTS         3u     /* total READY attempts before giving up       */
#define BYTE_TIMEOUT_MS         500u   /* per-byte timeout inside a packet            */
#define SUCCESS_SHOW_MS    3000u  /* steady LED duration after success    */
#define ERROR_SHOW_MS      10000u /* SOS LED duration after error         */

/* ============================================================================
 * LED  (PA2 — STAT_FRIEND_FOF)
 * ============================================================================ */
#define PROV_LED_ON()   HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_SET)
#define PROV_LED_OFF()  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_RESET)

/* SOS Morse: interleaved (ON ms, OFF ms) pairs */
static const uint16_t sos_pattern[] = {
    100u, 100u,   /* S dit 1 */
    100u, 100u,   /* S dit 2 */
    100u, 300u,   /* S dit 3 + letter gap */
    300u, 100u,   /* O dah 1 */
    300u, 100u,   /* O dah 2 */
    300u, 300u,   /* O dah 3 + letter gap */
    100u, 100u,   /* S dit 1 */
    100u, 100u,   /* S dit 2 */
    100u, 700u,   /* S dit 3 + word gap   */
};
#define SOS_STEPS  ((uint8_t)(sizeof(sos_pattern) / sizeof(sos_pattern[0])))  /* 18 */

typedef enum { LED_IDLE, LED_SLOW_BLINK, LED_FAST_BLINK, LED_STEADY_ON, LED_SOS } LedMode;

static LedMode  led_mode       = LED_IDLE;
static uint32_t led_phase_tick = 0u;
static uint8_t  led_gpio_val   = 0u;
static uint8_t  sos_step       = 0u;

static void led_set(LedMode mode)
{
    led_mode       = mode;
    led_phase_tick = HAL_GetTick();
    sos_step       = 0u;
    led_gpio_val   = (mode == LED_STEADY_ON || mode == LED_SOS) ? 1u : 0u;
    if (led_gpio_val) PROV_LED_ON(); else PROV_LED_OFF();
}

static void led_update(void)
{
    uint32_t now = HAL_GetTick();
    switch (led_mode)
    {
        case LED_SLOW_BLINK:
            if ((now - led_phase_tick) >= 250u) {
                led_gpio_val ^= 1u;
                if (led_gpio_val) PROV_LED_ON(); else PROV_LED_OFF();
                led_phase_tick = now;
            }
            break;

        case LED_FAST_BLINK:
            if ((now - led_phase_tick) >= 50u) {
                led_gpio_val ^= 1u;
                if (led_gpio_val) PROV_LED_ON(); else PROV_LED_OFF();
                led_phase_tick = now;
            }
            break;

        case LED_SOS:
            if ((now - led_phase_tick) >= sos_pattern[sos_step]) {
                sos_step = (sos_step + 1u) % SOS_STEPS;
                /* even index → ON, odd index → OFF */
                led_gpio_val = (sos_step % 2u == 0u) ? 1u : 0u;
                if (led_gpio_val) PROV_LED_ON(); else PROV_LED_OFF();
                led_phase_tick = now;
            }
            break;

        default:
            break;
    }
}

static void led_show_for(LedMode mode, uint32_t duration_ms)
{
    led_set(mode);
    uint32_t t0 = HAL_GetTick();
    while ((HAL_GetTick() - t0) < duration_ms) {
        led_update();
        IWDG->KR = 0xAAAAu;
    }
    PROV_LED_OFF();
}

/* ============================================================================
 * CRC-16/CCITT  (poly 0x1021, init 0xFFFF, no reflection)
 * ============================================================================ */
static uint16_t crc16_ccitt(const uint8_t *data, uint16_t len)
{
    uint16_t crc = 0xFFFFu;
    while (len--) {
        crc ^= (uint16_t)(*data++) << 8u;
        for (uint8_t i = 0u; i < 8u; i++)
            crc = (crc & 0x8000u) ? ((crc << 1u) ^ 0x1021u) : (crc << 1u);
    }
    return crc;
}

/* ============================================================================
 * UART register-level helpers (USART1)
 * ============================================================================ */
static bool uart_send(uint8_t b)
{
    uint32_t deadline = HAL_GetTick() + 50u;
    while (!(USART1->SR & USART_SR_TXE)) {
        if (HAL_GetTick() > deadline) return false;
    }
    USART1->DR = b;
    return true;
}

/* Poll RXNE with LED update and watchdog kick; 1 ms granularity */
static bool uart_recv_byte(uint8_t *out, uint32_t timeout_ms)
{
    uint32_t deadline = HAL_GetTick() + timeout_ms;
    while (HAL_GetTick() < deadline) {
        led_update();
        IWDG->KR = 0xAAAAu;
        if (USART1->SR & USART_SR_RXNE) {
            *out = (uint8_t)(USART1->DR & 0xFFu);
            return true;
        }
    }
    return false;
}

/* ============================================================================
 * Packet body receiver
 *
 * Called after the SOF byte (0x55) has already been consumed.
 * frame_buf[0] must already contain PROV_SOF.
 * Reads: TYPE | LEN | PAYLOAD | CRC_HI | CRC_LO
 * Validates type, length, and CRC.
 * ============================================================================ */
typedef struct {
    uint8_t type;
    uint8_t len;
    uint8_t payload[64];  /* sized for the largest packet (public key, 64 B) */
} Packet;

static bool recv_packet_body(Packet *pkt, uint8_t frame_buf[/* 3+64 */])
{
    /* frame_buf[0] = PROV_SOF (already set by caller) */

    if (!uart_recv_byte(&frame_buf[1], BYTE_TIMEOUT_MS)) return false; /* TYPE */
    if (!uart_recv_byte(&frame_buf[2], BYTE_TIMEOUT_MS)) return false; /* LEN  */

    uint8_t type = frame_buf[1];
    uint8_t len  = frame_buf[2];

    uint8_t expected_len;
    switch (type) {
        case PROV_TYPE_PRIVKEY:  expected_len = PROV_PRIVKEY_LEN; break;
        case PROV_TYPE_PUBKEY:   expected_len = PROV_PUBKEY_LEN;  break;
        case PROV_TYPE_CONFIG:   expected_len = PROV_CONFIG_LEN;  break;
        case PROV_GET_CONFIG:    expected_len = 0u;               break;
        case PROV_GET_PRIVKEY:   expected_len = 0u;               break;
        case PROV_GET_PUBKEY:    expected_len = 0u;               break;
        default:
            /* Unknown type: drain payload + CRC to keep framing intact, then reject. */
            for (uint8_t i = 0u; i < len; i++) {
                uint8_t dummy;
                if (!uart_recv_byte(&dummy, BYTE_TIMEOUT_MS)) return false;
            }
            { uint8_t d; uart_recv_byte(&d, BYTE_TIMEOUT_MS); uart_recv_byte(&d, BYTE_TIMEOUT_MS); }
            uart_send(PROV_RJCT);
            return false;
    }
    if (len != expected_len) return false;

    for (uint8_t i = 0u; i < len; i++) {
        if (!uart_recv_byte(&frame_buf[3u + i], BYTE_TIMEOUT_MS)) return false;
    }

    uint8_t crc_hi, crc_lo;
    if (!uart_recv_byte(&crc_hi, BYTE_TIMEOUT_MS)) return false;
    if (!uart_recv_byte(&crc_lo, BYTE_TIMEOUT_MS)) return false;

    uint16_t rx_crc = ((uint16_t)crc_hi << 8u) | crc_lo;
    uint16_t my_crc = crc16_ccitt(frame_buf, (uint16_t)(3u + len));

    if (rx_crc != my_crc) return false;

    pkt->type = type;
    pkt->len  = len;
    memcpy(pkt->payload, &frame_buf[3], len);
    return true;
}

/* ============================================================================
 * Flash NVRAM rewrite
 *
 * Erases the NVRAM flash page and reprograms it from nvram_shadow[].
 * The caller is responsible for pre-loading nvram_shadow with the complete
 * desired page content before calling this function.
 * ============================================================================ */
static uint8_t nvram_shadow[NVRAM_SIZE];

static bool nvram_write_page(void)
{
    HAL_FLASH_Unlock();

    FLASH_EraseInitTypeDef erase = {
        .TypeErase   = FLASH_TYPEERASE_PAGES,
        .PageAddress = NVRAM_BASE_ADDR,
        .NbPages     = 1u,
    };
    uint32_t page_error = 0u;
    if (HAL_FLASHEx_Erase(&erase, &page_error) != HAL_OK) {
        HAL_FLASH_Lock();
        return false;
    }

    /* STM32F1: minimum program unit is 16-bit half-word */
    for (uint32_t i = 0u; i < NVRAM_SIZE; i += 2u) {
        uint16_t hw = (uint16_t)nvram_shadow[i] |
                      ((uint16_t)nvram_shadow[i + 1u] << 8u);
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_HALFWORD, NVRAM_BASE_ADDR + i, hw) != HAL_OK) {
            HAL_FLASH_Lock();
            return false;
        }
        IWDG->KR = 0xAAAAu;
    }

    HAL_FLASH_Lock();
    return true;
}

/* ============================================================================
 * Public entry point
 * ============================================================================ */
UartProvResult uart_prov_run(void)
{
    MX_USART1_UART_Init();

    /* SOF(1) + TYPE(1) + LEN(1) + PAYLOAD_MAX(64) */
    uint8_t frame_buf[67];
    Packet  pkt;

    /* ---- Counterpart detection ------------------------------------------ */
    led_set(LED_SLOW_BLINK);

    uint8_t first_byte = 0u;
    bool    detected   = false;

    for (uint8_t attempt = 0u; attempt < DETECT_ATTEMPTS && !detected; attempt++)
    {
        uart_send(PROV_READY);
        if (uart_recv_byte(&first_byte, DETECT_TIMEOUT_MS)) {
            /*
             * Accept only meaningful protocol bytes.  With pull-up on PA10 the
             * RX line is held idle-high, but if noise still produces a byte we
             * do not want to enter the session loop on garbage.
             * Valid first bytes from the counterpart:
             *   PROV_PING (0x05) — keepalive sent every second after READY
             *   PROV_SOF  (0x55) — start of the first data packet
             *   PROV_EOT  (0x04) — immediate end-of-session (unusual but valid)
             */
            if (   first_byte == PROV_PING
                || first_byte == PROV_SOF
                || first_byte == PROV_EOT) {
                detected = true;
            }
            /* else: noise byte — discard and try the next READY attempt */
        }
    }

    if (!detected) {
        PROV_LED_OFF();
        MX_USART1_UART_DeInit();
        return UART_PROV_NO_COUNTERPART;
    }

    /* ---- Provisioning session ------------------------------------------- */
    led_set(LED_FAST_BLINK);

    /* Seed shadow from current NVRAM (preserves magic and untouched sections) */
    memcpy(nvram_shadow, (const void *)NVRAM_BASE_ADDR, NVRAM_SIZE);

    bool any_stored  = false;
    bool session_err = false;

    /*
     * first_byte holds the first byte the counterpart sent in response to
     * PROV_READY (could be PROV_SOF, PROV_EOT, or noise).
     * Process it without re-reading on the first iteration of the loop.
     */
    for (;;)
    {
        uint8_t b = first_byte;
        first_byte = 0u;

        if (b == 0u) {
            /* Wait for SOF, EOT, or PING from counterpart.
             * SESSION_IDLE_TIMEOUT_MS >> ping interval (1 s), so one missed
             * ping does not drop the session prematurely. */
            if (!uart_recv_byte(&b, SESSION_IDLE_TIMEOUT_MS)) {
                session_err = true;
                break;
            }
        }

        if (b == PROV_EOT) {
            uart_send(PROV_ACK);
            break;
        }

        if (b != PROV_SOF) {
            continue;  /* discard framing noise, wait for valid SOF */
        }

        /* SOF received — read packet body */
        frame_buf[0] = PROV_SOF;
        bool pkt_ok = recv_packet_body(&pkt, frame_buf);

        if (pkt_ok) {
            if (   pkt.type == PROV_GET_CONFIG
                || pkt.type == PROV_GET_PRIVKEY
                || pkt.type == PROV_GET_PUBKEY) {
                /*
                 * Read-back queries.  All three commands share the same response
                 * frame shape (SOF | TYPE | LEN | PAYLOAD | CRC16).  Data is read
                 * from nvram_shadow, not from flash, so that any pending writes
                 * received earlier in this session are reflected immediately.
                 */
                uint8_t  resp_type;
                uint8_t  resp_len;
                uint16_t resp_off;

                switch (pkt.type) {
                    case PROV_GET_PRIVKEY:
                        resp_type = PROV_TYPE_PRIVKEY;
                        resp_len  = PROV_PRIVKEY_LEN;
                        resp_off  = NVRAM_PRIVKEY_OFF;
                        break;
                    case PROV_GET_PUBKEY:
                        resp_type = PROV_TYPE_PUBKEY;
                        resp_len  = PROV_PUBKEY_LEN;
                        resp_off  = NVRAM_PUBKEY_OFF;
                        break;
                    default: /* PROV_GET_CONFIG */
                        resp_type = PROV_TYPE_CONFIG;
                        resp_len  = PROV_CONFIG_LEN;
                        resp_off  = NVRAM_CONFIG_OFF;
                        break;
                }

                /* Largest response is public key (64 B): frame = 3 + 64 = 67 B */
                uint8_t resp[3u + PROV_PUBKEY_LEN];
                resp[0u] = PROV_SOF;
                resp[1u] = resp_type;
                resp[2u] = resp_len;
                memcpy(&resp[3u], nvram_shadow + resp_off, resp_len);
                uint16_t resp_crc = crc16_ccitt(resp, (uint16_t)(3u + resp_len));
                for (uint8_t i = 0u; i < (uint8_t)(3u + resp_len); i++) uart_send(resp[i]);
                uart_send((uint8_t)(resp_crc >> 8u));
                uart_send((uint8_t)(resp_crc & 0xFFu));
            } else {
                uart_send(PROV_ACK);   /* ACK = accepted + ready for next */
                switch (pkt.type) {
                    case PROV_TYPE_PRIVKEY:
                        memcpy(nvram_shadow + NVRAM_PRIVKEY_OFF, pkt.payload, PROV_PRIVKEY_LEN);
                        break;
                    case PROV_TYPE_PUBKEY:
                        memcpy(nvram_shadow + NVRAM_PUBKEY_OFF,  pkt.payload, PROV_PUBKEY_LEN);
                        break;
                    case PROV_TYPE_CONFIG:
                        memcpy(nvram_shadow + NVRAM_CONFIG_OFF,  pkt.payload, PROV_CONFIG_LEN);
                        break;
                    default:
                        break;
                }
                any_stored = true;
            }
        } else {
            uart_send(PROV_NAK);   /* NAK = CRC error, please retransmit */
        }

        IWDG->KR = 0xAAAAu;
    }

    /* ---- Persist and indicate result ------------------------------------ */
    UartProvResult result;

    if (session_err) {
        result = UART_PROV_ERROR;
        led_show_for(LED_SOS, ERROR_SHOW_MS);
    } else if (!any_stored) {
        result = UART_PROV_OK;        /* counterpart had nothing to send */
        led_show_for(LED_STEADY_ON, SUCCESS_SHOW_MS);
    } else {
        if (nvram_write_page()) {
            result = UART_PROV_OK;
            led_show_for(LED_STEADY_ON, SUCCESS_SHOW_MS);
        } else {
            result = UART_PROV_ERROR;
            led_show_for(LED_SOS, ERROR_SHOW_MS);
        }
    }

    MX_USART1_UART_DeInit();
    return result;
}
