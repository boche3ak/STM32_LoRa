## Document References

[STM32F103 Datasheet](https://www.st.com/resource/en/datasheet/stm32f103c8.pdf)

[Semtec SX1278 Datasheet](https://cdn-shop.adafruit.com/product-files/3179/sx1276_77_78_79.pdf)

## Code Guidelines

We align with the basic [Google C++ Code Style Guide](https://google.github.io/styleguide/cppguide.html)
Any deviation shall be documented in this section.

## Feature development workflow

✅Ticket as a task -> separate branch -> commit with ticket reference

❌ Direct commits in master are not allowed, please create a branch.

## Merge strategy:

Gate: at least one peer review approval **and** buildable code

Git merge: fast forward with rebase - *this will create a strait main branch with no dubious merge commits.*

## Howto build:

This is a cmake project. Use the following commands to generate and build:

`cmake -DCMAKE_TOOLCHAIN_FILE=cmake/gcc-arm-none-eabi.cmake -DCMAKE_BUILD_TYPE=Debug -B build`

`cmake --build build`

---

## Field Provisioning via UART

The device supports field provisioning of cryptographic keys and runtime configuration
over USART1 at startup. No reflash of the application binary is needed.

### Hardware connection

| Signal | STM32 pin | Direction |
|--------|-----------|-----------|
| TX     | PA9       | device → counterpart |
| RX     | PA10      | counterpart → device |
| GND    | GND       | shared reference |

Settings: **9600 baud, 8N1, no flow control.**
PA10 is held idle-high by an internal pull-up while disconnected, preventing noise
on the floating pin from triggering a false session.

PA8 is not part of the UART link — it is the WHOAMI selector pin (Challenger vs Transponder).

### When provisioning runs

On every power-on the device sends a READY byte up to three times with a 2-second
timeout each (6 seconds total). If a counterpart responds with a valid protocol byte
(`PING`, `SOF`, or `EOT`), a provisioning session begins. If not, the device proceeds
normally with whatever data is already stored in NVRAM flash.

Once a session is open it stays open until the counterpart sends `EOT`. The
counterpart sends a `PING` keepalive every second so the operator can navigate menus
between operations without the device timing out. **Flash is written atomically only
when `EOT` is received** — the session is a transaction.

The counterpart may send any subset of the three write packets (private key, public
key, configuration) in any order, and may issue read-back queries at any point during
the session. Only the sections that were written are updated in NVRAM; the rest of the
1 KB page is preserved unchanged.

### LED feedback (PA2 — STAT\_FRIEND\_FOF)

| State | Pattern |
|-------|---------|
| Searching for counterpart | Slow blink — 250 ms on / 250 ms off |
| Communication in progress | Fast blink — 50 ms on / 50 ms off |
| Provisioning complete | Steady ON for 3 seconds |
| Unrecoverable error | SOS Morse pattern for 10 seconds |

After the provisioning phase ends (success or error) the LED is released and normal
LoRa operation takes over.

### Protocol

#### Control bytes

| Byte | Value | Direction | Meaning |
|------|-------|-----------|---------|
| `READY` | `0xAA` | device → counterpart | Device ready; session open |
| `ACK`   | `0x06` | device → counterpart | Packet accepted or EOT acknowledged (ASCII ACK) |
| `NAK`   | `0x15` | device → counterpart | CRC error — retransmit (ASCII NAK) |
| `RJCT`  | `0xFF` | device → counterpart | Unsupported packet type |
| `EOT`   | `0x04` | counterpart → device | End of session — commit flash (ASCII EOT) |
| `PING`  | `0x05` | counterpart → device | Keepalive — resets idle timer (ASCII ENQ) |

The device idle timeout is **5 seconds**. The counterpart sends `PING` every 1 second,
so up to four consecutive pings may be lost without dropping the session.

#### Packet frame

```
┌────────┬────────┬────────┬─────────────────┬──────────┬──────────┐
│ SOF    │ TYPE   │ LEN    │ PAYLOAD         │ CRC_HI   │ CRC_LO   │
│ 0x55   │ 1 byte │ 1 byte │ LEN bytes       │          │          │
└────────┴────────┴────────┴─────────────────┴──────────┴──────────┘
```

- **SOF** `0x55` — start-of-frame sync byte (alternating-bit pattern `01010101`).
- **TYPE** — identifies the payload kind:

  | Type constant | Value | Direction | Payload | Size |
  |---------------|-------|-----------|---------|------|
  | `PROV_TYPE_PRIVKEY`  | `0xB1` | counterpart → device | SECP256R1 private key scalar | 32 B |
  | `PROV_TYPE_PUBKEY`   | `0xB2` | counterpart → device | SECP256R1 uncompressed public key x\|\|y | 64 B |
  | `PROV_TYPE_CONFIG`   | `0xB3` | counterpart → device | Runtime config, 8 × `uint32_t` LE | 32 B |
  | `PROV_GET_CONFIG`    | `0xB4` | counterpart → device | Query — no payload; device replies with `0xB3` | 0 B |
  | `PROV_GET_PRIVKEY`   | `0xB5` | counterpart → device | Query — no payload; device replies with `0xB1` | 0 B |
  | `PROV_GET_PUBKEY`    | `0xB6` | counterpart → device | Query — no payload; device replies with `0xB2` | 0 B |

- **LEN** — payload byte count (fixed per type; receiver validates and rejects mismatches).
- **CRC** — CRC-16/CCITT, polynomial `0x1021`, initial value `0xFFFF`, no reflection,
  computed over `SOF || TYPE || LEN || PAYLOAD`, transmitted big-endian (high byte first).

Write packets (`0xB1–0xB3`) are acknowledged with `ACK` or `NAK`.
Query packets (`0xB4–0xB6`) are answered with the corresponding data packet directly
(no separate `ACK`); the data packet itself serves as the acknowledgement.

#### Configuration payload layout

All eight fields are `uint32_t` in little-endian byte order (native STM32 storage format).

| Offset | Size | Field | Default |
|--------|------|-------|---------|
| 0  | 4 B | `TxTimeoutMs` — LoRa transmit timeout | 500 ms |
| 4  | 4 B | `TransponderMainCycleMs` — Transponder poll rate | 2 ms |
| 8  | 4 B | `ChallengerMainCycleMs` — Challenger poll rate | 1000 ms |
| 12 | 4 B | `ResponseWaitCycleDelayMs` — Challenger wait per cycle | 10 ms |
| 16 | 4 B | `ResponseDelayToleranceMs` — Max acceptable challenge-response RTT | 500 ms |
| 20 | 4 B | `WatchdogTimeoutMs` — IWDG reload timeout | 1000 ms |
| 24 | 4 B | `TxPowerDbm` — LoRa TX output power via PA_BOOST pin (2–20 dBm) | 14 dBm |
| 28 | 4 B | `LnaGain` — LNA gain: 0 = AGC auto, 1 = G1 (max sensitivity) … 6 = G6 (min sensitivity) | 1 |

Total: 32 bytes.

> **Field calibration note:** `LnaGain` is the primary range-tuning knob. Start at G1
> (default, maximum sensitivity) and step towards G6 until reliable detection ends at the
> desired boundary distance. `TxPowerDbm` controls how far the device is heard; reduce it
> only if battery life is a concern after LNA is tuned. AGC (`LnaGain = 0`) can be used
> when no fixed detection radius is required.

#### Session flow

The session persists across multiple operations. The counterpart keeps the session
alive with periodic `PING` bytes and commits the flash only at the end with `EOT`.

```
Device                                  Counterpart (e.g. Raspberry Pi tool)
  │                                           │
  │──── READY (0xAA) ────────────────────────>│  session open
  │                                           │
  │<─── PING (0x05) ──────────────────────────│  keepalive (every ~1 s)
  │                                           │
  │<─── SOF│0xB1│32│<privkey>│CRC ───────────│  write private key
  │     [verify CRC — OK]                     │
  │──── ACK (0x06) ──────────────────────────>│
  │                                           │
  │<─── SOF│0xB5│0│CRC ───────────────────────│  read-back: GET_PRIVKEY
  │──── SOF│0xB1│32│<privkey>│CRC ───────────>│  device replies with stored value
  │                                           │
  │<─── PING (0x05) ──────────────────────────│  operator navigating menus
  │<─── PING (0x05) ──────────────────────────│
  │                                           │
  │<─── SOF│0xB3│24│<config>│CRC ────────────│  write configuration
  │     [verify CRC — bad]                    │
  │──── NAK (0x15) ──────────────────────────>│  CRC error — retransmit
  │<─── SOF│0xB3│24│<config>│CRC ────────────│
  │     [verify CRC — OK]                     │
  │──── ACK (0x06) ──────────────────────────>│
  │                                           │
  │<─── EOT (0x04) ───────────────────────────│  end of session
  │──── ACK (0x06) ──────────────────────────>│
  │     [erase NVRAM page, rewrite]           │
  │     [LED steady ON → 3 s → OFF]           │
```

Rules for the counterpart implementation:

1. Send `PING` every 1 second while idle. The device idle timeout is 5 seconds.
2. After sending a write packet, wait for `ACK` or `NAK` before proceeding.
3. On `NAK` (CRC error), retransmit the same packet. On `RJCT` (unknown type), abort.
4. After sending a read-back query (`0xB4–0xB6`), read the response data packet
   directly — the device does not send a separate `ACK`.
5. When finished, send `EOT` and wait for `ACK`. Flash is written at this point.
6. Any combination of write and read-back operations is allowed in a single session.
   Sections not written during the session are left unchanged in NVRAM.

#### Examples
The file `tools/fof_prov.py` is a proved working sample which can be either
used directly of extended to receive the keys in the automatic way.

#### Packet sizes on wire

| Packet | Wire bytes | Time at 9600 baud |
|--------|-----------|-------------------|
| Write private key  (`0xB1`) | 37 B | ≈ 38 ms |
| Write public key   (`0xB2`) | 69 B | ≈ 72 ms |
| Write configuration (`0xB3`) | 37 B | ≈ 38 ms |
| Query (`0xB4`–`0xB6`)       |  5 B | < 1 ms |
| PING / EOT / READY           |  1 B | < 1 ms |

### NVRAM flash layout

All provisioned data shares a single 1 KB flash page at `0x0800FC00`.
The full page is erased and rewritten atomically when `EOT` is received.

```
0x0800FC00  ┌──────────────────────┐   4 B   Magic pattern {0xF0, 0x0F, 0xDE, 0xAD}
0x0800FC04  ├──────────────────────┤  32 B   Private key  (SECP256R1 scalar)
0x0800FC24  ├──────────────────────┤  64 B   Public key   (SECP256R1 x‖y uncompressed)
0x0800FC64  ├──────────────────────┤  32 B   Runtime configuration (8 × uint32_t LE)
0x0800FC84  ├──────────────────────┤
            │   (unused — 892 B)   │
0x0800FFFF  └──────────────────────┘
```

