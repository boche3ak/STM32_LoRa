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

PA8 is not part of the UART link — it is the WHOAMI selector pin (Challenger vs Transponder).

### When provisioning runs

On every power-on the device sends a READY signal up to three times with a 2-second
timeout each (6 seconds total). If a counterpart responds, provisioning begins. If not,
the device proceeds normally with whatever keys are already stored in flash.

The counterpart may send any subset of the three packets (private key, public key,
configuration) in any order, or none at all. Only the packets that are received and
verified are written to flash; the rest of the NVRAM page is preserved unchanged.

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

| Byte | Value | Sender | Meaning |
|------|-------|--------|---------|
| READY | `0xAA` | device | Ready to receive next packet |
| ACK   | `0x06` | device | Packet accepted (ASCII ACK) |
| NAK   | `0x15` | device | Packet rejected — retransmit (ASCII NAK) |
| EOT   | `0x04` | counterpart | No more packets (ASCII EOT) |

#### Packet frame

```
┌────────┬────────┬────────┬─────────────────┬──────────┬──────────┐
│ SOF    │ TYPE   │ LEN    │ PAYLOAD         │ CRC_HI   │ CRC_LO   │
│ 0x55   │ 1 byte │ 1 byte │ LEN bytes       │          │          │
└────────┴────────┴────────┴─────────────────┴──────────┴──────────┘
```

- **SOF** `0x55` — start-of-frame sync byte (alternating-bit pattern).
- **TYPE** — identifies the payload:

  | Type | Value | Payload | Size |
  |------|-------|---------|------|
  | Private key  | `0xB1` | SECP256R1 scalar (raw bytes) | 32 B |
  | Public key   | `0xB2` | SECP256R1 uncompressed point x\|\|y | 64 B |
  | Configuration | `0xB3` | 4 × `uint32_t` little-endian (see below) | 16 B |

- **LEN** — payload byte count (fixed per type; receiver validates).
- **CRC** — CRC-16/CCITT, polynomial `0x1021`, initial value `0xFFFF`, no
  reflection, computed over `SOF || TYPE || LEN || PAYLOAD`, transmitted
  big-endian (high byte first).

#### Configuration payload layout

| Offset | Field | Default |
|--------|-------|---------|
| 0 | `TxTimeoutMs` — LoRa transmit timeout | 500 |
| 4 | `MainCycleDelayUs` — main loop period | 2000 |
| 8 | `ResponseDelayToleranceMs` — max acceptable RTT | 500 |
| 12 | `WatchdogTimeoutMs` — IWDG timeout | 1000 |

All values are `uint32_t` in little-endian byte order (native STM32 storage format).

#### Session flow

```
Device                              Counterpart
  │                                     │
  │─── READY (0xAA) ──────────────────>│  "I am ready to receive"
  │                                     │
  │<── SOF | TYPE | LEN | PAYLOAD | CRC─│  packet (e.g. private key)
  │    [verify CRC]                     │
  │─── ACK (0x06) ────────────────────>│  accepted — send next
  │                                     │
  │<── SOF | TYPE | LEN | PAYLOAD | CRC─│  packet (e.g. public key)
  │    [verify CRC — bad]               │
  │─── NAK (0x15) ────────────────────>│  rejected — retransmit
  │                                     │
  │<── SOF | TYPE | LEN | PAYLOAD | CRC─│  same packet retransmitted
  │    [verify CRC — OK]                │
  │─── ACK (0x06) ────────────────────>│
  │                                     │
  │<── EOT (0x04) ─────────────────────│  no more packets
  │─── ACK (0x06) ────────────────────>│
  │    [erase NVRAM page, rewrite]      │
  │    [LED steady ON → 3 s → OFF]      │
```

Key rules for the counterpart implementation:

1. Wait for READY before sending the first packet.
2. After sending a packet, wait for ACK or NAK before proceeding.
3. On NAK, retransmit the same packet. The device does not limit retries —
   the counterpart is responsible for deciding when to give up.
4. After the last packet (or if there is nothing to send), send EOT and
   wait for ACK.
5. The counterpart may send any combination of the three packet types. Packets
   not sent leave the corresponding NVRAM section unchanged.

#### Packet sizes on wire

| Packet | Bytes | Time at 9600 baud |
|--------|-------|-------------------|
| Private key  | 37 | ≈ 38 ms |
| Public key   | 69 | ≈ 72 ms |
| Configuration | 21 | ≈ 22 ms |

### NVRAM flash layout

All provisioned data shares a single 1 KB flash page at `0x0800FC00`.
The full page is erased and rewritten atomically on each successful session.

```
0x0800FC00  ┌──────────────────────┐  4 B   Magic pattern {0xF0,0x0F,0xDE,0xAD}
0x0800FC04  ├──────────────────────┤  32 B  FoF private key     (PROV_TYPE_PRIVKEY)
0x0800FC24  ├──────────────────────┤  64 B  FoF remote public key (PROV_TYPE_PUBKEY)
0x0800FC64  ├──────────────────────┤  16 B  Runtime configuration (PROV_TYPE_CONFIG)
0x0800FC74  ├──────────────────────┤
            │   (unused)           │
0x0800FFFF  └──────────────────────┘
```

