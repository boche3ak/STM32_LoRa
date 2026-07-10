#!/usr/bin/env python3
"""
fof_prov.py — FoF STM32 field provisioning tool (Raspberry Pi peer)

Sends a private key, a public key, and/or a configuration update to the
STM32 LoRa device via USART1 using the FoF provisioning protocol.

Hardware connections (Raspberry Pi  →  STM32 Blue Pill):
  GPIO14 / pin 8  (UART TX)  →  PA10  (USART1_RX)
  GPIO15 / pin 10 (UART RX)  ←  PA9   (USART1_TX)
  GND    / pin 6              ↔  GND

Enable UART on the Pi:
  sudo raspi-config → Interface Options → Serial Port
    - Login shell over serial: No
    - Serial port hardware: Yes
  → /dev/ttyAMA0 (or /dev/serial0) becomes the provisioning port.

Dependencies:
  pip3 install pyserial
  pip3 install cryptography   # optional — only needed for PEM key files

Supported key file formats:
  raw binary  — 32 B (private key) or 64 B (public key)
  hex text    — 64 or 128 hex chars in a .txt file (colons / spaces ignored)
  PEM         — requires the 'cryptography' package

Usage:
  python3 fof_prov.py --help
"""

import sys
import time
import struct
import textwrap
import argparse
import logging
from pathlib import Path
from typing import Optional, Tuple, List

try:
    import serial
except ImportError:
    sys.exit("pyserial is not installed.  Run:  pip3 install pyserial")


# ─── Protocol constants ───────────────────────────────────────────────────────

PROV_READY  = 0xAA   # device  → peer  : ready for next packet
PROV_ACK    = 0x06   # device  → peer  : packet accepted (ASCII ACK)
PROV_NAK    = 0x15   # device  → peer  : CRC error — retransmit (ASCII NAK)
PROV_EOT    = 0x04   # peer    → device: end of transmission (ASCII EOT)
PROV_SOF    = 0x55   # peer    → device: start-of-frame byte

PKT_PRIVKEY = 0xB1   # SECP256R1 private key scalar,  32 bytes
PKT_PUBKEY  = 0xB2   # SECP256R1 public key (x‖y),   64 bytes
PKT_CONFIG  = 0xB3   # runtime config, 4 × uint32_t LE, 16 bytes

PRIVKEY_LEN = 32
PUBKEY_LEN  = 64
CONFIG_LEN  = 16     # 4 × uint32_t

# Config field order matches NVRAM layout (see README § NVRAM flash layout)
CONFIG_FIELDS: List[Tuple[str, int]] = [
    ("TxTimeoutMs",              500),
    ("MainCycleDelayUs",        2000),
    ("ResponseDelayToleranceMs", 500),
    ("WatchdogTimeoutMs",       1000),
]


# ─── ANSI colour helpers ──────────────────────────────────────────────────────

_COLOR = sys.stdout.isatty()

def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s

def green(s: str)  -> str: return _c("92", s)
def yellow(s: str) -> str: return _c("93", s)
def red(s: str)    -> str: return _c("91", s)
def cyan(s: str)   -> str: return _c("96", s)
def bold(s: str)   -> str: return _c("1",  s)


# ─── CRC-16/CCITT ─────────────────────────────────────────────────────────────

def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT — poly 0x1021, init 0xFFFF, no input/output reflection."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1) & 0xFFFF
    return crc


# ─── Packet construction ──────────────────────────────────────────────────────

def build_packet(pkt_type: int, payload: bytes) -> bytes:
    """Return a complete wire packet: SOF | TYPE | LEN | PAYLOAD | CRC_HI | CRC_LO."""
    frame = bytes([PROV_SOF, pkt_type, len(payload)]) + payload
    crc   = crc16_ccitt(frame)
    return frame + bytes([crc >> 8, crc & 0xFF])


# ─── Key / config loading ─────────────────────────────────────────────────────

def load_key(path: str, expected_len: int) -> bytes:
    """
    Load raw key bytes from *path*.  Tried in order:
      1. PEM  (requires the `cryptography` package)
      2. Hex text  (stripped of whitespace and colons)
      3. Raw binary
    Raises ValueError / RuntimeError on failure.
    """
    data = Path(path).read_bytes()

    # ── PEM ──────────────────────────────────────────────────────────────────
    if data.lstrip().startswith(b"-----"):
        try:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key, load_pem_public_key,
            )
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePrivateKey, EllipticCurvePublicKey,
            )
        except ImportError:
            raise RuntimeError(
                "PEM file detected but 'cryptography' is not installed.\n"
                "  pip3 install cryptography\n"
                "Or convert the key to raw binary / hex first."
            )

        if expected_len == PRIVKEY_LEN:
            try:
                key = load_pem_private_key(data, password=None)
                if isinstance(key, EllipticCurvePrivateKey):
                    return key.private_numbers().private_value.to_bytes(32, "big")
            except Exception as exc:
                raise ValueError(f"Cannot parse PEM private key: {exc}") from exc

        if expected_len == PUBKEY_LEN:
            try:
                key = load_pem_public_key(data)
                if isinstance(key, EllipticCurvePublicKey):
                    n = key.public_numbers()
                    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")
            except Exception as exc:
                raise ValueError(f"Cannot parse PEM public key: {exc}") from exc

        raise ValueError("PEM file does not match expected EC key type.")

    # ── Hex text ──────────────────────────────────────────────────────────────
    try:
        hex_str = data.decode("ascii", errors="ignore")
        hex_str = "".join(c for c in hex_str if c in "0123456789abcdefABCDEF")
        if len(hex_str) == expected_len * 2:
            return bytes.fromhex(hex_str)
    except Exception:
        pass

    # ── Raw binary ────────────────────────────────────────────────────────────
    if len(data) == expected_len:
        return data

    raise ValueError(
        f"File '{path}': expected {expected_len} bytes, "
        f"got {len(data)} — not valid raw binary, hex text, or PEM."
    )


def build_config(args: argparse.Namespace) -> bytes:
    """Pack the four config fields into 16 bytes (little-endian uint32_t × 4)."""
    defaults = dict(CONFIG_FIELDS)
    vals = [
        args.tx_timeout    if args.tx_timeout    is not None else defaults["TxTimeoutMs"],
        args.main_delay    if args.main_delay     is not None else defaults["MainCycleDelayUs"],
        args.rtt_tolerance if args.rtt_tolerance  is not None else defaults["ResponseDelayToleranceMs"],
        args.watchdog      if args.watchdog        is not None else defaults["WatchdogTimeoutMs"],
    ]
    return struct.pack("<4I", *vals)


# ─── Hex dump ─────────────────────────────────────────────────────────────────

def hex_dump(label: str, data: bytes, cols: int = 16) -> None:
    print(f"   {label}  ({len(data)} B):")
    for i in range(0, len(data), cols):
        chunk    = data[i:i + cols]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        print(f"     {i:04x}  {hex_part:<{cols * 3}} {asc_part}")


# ─── Provisioning session ─────────────────────────────────────────────────────

class ProvSession:
    """
    Manages one provisioning session against the STM32 device.

    Protocol flow (this class is the "counterpart"):
      1. wait_for_ready()          — waits for 0xAA from device
      2. send_packet() × N         — each sends SOF|TYPE|LEN|PAYLOAD|CRC,
                                     retries on NAK, aborts on timeout
      3. send_eot()                — sends 0x04, waits for final ACK
    """

    def __init__(self, port: serial.Serial, *,
                 max_retries: int = 3,
                 interactive: bool = False,
                 dry_run: bool = False,
                 byte_timeout: float = 5.0,
                 verbose: bool = False):
        self.port         = port
        self.max_retries  = max_retries
        self.interactive  = interactive
        self.dry_run      = dry_run
        self.byte_timeout = byte_timeout
        self.verbose      = verbose
        self._sent  = 0
        self._acked = 0

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        print(f"  [{ts}]  {msg}")

    # ── Low-level I/O ─────────────────────────────────────────────────────────

    def _recv(self, timeout: float) -> Optional[int]:
        """Read one byte within *timeout* seconds.  Returns None on timeout."""
        self.port.timeout = timeout
        b = self.port.read(1)
        return b[0] if b else None

    # ── Phase 1 — wait for READY ──────────────────────────────────────────────

    def wait_for_ready(self, timeout: float = 8.0) -> bool:
        """
        Block until the device sends READY (0xAA).
        The device sends up to 3 × READY at 2-second intervals on power-up.
        Returns False if no READY arrives within *timeout* seconds.
        """
        print(f"\n{cyan(bold('◈  Waiting for READY from device…'))}")
        print(f"   Port {self.port.name}  │  {self.port.baudrate} baud  │  8N1")
        print(f"   (device sends up to 3 READY pulses, 2 s apart, on power-up)\n")

        deadline = time.monotonic() + timeout
        spinner  = 0
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            b = self._recv(timeout=min(0.5, remaining))
            if b is None:
                spinner += 1
                print(f"   {'.' * (spinner % 6 + 1):<7}", end="\r", flush=True)
                continue
            if b == PROV_READY:
                print()
                self._log(green(f"READY received  (0x{b:02X})"))
                return True
            logging.debug("ignored byte 0x%02X while waiting for READY", b)

        print()
        self._log(red(f"Timeout — no READY signal within {timeout:.0f} s"))
        return False

    # ── Phase 2 — send a packet ───────────────────────────────────────────────

    def send_packet(self, pkt_type: int, payload: bytes, label: str) -> bool:
        """
        Transmit *payload* as a packet of *pkt_type* and collect ACK.
        Returns True on success, False on unrecoverable failure.
        In interactive mode the user may skip a packet (returns True) or abort
        the whole session (returns False).
        """
        TYPE_NAMES = {PKT_PRIVKEY: "PRIVKEY/0xB1",
                      PKT_PUBKEY:  "PUBKEY/0xB2",
                      PKT_CONFIG:  "CONFIG/0xB3"}
        tname  = TYPE_NAMES.get(pkt_type, f"0x{pkt_type:02X}")
        packet = build_packet(pkt_type, payload)

        print(f"\n{bold('▸  ' + label)}")
        print(f"   type={tname}  payload={len(payload)} B  wire={len(packet)} B")

        if self.verbose:
            hex_dump("Payload", payload)
            hex_dump("Packet ", packet)

        if self.interactive:
            choice = input("   Send? [Y / n=abort / s=skip]  ").strip().lower()
            if choice in ("n", "q"):
                self._log(yellow("Aborted by user."))
                return False
            if choice == "s":
                self._log(yellow("Skipped."))
                return True   # skip is not an error

        if self.dry_run:
            self._log(yellow("[DRY RUN] packet built but not transmitted."))
            return True

        for attempt in range(1, self.max_retries + 1):
            if attempt > 1:
                self._log(yellow(f"Retry {attempt}/{self.max_retries}…"))

            self.port.write(packet)
            self.port.flush()
            self._sent += 1

            resp = self._recv(timeout=self.byte_timeout)

            if resp is None:
                self._log(red(f"Timeout waiting for ACK/NAK  (attempt {attempt})"))
                if self.interactive and attempt < self.max_retries:
                    if input("   Retry? [Y/n]  ").strip().lower() == "n":
                        return False
                continue

            if resp == PROV_ACK:
                self._log(green("ACK  ✓  packet accepted"))
                self._acked += 1
                return True

            if resp == PROV_NAK:
                self._log(yellow("NAK  ✗  CRC mismatch on device — retransmitting"))
                if self.interactive and attempt < self.max_retries:
                    if input("   Retry? [Y/n]  ").strip().lower() == "n":
                        return False
                continue

            self._log(yellow(f"Unexpected response 0x{resp:02X} — retrying"))

        self._log(red(f"Giving up after {self.max_retries} attempts."))
        return False

    # ── Phase 3 — end of transmission ─────────────────────────────────────────

    def send_eot(self) -> bool:
        """
        Send EOT (0x04) and wait for the final ACK from the device.
        The device will erase and rewrite the NVRAM flash page after ACK.
        """
        print(f"\n{bold('▸  EOT')}  (end of transmission)")

        if self.dry_run:
            self._log(yellow("[DRY RUN] EOT not transmitted."))
            return True

        self.port.write(bytes([PROV_EOT]))
        self.port.flush()

        resp = self._recv(timeout=self.byte_timeout)
        if resp == PROV_ACK:
            self._log(green("ACK  ✓  device writing flash…"))
            # Allow time for flash erase + reprogram (512 half-words × HAL overhead)
            time.sleep(0.8)
            return True

        got = f"0x{resp:02X}" if resp is not None else "timeout"
        self._log(red(f"No ACK for EOT (got {got})"))
        return False

    # ── Summary ───────────────────────────────────────────────────────────────

    def print_summary(self, success: bool) -> None:
        sep = "─" * 46
        print(f"\n{sep}")
        print(bold("  Session summary"))
        print(f"  Packets sent    :  {self._sent}")
        print(f"  Packets ACKed   :  {self._acked}")
        result = green("SUCCESS — flash updated") if success else red("FAILED")
        print(f"  Result          :  {result}")
        print(sep)


# ─── Argument parser ──────────────────────────────────────────────────────────

def make_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="fof_prov.py",
        description="FoF STM32 field provisioning tool — Raspberry Pi peer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        key-file formats:
          raw binary  — 32 B (private key) or 64 B (public key)
          hex text    — 64 or 128 hex digits in a .txt file (colons/spaces ignored)
          PEM         — requires:  pip3 install cryptography

        examples:
          # provision all three packets
          %(prog)s --port /dev/ttyAMA0 \\
              --private-key priv.bin --public-key pub.bin \\
              --tx-timeout 500 --main-delay 2000

          # update only the private key
          %(prog)s --port /dev/ttyAMA0 --private-key priv.bin

          # update config only, confirm each step interactively
          %(prog)s --port /dev/ttyAMA0 --tx-timeout 1000 --watchdog 2000 --interactive

          # inspect packet bytes without transmitting anything
          %(prog)s --port /dev/ttyAMA0 --public-key pub.hex --dry-run -v
        """),
    )

    g = ap.add_argument_group("serial port")
    g.add_argument("--port", default="/dev/ttyAMA0",
                   help="UART device  (default: /dev/ttyAMA0)")
    g.add_argument("--baud", type=int, default=9600,
                   help="baud rate  (default: 9600)")

    g = ap.add_argument_group("key packets")
    g.add_argument("--private-key", metavar="FILE",
                   help="private key — 32-byte SECP256R1 scalar")
    g.add_argument("--public-key", metavar="FILE",
                   help="public key  — 64-byte uncompressed SECP256R1 point (x‖y)")

    g = ap.add_argument_group("config packet  (sent when any flag is provided)")
    g.add_argument("--tx-timeout",    type=int, metavar="MS",
                   help="Cfg_TxTimeoutMs                (default: 500)")
    g.add_argument("--main-delay",    type=int, metavar="US",
                   help="Cfg_MainCycleDelayUs            (default: 2000)")
    g.add_argument("--rtt-tolerance", type=int, metavar="MS",
                   help="Cfg_ResponseDelayToleranceMs   (default: 500)")
    g.add_argument("--watchdog",      type=int, metavar="MS",
                   help="Cfg_WatchdogTimeoutMs           (default: 1000)")

    g = ap.add_argument_group("behaviour")
    g.add_argument("--interactive", action="store_true",
                   help="prompt before each packet; allow skip / abort / retry")
    g.add_argument("--dry-run", action="store_true",
                   help="build packets and print them — do not open the serial port")
    g.add_argument("--max-retries", type=int, default=3, metavar="N",
                   help="max NAK retries per packet  (default: 3)")
    g.add_argument("--wait", type=float, default=8.0, metavar="SECS",
                   help="seconds to wait for device READY  (default: 8)")
    g.add_argument("--byte-timeout", type=float, default=5.0, metavar="SECS",
                   help="per-byte receive timeout  (default: 5)")
    g.add_argument("-v", "--verbose", action="store_true",
                   help="show hex dumps of all packets")

    return ap


# ─── Entry point ─────────────────────────────────────────────────────────────

def main() -> int:
    ap   = make_parser()
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(message)s")

    # ── Collect packets to send ───────────────────────────────────────────────
    packets: List[Tuple[int, bytes, str]] = []   # (type, payload, label)
    load_errors: List[str] = []

    if args.private_key:
        try:
            raw = load_key(args.private_key, PRIVKEY_LEN)
            packets.append((PKT_PRIVKEY, raw, "Private Key  (PRIVKEY 0xB1)"))
        except Exception as exc:
            load_errors.append(f"--private-key: {exc}")

    if args.public_key:
        try:
            raw = load_key(args.public_key, PUBKEY_LEN)
            packets.append((PKT_PUBKEY, raw, "Public Key   (PUBKEY 0xB2)"))
        except Exception as exc:
            load_errors.append(f"--public-key: {exc}")

    config_args = (args.tx_timeout, args.main_delay, args.rtt_tolerance, args.watchdog)
    if any(v is not None for v in config_args):
        payload = build_config(args)
        vals = struct.unpack("<4I", payload)
        label = (
            f"Config       (CONFIG 0xB3)\n"
            f"   TxTimeoutMs={vals[0]}  MainCycleDelayUs={vals[1]}"
            f"  RttTolerance={vals[2]}  WatchdogTimeout={vals[3]}"
        )
        packets.append((PKT_CONFIG, payload, label))

    if load_errors:
        for err in load_errors:
            print(red(f"Error: {err}"))
        return 1

    if not packets:
        print(yellow("Nothing to send."))
        print("Specify at least one of: --private-key  --public-key  --tx-timeout"
              "  --main-delay  --rtt-tolerance  --watchdog")
        ap.print_usage()
        return 1

    # ── Print plan ────────────────────────────────────────────────────────────
    print(bold(f"\nFoF provisioning  —  {len(packets)} packet(s) scheduled:"))
    for i, (_, payload, label) in enumerate(packets, 1):
        first_line = label.split("\n")[0]
        print(f"  {i}. {first_line}  ({len(payload)} B payload)")

    # ── Open serial port ──────────────────────────────────────────────────────
    if args.dry_run:
        ser = None
        print(yellow("\n[DRY RUN] serial port will not be opened."))
    else:
        try:
            ser = serial.Serial(
                port=args.port,
                baudrate=args.baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=args.byte_timeout,
            )
            ser.reset_input_buffer()
            ser.reset_output_buffer()
        except serial.SerialException as exc:
            print(red(f"\nCannot open {args.port}: {exc}"))
            return 1

    # ── Run session ───────────────────────────────────────────────────────────
    sess = ProvSession(
        port=ser,
        max_retries=args.max_retries,
        interactive=args.interactive,
        dry_run=args.dry_run,
        byte_timeout=args.byte_timeout,
        verbose=args.verbose,
    )

    success = True

    if not args.dry_run:
        if not sess.wait_for_ready(timeout=args.wait):
            sess.print_summary(success=False)
            if ser:
                ser.close()
            return 1

    for pkt_type, payload, label in packets:
        if not sess.send_packet(pkt_type, payload, label):
            success = False
            if not args.interactive:
                break   # non-interactive: abort on first failure

    if success:
        success = sess.send_eot()

    if ser:
        ser.close()

    sess.print_summary(success)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
