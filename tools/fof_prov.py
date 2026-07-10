#!/usr/bin/env python3
"""
fof_prov.py — FoF STM32 Field Provisioning Tool

Interactive TUI (and non-interactive CLI) for provisioning the STM32 LoRa
device via USART1: send private key, public key, configuration data, and
optionally read back the current configuration.

Hardware connections (Raspberry Pi  →  STM32 Blue Pill):
  GPIO14 / pin 8  (UART TX)  →  PA10  (USART1_RX)
  GPIO15 / pin 10 (UART RX)  ←  PA9   (USART1_TX)
  GND    / pin 6              ↔  GND

Enable UART on the Pi:
  sudo raspi-config → Interface Options → Serial Port
    Login shell over serial:  No
    Serial port hardware:     Yes

Dependencies:
  pip3 install pyserial
  pip3 install cryptography   # optional — required only for PEM key files
                              # also required for key generation (--generate)

Supported key-file formats (for --private-key / --public-key):
  raw binary  — 32 B (private) or 64 B (public)
  hex text    — 64 or 128 hex chars in a text file (colons/spaces ignored)
  PEM         — requires 'cryptography' package
"""

import sys
import os
import json
import copy
import time
import struct
import textwrap
import argparse
import logging
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any

try:
    import serial
except ImportError:
    sys.exit("pyserial not installed.  Run:  pip3 install pyserial")


# ── Protocol constants ────────────────────────────────────────────────────────

PROV_READY   = 0xAA   # device  → peer  : ready for next packet
PROV_ACK     = 0x06   # device  → peer  : packet accepted
PROV_NAK     = 0x15   # device  → peer  : CRC error — retransmit
PROV_RJCT    = 0xFF   # device  → peer  : request not supported
PROV_EOT     = 0x04   # peer    → device: end of transmission

PROV_SOF         = 0x55   # packet start-of-frame byte
PKT_PRIVKEY      = 0xB1   # SECP256R1 private key scalar   (32 B)
PKT_PUBKEY       = 0xB2   # SECP256R1 public key  x‖y     (64 B)
PKT_CONFIG       = 0xB3   # runtime config  6 × uint32_t   (24 B)
PKT_GET_CONFIG   = 0xB4   # query: read back device config  (0 B payload)

PRIVKEY_LEN = 32
PUBKEY_LEN  = 64
CONFIG_LEN  = 24    # 6 × uint32_t


# ── Config field definitions (order matches NVRAM layout) ────────────────────

CONFIG_FIELDS: List[Tuple[str, str, int]] = [
    ("TxTimeoutMs",              "LoRa transmit timeout",                 500),
    ("TransponderMainCycleMs",   "Transponder poll rate",                   2),
    ("ChallengerMainCycleMs",    "Challenger poll rate",                 1000),
    ("ResponseWaitCycleDelayMs", "Challenger wait per cycle for response",  10),
    ("ResponseDelayToleranceMs", "Max acceptable challenge-response RTT",  500),
    ("WatchdogTimeoutMs",        "Watchdog timeout",                      1000),
]

def _default_config() -> Dict[str, int]:
    return {f[0]: f[2] for f in CONFIG_FIELDS}

def _pack_config(cfg: Dict[str, int]) -> bytes:
    return struct.pack("<6I", *[cfg.get(f[0], f[2]) for f in CONFIG_FIELDS])

def _unpack_config(data: bytes) -> Dict[str, int]:
    vals = struct.unpack("<6I", data)
    return {f[0]: v for f, v in zip(CONFIG_FIELDS, vals)}


# ── ANSI colour helpers ───────────────────────────────────────────────────────

_COLOR = sys.stdout.isatty()

def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s

def green(s: str)  -> str: return _c("92", s)
def yellow(s: str) -> str: return _c("93", s)
def red(s: str)    -> str: return _c("91", s)
def cyan(s: str)   -> str: return _c("96", s)
def bold(s: str)   -> str: return _c("1",  s)
def dim(s: str)    -> str: return _c("2",  s)


# ── CRC-16/CCITT ─────────────────────────────────────────────────────────────

def crc16_ccitt(data: bytes) -> int:
    """poly 0x1021, init 0xFFFF, no reflection — matches device implementation."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1) & 0xFFFF
    return crc


# ── Packet construction / parsing ─────────────────────────────────────────────

def build_packet(pkt_type: int, payload: bytes) -> bytes:
    """SOF | TYPE | LEN | PAYLOAD | CRC_HI | CRC_LO"""
    frame = bytes([PROV_SOF, pkt_type, len(payload)]) + payload
    crc   = crc16_ccitt(frame)
    return frame + bytes([crc >> 8, crc & 0xFF])

def parse_packet(raw: bytes) -> Optional[Tuple[int, bytes]]:
    """Parse a complete received packet. Returns (type, payload) or None."""
    if len(raw) < 5 or raw[0] != PROV_SOF:
        return None
    pkt_len = raw[2]
    if len(raw) != 3 + pkt_len + 2:
        return None
    rx_crc = (raw[-2] << 8) | raw[-1]
    if rx_crc != crc16_ccitt(raw[:-2]):
        return None
    return raw[1], bytes(raw[3:3 + pkt_len])


# ── Key loading ───────────────────────────────────────────────────────────────

def load_key(path: str, expected_len: int) -> bytes:
    """
    Load raw key bytes.  Tried in order:
      1. PEM  (requires 'cryptography')
      2. Hex text  (64 or 128 hex chars, colons/spaces stripped)
      3. Raw binary
    """
    data = Path(path).read_bytes()

    if data.lstrip().startswith(b"-----"):
        try:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key, load_pem_public_key)
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePrivateKey, EllipticCurvePublicKey)
        except ImportError:
            raise RuntimeError(
                "PEM file requires 'cryptography'.  Run:  pip3 install cryptography")
        if expected_len == PRIVKEY_LEN:
            key = load_pem_private_key(data, password=None)
            if not isinstance(key, EllipticCurvePrivateKey):
                raise ValueError("Not an EC private key")
            return key.private_numbers().private_value.to_bytes(32, "big")
        key = load_pem_public_key(data)
        if not isinstance(key, EllipticCurvePublicKey):
            raise ValueError("Not an EC public key")
        n = key.public_numbers()
        return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")

    hex_str = "".join(c for c in data.decode("ascii", errors="ignore")
                      if c in "0123456789abcdefABCDEF")
    if len(hex_str) == expected_len * 2:
        return bytes.fromhex(hex_str)

    if len(data) == expected_len:
        return data

    raise ValueError(
        f"Expected {expected_len} bytes; got {len(data)}.  "
        "File must be raw binary, hex text, or PEM.")


# ── Key generation ────────────────────────────────────────────────────────────

def generate_keypair(out_dir: Path) -> Tuple[bytes, bytes]:
    """Generate a SECP256R1 keypair and save raw bytes to out_dir.
    Returns (private_bytes, public_bytes).
    Requires 'cryptography'.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            generate_private_key, SECP256R1)
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        raise RuntimeError(
            "Key generation requires 'cryptography'.  Run:  pip3 install cryptography")

    priv_key  = generate_private_key(SECP256R1(), default_backend())
    priv_nums = priv_key.private_numbers()
    pub_nums  = priv_key.public_key().public_numbers()

    priv_bytes = priv_nums.private_value.to_bytes(32, "big")
    pub_bytes  = (pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big"))

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "private.bin").write_bytes(priv_bytes)
    (out_dir / "public.bin").write_bytes(pub_bytes)
    return priv_bytes, pub_bytes


# ── Settings (JSON persistence) ───────────────────────────────────────────────

_CFG_FILE = Path(__file__).with_name(".fof_prov.cfg")

class Settings:
    _DEFAULTS: Dict[str, Any] = {
        "port":         "/dev/serial0",
        "baud":         9600,
        "max_retries":  3,
        "wait_timeout": 30.0,
        "byte_timeout": 5.0,
        "key_dir":      "keys",
        "verbose":      False,
        "config":       {f[0]: f[2] for f in CONFIG_FIELDS},
    }

    def __init__(self) -> None:
        self._data: Dict[str, Any] = copy.deepcopy(self._DEFAULTS)
        try:
            if _CFG_FILE.exists():
                loaded = json.loads(_CFG_FILE.read_text())
                # Deep-merge: top-level keys
                self._data.update(loaded)
                # Deep-merge: config sub-dict
                merged_cfg = copy.deepcopy(self._DEFAULTS["config"])
                merged_cfg.update(loaded.get("config", {}))
                self._data["config"] = merged_cfg
        except Exception:
            pass

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._data[key] = value
        self._save()

    def _save(self) -> None:
        try:
            _CFG_FILE.write_text(json.dumps(self._data, indent=2))
        except Exception:
            pass

    def privkey_path(self) -> Path:
        return Path(self["key_dir"]) / "private.bin"

    def pubkey_path(self) -> Path:
        return Path(self["key_dir"]) / "public.bin"

    def key_dir_path(self) -> Path:
        return Path(self["key_dir"])


# ── Provisioning session ──────────────────────────────────────────────────────

class ProvSession:
    def __init__(self, port: serial.Serial, *,
                 max_retries: int = 3,
                 byte_timeout: float = 5.0,
                 verbose: bool = False):
        self.port         = port
        self.max_retries  = max_retries
        self.byte_timeout = byte_timeout
        self.verbose      = verbose
        self._sent  = 0
        self._acked = 0

    def _log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        print(f"  [{ts}]  {msg}")

    def _recv(self, timeout: float) -> Optional[int]:
        self.port.timeout = timeout
        b = self.port.read(1)
        return b[0] if b else None

    # ── Phase 1 ───────────────────────────────────────────────────────────────

    def wait_for_ready(self, timeout: float = 8.0) -> bool:
        print(f"\n  {cyan('Waiting for device READY…')}")
        deadline = time.monotonic() + timeout
        dots = 0
        while time.monotonic() < deadline:
            b = self._recv(timeout=min(0.5, deadline - time.monotonic()))
            if b is None:
                dots += 1
                print(f"  {'.' * (dots % 6 + 1):<7}", end="\r", flush=True)
                continue
            if b == PROV_READY:
                print()
                self._log(green(f"READY  (0x{b:02X})"))
                return True
        print()
        self._log(red("Timeout — no READY signal from device"))
        return False

    # ── Phase 2 — write packet ────────────────────────────────────────────────

    def send_packet(self, pkt_type: int, payload: bytes, label: str) -> bool:
        TYPE_STR = {PKT_PRIVKEY: "PRIVKEY/0xB1",
                    PKT_PUBKEY:  "PUBKEY/0xB2",
                    PKT_CONFIG:  "CONFIG/0xB3"}
        packet = build_packet(pkt_type, payload)
        print(f"\n  {bold('▸  ' + label)}")
        print(f"     type={TYPE_STR.get(pkt_type, hex(pkt_type))}"
              f"  payload={len(payload)} B  wire={len(packet)} B")
        if self.verbose:
            _hex_dump("Payload", payload)
            _hex_dump("Packet ", packet)

        for attempt in range(1, self.max_retries + 1):
            if attempt > 1:
                self._log(yellow(f"Retry {attempt}/{self.max_retries}…"))
            self.port.write(packet)
            self.port.flush()
            self._sent += 1

            resp = self._recv(timeout=self.byte_timeout)
            if resp is None:
                self._log(red(f"Timeout waiting for ACK/NAK  (attempt {attempt})"))
                continue
            if resp == PROV_ACK:
                self._log(green("ACK  ✓"))
                self._acked += 1
                return True
            if resp == PROV_NAK:
                self._log(yellow("NAK  ✗  CRC mismatch — retransmitting"))
                continue
            self._log(yellow(f"Unexpected response 0x{resp:02X} — retrying"))

        self._log(red(f"Giving up after {self.max_retries} attempts."))
        return False

    # ── Phase 2 — read config (GET_CONFIG) ───────────────────────────────────

    def _recv_packet_from_sof(self) -> Optional[Tuple[int, bytes]]:
        """Read TYPE+LEN+PAYLOAD+CRC after SOF has already been consumed."""
        frame = bytearray([PROV_SOF])
        for _ in range(2):           # TYPE, LEN
            b = self._recv(self.byte_timeout)
            if b is None:
                return None
            frame.append(b)
        pkt_len = frame[2]
        for _ in range(pkt_len):     # PAYLOAD
            b = self._recv(self.byte_timeout)
            if b is None:
                return None
            frame.append(b)
        for _ in range(2):           # CRC HI, LO
            b = self._recv(self.byte_timeout)
            if b is None:
                return None
            frame.append(b)
        return parse_packet(bytes(frame))

    def get_config(self) -> Optional[Dict[str, int]]:
        """
        Send a GET_CONFIG request and return the device config dict.
        Returns None on error or if the device does not support the command.
        """
        packet = build_packet(PKT_GET_CONFIG, b"")
        print(f"\n  {bold('▸  GET_CONFIG request')}")
        if self.verbose:
            _hex_dump("Packet", packet)

        self.port.write(packet)
        self.port.flush()

        resp = self._recv(timeout=self.byte_timeout)
        if resp is None:
            self._log(red("Timeout — no response from device"))
            return None

        if resp in (PROV_RJCT, PROV_NAK):
            print(f"\n  {red('✗')}  This device doesn't support reading out the configuration.")
            return None

        if resp == PROV_SOF:
            result = self._recv_packet_from_sof()
            if result is None:
                self._log(red("Timeout reading response packet"))
                return None
            pkt_type, payload = result
            if pkt_type != PKT_CONFIG or len(payload) != CONFIG_LEN:
                self._log(red(f"Unexpected response: type=0x{pkt_type:02X} len={len(payload)}"))
                return None
            self._log(green("Configuration received  ✓"))
            return _unpack_config(payload)

        self._log(yellow(f"Unexpected response 0x{resp:02X}"))
        return None

    # ── Phase 3 ───────────────────────────────────────────────────────────────

    def send_eot(self) -> bool:
        print(f"\n  {bold('▸  EOT')}  (end of transmission)")
        self.port.write(bytes([PROV_EOT]))
        self.port.flush()
        resp = self._recv(timeout=self.byte_timeout)
        if resp == PROV_ACK:
            self._log(green("ACK  ✓  device writing flash…"))
            time.sleep(0.8)
            return True
        got = f"0x{resp:02X}" if resp is not None else "timeout"
        self._log(red(f"No ACK for EOT (got {got})"))
        return False

    def print_summary(self, success: bool) -> None:
        sep = "─" * 46
        print(f"\n{sep}")
        print(bold("  Summary"))
        print(f"  Packets sent   :  {self._sent}")
        print(f"  Packets ACKed  :  {self._acked}")
        print(f"  Result         :  "
              + (green("SUCCESS — flash updated") if success else red("FAILED")))
        print(sep)


# ── Hex dump ──────────────────────────────────────────────────────────────────

def _hex_dump(label: str, data: bytes, cols: int = 16) -> None:
    print(f"   {label}  ({len(data)} B):")
    for i in range(0, len(data), cols):
        chunk    = data[i:i + cols]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        print(f"     {i:04x}  {hex_part:<{cols * 3}} {asc_part}")


# ── Port helpers ──────────────────────────────────────────────────────────────

def _resolve_port(port: str) -> str:
    try:
        p = Path(port)
        if p.is_symlink():
            return f"{port} ({p.resolve()})"
    except Exception:
        pass
    return port

def _open_port(settings: Settings) -> Optional[serial.Serial]:
    try:
        ser = serial.Serial(
            port=settings["port"],
            baudrate=settings["baud"],
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
        )
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        return ser
    except serial.SerialException as exc:
        print(red(f"\n  Cannot open {settings['port']}: {exc}"))
        return None


# ── Flash / get-config operations ─────────────────────────────────────────────

def do_flash(packets: List[Tuple[int, bytes, str]], settings: Settings) -> bool:
    """Open port, send packets, send EOT.  Returns success."""
    ser = _open_port(settings)
    if ser is None:
        return False

    sess = ProvSession(ser,
                       max_retries=settings["max_retries"],
                       byte_timeout=settings["byte_timeout"],
                       verbose=settings["verbose"])
    success = True
    if not sess.wait_for_ready(timeout=settings["wait_timeout"]):
        ser.close()
        return False

    for pkt_type, payload, label in packets:
        if not sess.send_packet(pkt_type, payload, label):
            success = False
            break

    if success:
        success = sess.send_eot()

    ser.close()
    sess.print_summary(success)
    return success

def do_get_config(settings: Settings) -> Optional[Dict[str, int]]:
    """Open port, send GET_CONFIG, return config dict or None."""
    ser = _open_port(settings)
    if ser is None:
        return None

    sess = ProvSession(ser,
                       max_retries=1,
                       byte_timeout=settings["byte_timeout"],
                       verbose=settings["verbose"])
    result = None
    if sess.wait_for_ready(timeout=settings["wait_timeout"]):
        result = sess.get_config()
        # Always end the session gracefully
        ser.write(bytes([PROV_EOT]))
        ser.flush()
        ser.read(1)   # consume ACK (best-effort)

    ser.close()
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  TUI — helpers
# ─────────────────────────────────────────────────────────────────────────────

def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def _header(settings: Settings, subtitle: str = "") -> None:
    port_str = _resolve_port(settings["port"])
    box_w = 50
    print("╔" + "═" * box_w + "╗")
    print(f"║  {'FoF Field Provisioning Tool':<{box_w - 2}}║")
    print(f"║  {port_str:<{box_w - 2}}║")
    print("╚" + "═" * box_w + "╝")
    if subtitle:
        print(f"\n── {subtitle} " + "─" * max(0, box_w - len(subtitle) - 1))
    print()

def _pause(msg: str = "Press Enter to return…") -> None:
    try:
        input(f"\n  {msg}")
    except (KeyboardInterrupt, EOFError):
        pass

def _choose(options: List[str], *, zero_label: str = "Back") -> int:
    """Print numbered options; return 1-based selection or 0 for zero_label."""
    for i, label in enumerate(options, 1):
        print(f"  {i}.  {label}")
    print(f"  0.  {zero_label}")
    print()
    while True:
        try:
            raw = input("  Select: ").strip()
            n   = int(raw)
            if 0 <= n <= len(options):
                return n
        except (ValueError, KeyboardInterrupt, EOFError):
            pass
        print(f"  Enter 0–{len(options)}.")

def _ask_yn(prompt: str, default: bool = True) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    try:
        raw = input(f"  {prompt} {hint}: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return default
    if not raw:
        return default
    return raw.startswith("y")

def _file_line(label: str, path: Path, expected_size: int) -> str:
    if path.exists():
        size = path.stat().st_size
        size_ok = size == expected_size
        icon = green("✓") if size_ok else yellow("!")
        detail = f"{size} B" + ("" if size_ok else f"  ← expected {expected_size}")
    else:
        icon   = red("✗")
        detail = "not found"
    return f"  {icon}  {label:<16} {str(path):<34}  [{detail}]"


# ─────────────────────────────────────────────────────────────────────────────
#  TUI — menus
# ─────────────────────────────────────────────────────────────────────────────

def menu_main(settings: Settings) -> None:
    while True:
        _clear()
        _header(settings)
        choice = _choose([
            "Flash All          (private key + public key + config)",
            "Flash Private Key",
            "Flash Public Key",
            "Flash Configuration",
            "Get Configuration",
            "Generate Key Pair",
            "Settings",
        ], zero_label="Exit")
        if choice == 0:
            break
        elif choice == 1:
            menu_flash_all(settings)
        elif choice == 2:
            menu_flash_key(settings, PKT_PRIVKEY, "Private Key",
                           settings.privkey_path(), PRIVKEY_LEN)
        elif choice == 3:
            menu_flash_key(settings, PKT_PUBKEY, "Public Key",
                           settings.pubkey_path(), PUBKEY_LEN)
        elif choice == 4:
            menu_flash_config(settings)
        elif choice == 5:
            menu_get_config(settings)
        elif choice == 6:
            menu_generate_keys(settings)
        elif choice == 7:
            menu_settings(settings)


# ── Flash All ─────────────────────────────────────────────────────────────────

def menu_flash_all(settings: Settings) -> None:
    while True:
        _clear()
        _header(settings, "Flash All")
        priv_path = settings.privkey_path()
        pub_path  = settings.pubkey_path()
        print(_file_line("Private key", priv_path,  PRIVKEY_LEN))
        print(_file_line("Public key",  pub_path,   PUBKEY_LEN))
        print(f"  {green('✓')}  {'Config':<16} (from settings)  [6 fields]")
        print()

        choice = _choose(["Start", "Edit config values"])
        if choice == 0:
            break
        elif choice == 1:
            packets = _collect_key_packets(settings)
            packets.append((PKT_CONFIG, _pack_config(settings["config"]), "Configuration"))
            if not packets:
                print(red("  No data to send — all key files missing."))
                _pause()
            else:
                do_flash(packets, settings)
                _pause()
        elif choice == 2:
            menu_edit_config(settings)

def _collect_key_packets(settings: Settings) -> List[Tuple[int, bytes, str]]:
    """Load whichever key files exist; warn about missing ones."""
    packets: List[Tuple[int, bytes, str]] = []
    for path, pkt_type, label, expected_len in [
        (settings.privkey_path(), PKT_PRIVKEY, "Private Key", PRIVKEY_LEN),
        (settings.pubkey_path(),  PKT_PUBKEY,  "Public Key",  PUBKEY_LEN),
    ]:
        if path.exists():
            try:
                raw = load_key(str(path), expected_len)
                packets.append((pkt_type, raw, label))
            except Exception as exc:
                print(yellow(f"  ! Skipping {label}: {exc}"))
        else:
            print(yellow(f"  ! Skipping {label}: file not found"))
    return packets


# ── Flash single key ──────────────────────────────────────────────────────────

def menu_flash_key(settings: Settings, pkt_type: int, label: str,
                   default_path: Path, expected_len: int) -> None:
    current_path = default_path
    while True:
        _clear()
        _header(settings, f"Flash {label}")
        print(_file_line(label, current_path, expected_len))
        print()

        choice = _choose(["Start", "Choose file"])
        if choice == 0:
            break
        elif choice == 1:
            if not current_path.exists():
                print(red(f"  ✗  File not found: {current_path}"))
                print(dim("     Use option 2 to select a file."))
                _pause()
                continue
            try:
                raw = load_key(str(current_path), expected_len)
            except Exception as exc:
                print(red(f"  ✗  {exc}"))
                _pause()
                continue
            do_flash([(pkt_type, raw, label)], settings)
            _pause()
        elif choice == 2:
            try:
                raw_input = input(f"  Path [{current_path}]: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            p = Path(raw_input) if raw_input else current_path
            if not p.exists():
                print(red(f"  ✗  Not found: {p}"))
                _pause()
            else:
                current_path = p


# ── Flash Configuration ───────────────────────────────────────────────────────

def menu_flash_config(settings: Settings) -> None:
    while True:
        _clear()
        _header(settings, "Flash Configuration")
        _print_config(settings["config"])
        print()

        choice = _choose(["Start", "Edit values", "Reset to defaults"])
        if choice == 0:
            break
        elif choice == 1:
            payload = _pack_config(settings["config"])
            do_flash([(PKT_CONFIG, payload, "Configuration")], settings)
            _pause()
        elif choice == 2:
            menu_edit_config(settings)
        elif choice == 3:
            settings["config"] = _default_config()
            print(green("  Config reset to defaults."))
            _pause()


def menu_edit_config(settings: Settings) -> None:
    while True:
        _clear()
        _header(settings, "Edit Configuration")
        cfg = settings["config"]
        for i, (name, desc, default) in enumerate(CONFIG_FIELDS, 1):
            val = cfg.get(name, default)
            print(f"  {i}.  {name:<32}  [{val:>6} ms]  {dim(desc)}")
        print(f"  {len(CONFIG_FIELDS) + 1}.  Reset to defaults")
        print(f"  0.  Back")
        print()

        try:
            raw = input("  Select: ").strip()
            idx = int(raw)
        except (ValueError, KeyboardInterrupt, EOFError):
            continue

        if idx == 0:
            break
        elif 1 <= idx <= len(CONFIG_FIELDS):
            name, desc, default = CONFIG_FIELDS[idx - 1]
            current = cfg.get(name, default)
            try:
                v = input(f"  {name} [{current}]: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if v:
                try:
                    new_val = int(v)
                    if new_val < 0:
                        raise ValueError
                    cfg[name] = new_val
                    settings["config"] = cfg
                except ValueError:
                    print(red("  Invalid — enter a non-negative integer."))
                    _pause()
        elif idx == len(CONFIG_FIELDS) + 1:
            settings["config"] = _default_config()
            print(green("  Reset to defaults."))
            _pause()

def _print_config(cfg: Dict[str, int]) -> None:
    for name, desc, default in CONFIG_FIELDS:
        val = cfg.get(name, default)
        print(f"  {name:<32}  {val:>6} ms   {dim(desc)}")


# ── Get Configuration ─────────────────────────────────────────────────────────

def menu_get_config(settings: Settings) -> None:
    while True:
        _clear()
        _header(settings, "Get Configuration")
        print("  Reads the current configuration from device NVRAM.")
        print()

        choice = _choose(["Start"])
        if choice == 0:
            break
        elif choice == 1:
            result = do_get_config(settings)
            if result is not None:
                print(f"\n  {green('✓')}  Configuration received:\n")
                _print_config(result)
                if _ask_yn("Load these values into settings?"):
                    settings["config"] = result
                    print(green("  Settings updated."))
            _pause()


# ── Generate Key Pair ─────────────────────────────────────────────────────────

def menu_generate_keys(settings: Settings) -> None:
    while True:
        _clear()
        _header(settings, "Generate Key Pair")
        out_dir   = settings.key_dir_path()
        priv_path = out_dir / "private.bin"
        pub_path  = out_dir / "public.bin"
        print(f"  Output directory : {out_dir}")
        print(f"  Private key      : {priv_path}"
              + (f"  {yellow('[will overwrite]')}" if priv_path.exists() else ""))
        print(f"  Public key       : {pub_path}"
              + (f"  {yellow('[will overwrite]')}" if pub_path.exists() else ""))
        print()

        choice = _choose(["Generate and save", "Change output directory"])
        if choice == 0:
            break
        elif choice == 1:
            if (priv_path.exists() or pub_path.exists()):
                if not _ask_yn("Existing key files will be overwritten. Continue?",
                               default=False):
                    continue
            print()
            try:
                priv_bytes, pub_bytes = generate_keypair(out_dir)
                print(green(f"  ✓  {priv_path}  [{len(priv_bytes)} B]"))
                print(green(f"  ✓  {pub_path}   [{len(pub_bytes)} B]"))
            except Exception as exc:
                print(red(f"  ✗  Key generation failed: {exc}"))
                _pause()
                continue

            if _ask_yn("Flash to device now?"):
                packets = [
                    (PKT_PRIVKEY, priv_bytes, "Private Key"),
                    (PKT_PUBKEY,  pub_bytes,  "Public Key"),
                ]
                do_flash(packets, settings)
            _pause()
        elif choice == 2:
            try:
                raw = input(f"  Key directory [{settings['key_dir']}]: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if raw:
                settings["key_dir"] = raw


# ── Settings ──────────────────────────────────────────────────────────────────

def menu_settings(settings: Settings) -> None:
    while True:
        _clear()
        _header(settings, "Settings")
        print(f"  1.  Serial port      [{settings['port']}]")
        print(f"  2.  Baud rate        [{settings['baud']}]")
        print(f"  3.  Max retries      [{settings['max_retries']}]")
        print(f"  4.  Wait timeout     [{settings['wait_timeout']} s]")
        print(f"  5.  Key directory    [{settings['key_dir']}]")
        print(f"  6.  Verbose output   [{'on' if settings['verbose'] else 'off'}]")
        print(f"  0.  Back")
        print()

        try:
            raw = input("  Select: ").strip()
            idx = int(raw)
        except (ValueError, KeyboardInterrupt, EOFError):
            continue

        if idx == 0:
            break
        elif idx == 1:
            _settings_str(settings, "port", "Serial port", "/dev/serial0")
        elif idx == 2:
            _settings_int(settings, "baud", "Baud rate", 9600)
        elif idx == 3:
            _settings_int(settings, "max_retries", "Max retries", 3)
        elif idx == 4:
            _settings_float(settings, "wait_timeout", "Wait timeout (s)", 8.0)
        elif idx == 5:
            _settings_str(settings, "key_dir", "Key directory", "keys")
        elif idx == 6:
            settings["verbose"] = not settings["verbose"]

def _settings_str(settings: Settings, key: str, label: str, default: str) -> None:
    try:
        v = input(f"  {label} [{settings[key]}]: ").strip()
        if v:
            settings[key] = v
    except (KeyboardInterrupt, EOFError):
        pass

def _settings_int(settings: Settings, key: str, label: str, default: int) -> None:
    try:
        v = input(f"  {label} [{settings[key]}]: ").strip()
        if v:
            settings[key] = int(v)
    except (ValueError, KeyboardInterrupt, EOFError):
        pass

def _settings_float(settings: Settings, key: str, label: str, default: float) -> None:
    try:
        v = input(f"  {label} [{settings[key]}]: ").strip()
        if v:
            settings[key] = float(v)
    except (ValueError, KeyboardInterrupt, EOFError):
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  Non-interactive CLI  (unchanged behaviour from v1)
# ─────────────────────────────────────────────────────────────────────────────

def make_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="fof_prov.py",
        description="FoF STM32 field provisioning — Raspberry Pi peer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Run without action flags to enter the interactive menu.

        examples:
          python3 fof_prov.py                            # interactive TUI
          python3 fof_prov.py --generate                 # generate keys, then flash
          python3 fof_prov.py --private-key priv.bin     # flash one key
          python3 fof_prov.py --port /dev/ttyAMA0 \\
              --private-key priv.bin --public-key pub.bin \\
              --tx-timeout 500 --main-delay 2
        """),
    )

    g = ap.add_argument_group("serial port")
    g.add_argument("--port",  default=None, help="UART device  (default: from settings)")
    g.add_argument("--baud",  type=int, default=None, help="baud rate (default: 9600)")

    g = ap.add_argument_group("key packets")
    g.add_argument("--private-key", metavar="FILE")
    g.add_argument("--public-key",  metavar="FILE")
    g.add_argument("--generate",    action="store_true",
                   help="generate a fresh SECP256R1 keypair, save to key-dir, then flash")

    g = ap.add_argument_group("config packet  (sent when any flag is provided)")
    g.add_argument("--tx-timeout",        type=int, metavar="MS",
                   help="TxTimeoutMs                (default: 500)")
    g.add_argument("--transponder-cycle", type=int, metavar="MS",
                   help="TransponderMainCycleMs      (default: 2)")
    g.add_argument("--challenger-cycle",  type=int, metavar="MS",
                   help="ChallengerMainCycleMs       (default: 1000)")
    g.add_argument("--response-wait",     type=int, metavar="MS",
                   help="ResponseWaitCycleDelayMs    (default: 10)")
    g.add_argument("--rtt-tolerance",     type=int, metavar="MS",
                   help="ResponseDelayToleranceMs    (default: 500)")
    g.add_argument("--watchdog",          type=int, metavar="MS",
                   help="WatchdogTimeoutMs           (default: 1000)")

    g = ap.add_argument_group("behaviour")
    g.add_argument("--max-retries",  type=int, default=None, metavar="N")
    g.add_argument("--wait",         type=float, default=None, metavar="SECS",
                   help="seconds to wait for device READY  (default: 30)")
    g.add_argument("--byte-timeout", type=float, default=None, metavar="SECS")
    g.add_argument("--dry-run",      action="store_true",
                   help="build and print packets without opening the serial port")
    g.add_argument("-v", "--verbose", action="store_true")

    return ap


def run_cli(args: argparse.Namespace, settings: Settings) -> int:
    # Override settings with CLI flags
    if args.port:         settings["port"]         = args.port
    if args.baud:         settings["baud"]         = args.baud
    if args.max_retries:  settings["max_retries"]  = args.max_retries
    if args.wait:         settings["wait_timeout"] = args.wait
    if args.byte_timeout: settings["byte_timeout"] = args.byte_timeout
    if args.verbose:      settings["verbose"]      = True

    packets: List[Tuple[int, bytes, str]] = []
    errors:  List[str] = []

    # Key generation
    if args.generate:
        out_dir = settings.key_dir_path()
        print(f"Generating SECP256R1 keypair → {out_dir}/")
        try:
            priv_bytes, pub_bytes = generate_keypair(out_dir)
            print(green(f"  ✓  private.bin  [{len(priv_bytes)} B]"))
            print(green(f"  ✓  public.bin   [{len(pub_bytes)} B]"))
            packets.append((PKT_PRIVKEY, priv_bytes, "Private Key"))
            packets.append((PKT_PUBKEY,  pub_bytes,  "Public Key"))
        except Exception as exc:
            errors.append(f"--generate: {exc}")

    if args.private_key and not args.generate:
        try:
            packets.append((PKT_PRIVKEY, load_key(args.private_key, PRIVKEY_LEN),
                            "Private Key"))
        except Exception as exc:
            errors.append(f"--private-key: {exc}")

    if args.public_key and not args.generate:
        try:
            packets.append((PKT_PUBKEY, load_key(args.public_key, PUBKEY_LEN),
                            "Public Key"))
        except Exception as exc:
            errors.append(f"--public-key: {exc}")

    # Config
    cfg_flags = {
        "TxTimeoutMs":              args.tx_timeout,
        "TransponderMainCycleMs":   args.transponder_cycle,
        "ChallengerMainCycleMs":    args.challenger_cycle,
        "ResponseWaitCycleDelayMs": args.response_wait,
        "ResponseDelayToleranceMs": args.rtt_tolerance,
        "WatchdogTimeoutMs":        args.watchdog,
    }
    if any(v is not None for v in cfg_flags.values()):
        cfg = dict(settings["config"])
        for k, v in cfg_flags.items():
            if v is not None:
                cfg[k] = v
        payload = _pack_config(cfg)
        vals    = struct.unpack("<6I", payload)
        label   = ("Configuration\n"
                   + "\n".join(f"   {n}={v}"
                               for (n, _, _), v in zip(CONFIG_FIELDS, vals)))
        packets.append((PKT_CONFIG, payload, label))

    if errors:
        for e in errors:
            print(red(f"Error: {e}"))
        return 1

    if not packets:
        print(yellow("Nothing to send.  Run without flags for interactive mode."))
        make_parser().print_usage()
        return 1

    print(bold(f"\nFoF provisioning — {len(packets)} packet(s):"))
    for _, payload, label in packets:
        print(f"  • {label.splitlines()[0]}  ({len(payload)} B)")

    if args.dry_run:
        print(yellow("\n[DRY RUN] packets not transmitted."))
        if args.verbose:
            for pkt_type, payload, label in packets:
                pkt = build_packet(pkt_type, payload)
                _hex_dump(label.splitlines()[0], pkt)
        return 0

    success = do_flash(packets, settings)
    return 0 if success else 1


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    settings = Settings()
    ap       = make_parser()
    args     = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(message)s")

    # Determine mode: interactive if no action flags supplied
    action_flags = [
        args.private_key, args.public_key,
        args.tx_timeout, args.transponder_cycle, args.challenger_cycle,
        args.response_wait, args.rtt_tolerance, args.watchdog,
    ]
    is_interactive = (
        not args.generate
        and all(f is None for f in action_flags)
    )

    if is_interactive:
        try:
            menu_main(settings)
        except (KeyboardInterrupt, EOFError):
            print()
        return 0

    return run_cli(args, settings)


if __name__ == "__main__":
    sys.exit(main())
