#!/usr/bin/env python3
"""
fof_prov.py — FoF STM32 Field Provisioning Tool

Interactive TUI (and non-interactive CLI) for provisioning the STM32 LoRa
device via USART1: send private key, public key, configuration data, and
read back the current configuration.

Persistent-session model
────────────────────────
The UART connection stays open across all menu operations.  A background
thread sends PROV_PING (0x05) every second so the device does not time out
between individual operations.  EOT (and the resulting flash commit) is sent
only when the user disconnects or exits.

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
  pip3 install cryptography   # optional — PEM key files and key generation
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
import threading
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any

try:
    import serial
except ImportError:
    sys.exit("pyserial not installed.  Run:  pip3 install pyserial")


# ── Protocol constants ────────────────────────────────────────────────────────

PROV_READY   = 0xAA   # device → peer : ready for next packet
PROV_ACK     = 0x06   # device → peer : packet accepted
PROV_NAK     = 0x15   # device → peer : CRC error — retransmit
PROV_RJCT    = 0xFF   # device → peer : request not supported
PROV_EOT     = 0x04   # peer → device : end of transmission (commits flash)
PROV_PING    = 0x05   # peer → device : keepalive (ignored by device packet loop)

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
    ("TxTimeoutMs",              "LoRa transmit timeout",                  500),
    ("TransponderMainCycleMs",   "Transponder poll rate",                    2),
    ("ChallengerMainCycleMs",    "Challenger poll rate",                  1000),
    ("ResponseWaitCycleDelayMs", "Challenger wait per cycle for response",   10),
    ("ResponseDelayToleranceMs", "Max acceptable challenge-response RTT",   500),
    ("WatchdogTimeoutMs",        "Watchdog timeout",                       1000),
]

def _default_config() -> Dict[str, int]:
    return {f[0]: f[2] for f in CONFIG_FIELDS}

def _pack_config(cfg: Dict[str, int]) -> bytes:
    return struct.pack("<6I", *[cfg.get(f[0], f[2]) for f in CONFIG_FIELDS])

def _unpack_config(data: bytes) -> Dict[str, int]:
    return {f[0]: v for f, v in zip(CONFIG_FIELDS, struct.unpack("<6I", data))}


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
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1) & 0xFFFF
    return crc


# ── Packet construction / parsing ─────────────────────────────────────────────

def build_packet(pkt_type: int, payload: bytes) -> bytes:
    frame = bytes([PROV_SOF, pkt_type, len(payload)]) + payload
    crc   = crc16_ccitt(frame)
    return frame + bytes([crc >> 8, crc & 0xFF])

def parse_packet(raw: bytes) -> Optional[Tuple[int, bytes]]:
    if len(raw) < 5 or raw[0] != PROV_SOF:
        return None
    pkt_len = raw[2]
    if len(raw) != 3 + pkt_len + 2:
        return None
    if ((raw[-2] << 8) | raw[-1]) != crc16_ccitt(raw[:-2]):
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
    pub_bytes  = pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
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
                merged = copy.deepcopy(self._DEFAULTS["config"])
                merged.update(loaded.get("config", {}))
                self._data["config"] = merged
        except Exception:
            pass

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._data[key] = value
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


# ── Active session (persistent UART connection + keepalive) ───────────────────

class ActiveSession:
    """
    Persistent UART connection with background keepalive.

    After READY is received, call start_ping().  A daemon thread then sends
    PROV_PING (0x05) every second through a write lock so ping bytes cannot
    interleave with packet data.  EOT (flash commit) is sent on close().
    """

    def __init__(self, ser: serial.Serial) -> None:
        self.ser      = ser
        self._lock    = threading.Lock()
        self._stop    = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start_ping(self) -> None:
        self._thread = threading.Thread(target=self._ping_loop, daemon=True)
        self._thread.start()

    def _ping_loop(self) -> None:
        while not self._stop.wait(1.0):
            with self._lock:
                try:
                    self.ser.write(bytes([PROV_PING]))
                    self.ser.flush()
                except Exception:
                    break

    def send(self, data: bytes, *, flush_rx: bool = False) -> None:
        """Write bytes exclusively — ping is blocked for the duration.
        flush_rx=True discards stale incoming bytes before writing, inside the
        same lock window so no ping can arrive between the flush and the write."""
        with self._lock:
            if flush_rx:
                self.ser.reset_input_buffer()
            self.ser.write(data)
            self.ser.flush()

    def recv(self, timeout: float) -> Optional[int]:
        """Read one byte with timeout.  No lock needed (opposite direction)."""
        self.ser.timeout = timeout
        b = self.ser.read(1)
        return b[0] if b else None

    def close(self, commit: bool = True) -> None:
        """Stop pings, optionally send EOT (commits flash), close port."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if commit:
            try:
                with self._lock:
                    self.ser.write(bytes([PROV_EOT]))
                    self.ser.flush()
                self.ser.timeout = 3.0
                self.ser.read(1)   # consume ACK
            except Exception:
                pass
        try:
            self.ser.close()
        except Exception:
            pass


# ── Global session state ──────────────────────────────────────────────────────

class _State:
    conn:      Optional[ActiveSession]  = None
    prov:      Optional["ProvSession"]  = None
    _settings: Optional["Settings"]     = None   # updated by start_auto_connect
    _ac_thread: Optional[threading.Thread] = None

_gs = _State()


# ── Background auto-connect thread ────────────────────────────────────────────

def _auto_connect_worker() -> None:
    """
    Daemon thread: keeps the serial port open and listens for PROV_READY.

    Lifecycle:
      • While _gs.conn is None: open port, block-read for READY (2 s per read),
        establish session when READY arrives, print a brief notification.
      • While _gs.conn is not None: sleep until session disappears (disconnect).
      • On disconnect: loop restarts — port is re-opened and READY is awaited
        again (for the next provisioning cycle / device reboot).

    Settings (_gs._settings) are re-read each outer iteration so that port or
    baud changes made in the Settings menu take effect without restarting the
    thread.
    """
    while True:
        s = _gs._settings
        if s is None:
            time.sleep(0.5)
            continue

        # ── Session active: just wait ────────────────────────────────────────
        if _gs.conn is not None:
            time.sleep(2.0)
            continue

        # ── Try to open port ─────────────────────────────────────────────────
        ser = None
        try:
            ser = serial.Serial(
                port     = s["port"],
                baudrate = s["baud"],
                bytesize = serial.EIGHTBITS,
                parity   = serial.PARITY_NONE,
                stopbits = serial.STOPBITS_ONE,
            )
            ser.reset_input_buffer()
            ser.reset_output_buffer()
        except serial.SerialException:
            if ser is not None:
                try: ser.close()
                except Exception: pass
            time.sleep(3.0)
            continue

        # ── Wait for READY on open port ──────────────────────────────────────
        ser.timeout = 2.0          # short per-read timeout so we stay responsive
        connected   = False
        try:
            while _gs.conn is None and _gs._settings is s:
                data = ser.read(1)
                if not data:
                    continue       # read timed out, keep waiting
                if data[0] == PROV_READY:
                    ser.reset_input_buffer()
                    conn = ActiveSession(ser)
                    prov = ProvSession(conn,
                                       max_retries  = s["max_retries"],
                                       byte_timeout = s["byte_timeout"],
                                       verbose      = s["verbose"])
                    conn.start_ping()
                    _gs.conn = conn
                    _gs.prov = prov
                    ser       = None    # ownership transferred — do NOT close below
                    connected = True
                    print(f"\n  {green('●')} Device connected  [{s['port']}]",
                          flush=True)
                    break
                # Other byte (noise): ignore and keep listening
        except Exception:
            pass
        finally:
            if ser is not None:    # only close if we still own it
                try: ser.close()
                except Exception: pass

        if not connected:
            time.sleep(0.5)        # brief pause before re-trying


def start_auto_connect(settings: "Settings") -> None:
    """
    Update the settings reference and start the auto-connect daemon if needed.

    Safe to call repeatedly — only spawns a new thread when the existing one
    is no longer alive (first call, or after unexpected thread death).
    """
    _gs._settings = settings       # always refresh so thread sees new values
    if _gs._ac_thread is not None and _gs._ac_thread.is_alive():
        return
    t = threading.Thread(target=_auto_connect_worker, daemon=True)
    t.start()
    _gs._ac_thread = t


# ── Provisioning session ──────────────────────────────────────────────────────

class ProvSession:
    """Protocol operations over an ActiveSession."""

    def __init__(self, conn: ActiveSession, *,
                 max_retries: int = 3,
                 byte_timeout: float = 5.0,
                 verbose: bool = False) -> None:
        self._conn        = conn
        self.max_retries  = max_retries
        self.byte_timeout = byte_timeout
        self.verbose      = verbose
        self._sent  = 0
        self._acked = 0

    def reset_counters(self) -> None:
        self._sent = self._acked = 0

    def _log(self, msg: str) -> None:
        print(f"  [{time.strftime('%H:%M:%S')}]  {msg}")

    def _recv(self, timeout: float) -> Optional[int]:
        return self._conn.recv(timeout)

    # ── Send packet ───────────────────────────────────────────────────────────

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
            # Flush RX before every attempt — on timeout retries, delayed bytes
            # from the previous attempt may still be arriving.
            self._conn.send(packet, flush_rx=True)
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

    # ── Get config ────────────────────────────────────────────────────────────

    def _recv_packet_from_sof(self) -> Optional[Tuple[int, bytes]]:
        """Read TYPE+LEN+PAYLOAD+CRC after SOF has already been consumed."""
        frame = bytearray([PROV_SOF])
        for _ in range(2):          # TYPE, LEN
            b = self._recv(self.byte_timeout)
            if b is None:
                return None
            frame.append(b)
        pkt_len = frame[2]
        if pkt_len > 64:            # sanity: largest known payload is 64 B (pubkey)
            self._log(red(f"LEN={pkt_len} > 64 — framing error, aborting"))
            return None
        for _ in range(pkt_len):    # PAYLOAD
            b = self._recv(self.byte_timeout)
            if b is None:
                return None
            frame.append(b)
        for _ in range(2):          # CRC HI, LO
            b = self._recv(self.byte_timeout)
            if b is None:
                return None
            frame.append(b)
        return parse_packet(bytes(frame))

    def get_config(self) -> Optional[Dict[str, int]]:
        """
        Send a GET_CONFIG request and return the device config dict.
        Returns None on error or if the device does not support the command.

        Retries up to max_retries times.  Before each attempt the RX buffer is
        flushed (inside the send lock) so stale bytes from earlier operations —
        e.g. extra READY signals or partial responses — cannot corrupt the read.
        """
        packet = build_packet(PKT_GET_CONFIG, b"")
        print(f"\n  {bold('▸  GET_CONFIG request')}")
        if self.verbose:
            _hex_dump("Packet", packet)

        for attempt in range(1, self.max_retries + 1):
            if attempt > 1:
                self._log(yellow(f"Retry {attempt}/{self.max_retries}…"))

            # flush_rx=True clears stale bytes atomically with the write
            self._conn.send(packet, flush_rx=True)

            # Scan for SOF, tolerating up to 3 leading stale bytes
            resp = None
            for _ in range(4):
                resp = self._recv(timeout=self.byte_timeout)
                if resp is None:
                    self._log(yellow(f"No response (attempt {attempt})"))
                    break
                if resp in (PROV_RJCT, PROV_NAK):
                    print(f"\n  {red('✗')}  "
                          "This device doesn't support reading out the configuration.")
                    return None
                if resp == PROV_SOF:
                    break
                self._log(yellow(f"Skipping stale byte 0x{resp:02X}"))

            if resp != PROV_SOF:
                continue  # retry

            result = self._recv_packet_from_sof()
            if result is None:
                self._log(yellow(f"Incomplete response (attempt {attempt})"))
                continue
            pkt_type, payload = result
            if pkt_type != PKT_CONFIG or len(payload) != CONFIG_LEN:
                self._log(yellow(
                    f"Unexpected response type=0x{pkt_type:02X} len={len(payload)}"
                    f" (attempt {attempt})"))
                continue

            self._log(green("Configuration received  ✓"))
            return _unpack_config(payload)

        self._log(red(f"GET_CONFIG failed after {self.max_retries} attempts."))
        return None

    # ── Summary ───────────────────────────────────────────────────────────────

    def print_summary(self, success: bool) -> None:
        sep = "─" * 46
        print(f"\n{sep}")
        if self._sent:
            print(f"  Packets sent   :  {self._sent}")
            print(f"  Packets ACKed  :  {self._acked}")
        print(f"  Result         :  "
              + (green("OK") if success else red("FAILED")))
        print(sep)


# ── Hex dump ──────────────────────────────────────────────────────────────────

def _hex_dump(label: str, data: bytes, cols: int = 16) -> None:
    print(f"   {label}  ({len(data)} B):")
    for i in range(0, len(data), cols):
        chunk = data[i:i + cols]
        print(f"     {i:04x}  {' '.join(f'{b:02x}' for b in chunk):<{cols*3}}"
              f"  {''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in chunk)}")


# ── Connection management ─────────────────────────────────────────────────────

def _resolve_port(port: str) -> str:
    try:
        p = Path(port)
        if p.is_symlink():
            return f"{port} ({p.resolve()})"
    except Exception:
        pass
    return port

def ensure_connected(settings: Settings) -> bool:
    """
    Return True when a session is open, blocking up to wait_timeout seconds.

    The auto-connect thread is responsible for opening the port and receiving
    READY.  This function just starts that thread (if not running) and polls
    _gs.conn until it is set or the timeout expires.
    """
    if _gs.conn is not None:
        return True

    start_auto_connect(settings)

    print(f"\n  {cyan('Waiting for device…')}")
    print(f"  Port {_resolve_port(settings['port'])}  │  {settings['baud']} baud  │  8N1")
    print(f"  (power on or reset the device within {settings['wait_timeout']:.0f} s)\n")

    deadline = time.monotonic() + settings["wait_timeout"]
    dots = 0
    while time.monotonic() < deadline:
        if _gs.conn is not None:
            return True
        time.sleep(0.5)
        dots += 1
        print(f"  {'.' * (dots % 6 + 1):<7}", end="\r", flush=True)

    print()
    print(red("  Timeout — no READY from device"))
    return False

def disconnect(commit: bool = True) -> None:
    if _gs.conn is None:
        return
    msg = "Disconnecting and writing flash…" if commit else "Disconnecting (no flash write)…"
    print(f"\n  {msg}")
    _gs.conn.close(commit=commit)
    _gs.conn = None
    _gs.prov = None
    print(green("  Disconnected."))


# ── Flash / get-config operations ─────────────────────────────────────────────

def do_flash(packets: List[Tuple[int, bytes, str]], settings: Settings) -> bool:
    if not ensure_connected(settings):
        return False
    prov = _gs.prov
    prov.reset_counters()
    success = True
    for pkt_type, payload, label in packets:
        if not prov.send_packet(pkt_type, payload, label):
            success = False
            break
    prov.print_summary(success)
    return success

def do_get_config(settings: Settings) -> Optional[Dict[str, int]]:
    if not ensure_connected(settings):
        return None
    return _gs.prov.get_config()


# ─────────────────────────────────────────────────────────────────────────────
#  TUI helpers
# ─────────────────────────────────────────────────────────────────────────────

def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def _header(settings: Settings, subtitle: str = "") -> None:
    box_w    = 52
    port_str = _resolve_port(settings["port"])
    if _gs.conn is not None:
        conn_str = green("●") + " Connected"
        port_line = f"{port_str}  {conn_str}"
    else:
        conn_str = dim("○") + " Offline"
        port_line = f"{port_str}  {conn_str}"

    print("╔" + "═" * box_w + "╗")
    print(f"║  {'FoF Field Provisioning Tool':<{box_w - 2}}║")
    print(f"║  {port_line:<{box_w - 3 + (9 if _COLOR else 0)}}║")
    print("╚" + "═" * box_w + "╝")
    if subtitle:
        print(f"\n── {subtitle} " + "─" * max(0, box_w - len(subtitle)))
    print()

def _pause(msg: str = "Press Enter to return…") -> None:
    try:
        input(f"\n  {msg}")
    except (KeyboardInterrupt, EOFError):
        pass

def _choose(options: List[str], *, zero_label: str = "Back") -> int:
    for i, label in enumerate(options, 1):
        print(f"  {i}.  {label}")
    print(f"  0.  {zero_label}")
    print()
    while True:
        try:
            n = int(input("  Select: ").strip())
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
    return raw.startswith("y") if raw else default

def _file_line(label: str, path: Path, expected_size: int) -> str:
    if path.exists():
        size = path.stat().st_size
        icon = green("✓") if size == expected_size else yellow("!")
        detail = f"{size} B" + ("" if size == expected_size else f"  ← expected {expected_size}")
    else:
        icon, detail = red("✗"), "not found"
    return f"  {icon}  {label:<16} {str(path):<36} [{detail}]"


# ─────────────────────────────────────────────────────────────────────────────
#  TUI menus
# ─────────────────────────────────────────────────────────────────────────────

def menu_main(settings: Settings) -> None:
    start_auto_connect(settings)   # begin listening for device READY immediately
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
            "Disconnect" if _gs.conn else dim("Disconnect  (not connected)"),
        ], zero_label="Exit")

        if choice == 0:
            if _gs.conn:
                if _ask_yn("Write flash and disconnect?"):
                    disconnect(commit=True)
                else:
                    disconnect(commit=False)
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
        elif choice == 8:
            if _gs.conn:
                if _ask_yn("Write flash and disconnect?"):
                    disconnect(commit=True)
                else:
                    disconnect(commit=False)
            # else: no-op, re-displays menu


# ── Flash All ─────────────────────────────────────────────────────────────────

def menu_flash_all(settings: Settings) -> None:
    while True:
        _clear()
        _header(settings, "Flash All")
        print(_file_line("Private key", settings.privkey_path(),  PRIVKEY_LEN))
        print(_file_line("Public key",  settings.pubkey_path(),   PUBKEY_LEN))
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
    packets: List[Tuple[int, bytes, str]] = []
    for path, pkt_type, label, elen in [
        (settings.privkey_path(), PKT_PRIVKEY, "Private Key", PRIVKEY_LEN),
        (settings.pubkey_path(),  PKT_PUBKEY,  "Public Key",  PUBKEY_LEN),
    ]:
        if path.exists():
            try:
                packets.append((pkt_type, load_key(str(path), elen), label))
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
                v = input(f"  Path [{current_path}]: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if v:
                current_path = Path(v)


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
            do_flash([(PKT_CONFIG, _pack_config(settings["config"]), "Configuration")],
                     settings)
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
            idx = int(input("  Select: ").strip())
        except (ValueError, KeyboardInterrupt, EOFError):
            continue

        if idx == 0:
            break
        elif 1 <= idx <= len(CONFIG_FIELDS):
            name, _, default = CONFIG_FIELDS[idx - 1]
            current = cfg.get(name, default)
            try:
                v = input(f"  {name} [{current}]: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if v:
                try:
                    cfg[name] = max(0, int(v))
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
        print(f"  {name:<32}  {cfg.get(name, default):>6} ms   {dim(desc)}")


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
                if _ask_yn("Load these values into local settings?"):
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
                do_flash([(PKT_PRIVKEY, priv_bytes, "Private Key"),
                          (PKT_PUBKEY,  pub_bytes,  "Public Key")], settings)
            _pause()
        elif choice == 2:
            try:
                v = input(f"  Key directory [{settings['key_dir']}]: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if v:
                settings["key_dir"] = v


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
            idx = int(input("  Select: ").strip())
        except (ValueError, KeyboardInterrupt, EOFError):
            continue

        if idx == 0:
            break
        elif idx == 1:
            _set_str(settings, "port",         "Serial port")
            start_auto_connect(settings)   # update thread's port reference
        elif idx == 2:
            _set_int(settings, "baud",         "Baud rate")
            start_auto_connect(settings)
        elif idx == 3:
            _set_int(settings, "max_retries",  "Max retries")
        elif idx == 4:
            _set_float(settings, "wait_timeout", "Wait timeout (s)")
        elif idx == 5:
            _set_str(settings, "key_dir",      "Key directory")
        elif idx == 6:
            settings["verbose"] = not settings["verbose"]

def _set_str(s: Settings, key: str, label: str) -> None:
    try:
        v = input(f"  {label} [{s[key]}]: ").strip()
        if v:
            s[key] = v
    except (KeyboardInterrupt, EOFError):
        pass

def _set_int(s: Settings, key: str, label: str) -> None:
    try:
        v = input(f"  {label} [{s[key]}]: ").strip()
        if v:
            s[key] = int(v)
    except (ValueError, KeyboardInterrupt, EOFError):
        pass

def _set_float(s: Settings, key: str, label: str) -> None:
    try:
        v = input(f"  {label} [{s[key]}]: ").strip()
        if v:
            s[key] = float(v)
    except (ValueError, KeyboardInterrupt, EOFError):
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  Non-interactive CLI
# ─────────────────────────────────────────────────────────────────────────────

def make_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="fof_prov.py",
        description="FoF STM32 field provisioning — Raspberry Pi peer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Run without action flags to enter the interactive TUI.

        examples:
          python3 fof_prov.py                            # interactive TUI
          python3 fof_prov.py --generate                 # generate keys, then flash
          python3 fof_prov.py --private-key priv.bin     # flash one key
          python3 fof_prov.py --port /dev/ttyAMA0 \\
              --private-key priv.bin --public-key pub.bin \\
              --tx-timeout 500 --transponder-cycle 2
        """),
    )
    g = ap.add_argument_group("serial port")
    g.add_argument("--port",  default=None)
    g.add_argument("--baud",  type=int, default=None)

    g = ap.add_argument_group("key packets")
    g.add_argument("--private-key", metavar="FILE")
    g.add_argument("--public-key",  metavar="FILE")
    g.add_argument("--generate", action="store_true",
                   help="generate a SECP256R1 keypair, save to key-dir, then flash")

    g = ap.add_argument_group("config packet  (sent when any flag is provided)")
    g.add_argument("--tx-timeout",        type=int, metavar="MS")
    g.add_argument("--transponder-cycle", type=int, metavar="MS")
    g.add_argument("--challenger-cycle",  type=int, metavar="MS")
    g.add_argument("--response-wait",     type=int, metavar="MS")
    g.add_argument("--rtt-tolerance",     type=int, metavar="MS")
    g.add_argument("--watchdog",          type=int, metavar="MS")

    g = ap.add_argument_group("behaviour")
    g.add_argument("--max-retries",  type=int, default=None, metavar="N")
    g.add_argument("--wait",         type=float, default=None, metavar="SECS",
                   help="seconds to wait for device READY  (default: 30)")
    g.add_argument("--byte-timeout", type=float, default=None, metavar="SECS")
    g.add_argument("--dry-run",      action="store_true")
    g.add_argument("-v", "--verbose", action="store_true")

    return ap


def run_cli(args: argparse.Namespace, settings: Settings) -> int:
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
        try:
            priv, pub = generate_keypair(settings.key_dir_path())
            print(green(f"  ✓  private.bin  [{len(priv)} B]"))
            print(green(f"  ✓  public.bin   [{len(pub)} B]"))
            packets += [(PKT_PRIVKEY, priv, "Private Key"),
                        (PKT_PUBKEY,  pub,  "Public Key")]
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

    cfg_overrides = {
        "TxTimeoutMs":              args.tx_timeout,
        "TransponderMainCycleMs":   args.transponder_cycle,
        "ChallengerMainCycleMs":    args.challenger_cycle,
        "ResponseWaitCycleDelayMs": args.response_wait,
        "ResponseDelayToleranceMs": args.rtt_tolerance,
        "WatchdogTimeoutMs":        args.watchdog,
    }
    if any(v is not None for v in cfg_overrides.values()):
        cfg = dict(settings["config"])
        for k, v in cfg_overrides.items():
            if v is not None:
                cfg[k] = v
        packets.append((PKT_CONFIG, _pack_config(cfg), "Configuration"))

    if errors:
        for e in errors:
            print(red(f"Error: {e}"))
        return 1

    if not packets:
        print(yellow("Nothing to send.  Run without flags for interactive mode."))
        make_parser().print_usage()
        return 1

    if args.dry_run:
        print(bold(f"\nDRY RUN — {len(packets)} packet(s):"))
        for pkt_type, payload, label in packets:
            pkt = build_packet(pkt_type, payload)
            print(f"  {label}  ({len(payload)} B payload, {len(pkt)} B wire)")
            if args.verbose:
                _hex_dump(label, pkt)
        return 0

    success = do_flash(packets, settings)
    if _gs.conn:
        disconnect(commit=success)
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
    if not args.generate and all(f is None for f in action_flags):
        try:
            menu_main(settings)
        except (KeyboardInterrupt, EOFError):
            print()
            if _gs.conn:
                disconnect(commit=False)
        return 0

    return run_cli(args, settings)


if __name__ == "__main__":
    sys.exit(main())
