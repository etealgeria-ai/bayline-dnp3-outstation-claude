"""Lab tooling: link fault injection and wire capture.

Faults act on complete outgoing link frames at the TCP layer, after the
outstation has built them, so the protocol state inside the outstation stays
correct. That is what a real noisy channel does: the device thinks it answered.
"""

from __future__ import annotations

import json
import random
import threading
import time
from dataclasses import asdict, dataclass, field

from bayline.codec import describe_frame


@dataclass
class Faults:
    drop_pct: float = 0.0        # outgoing frames silently lost
    corrupt_pct: float = 0.0     # one CRC byte flipped, so the master must reject it
    duplicate_pct: float = 0.0   # frame sent twice
    delay_ms: int = 0            # fixed extra latency before each reply
    jitter_ms: int = 0           # random extra latency, 0..jitter_ms
    silent: bool = False         # device answers nothing (dead RTU)
    seed: int | None = None
    _rng: random.Random = field(default_factory=random.Random, repr=False, compare=False)

    NUMERIC = ("drop_pct", "corrupt_pct", "duplicate_pct", "delay_ms", "jitter_ms")

    def __post_init__(self) -> None:
        self.reseed(self.seed)

    def reseed(self, seed: int | None) -> None:
        self.seed = seed
        self._rng = random.Random(seed)

    def set(self, name: str, value) -> str | None:
        if name == "silent":
            self.silent = bool(value)
            return None
        if name == "seed":
            self.reseed(None if value in (None, "") else int(value))
            return None
        if name not in self.NUMERIC:
            return f"Unknown fault {name}."
        try:
            number = float(value)
        except (TypeError, ValueError):
            return f"{name} must be a number."
        if name.endswith("_pct") and not 0 <= number <= 100:
            return f"{name} must be 0..100."
        if name.endswith("_ms") and not 0 <= number <= 60000:
            return f"{name} must be 0..60000."
        setattr(self, name, int(number) if name.endswith("_ms") else number)
        return None

    def active(self) -> bool:
        return self.silent or any(getattr(self, n) for n in self.NUMERIC)

    def as_dict(self) -> dict:
        data = asdict(self)
        data.pop("_rng", None)
        return data

    def latency_s(self) -> float:
        extra = self._rng.randint(0, self.jitter_ms) if self.jitter_ms else 0
        return (self.delay_ms + extra) / 1000

    def apply(self, frames: list[bytes]) -> list[tuple[bytes, str]]:
        """Return (frame, label) for every frame the outstation built.

        label is '' for a clean frame, 'corrupt' or 'duplicate' for frames that
        go on the wire altered or twice, and 'dropped' or 'silent' for frames
        that must NOT be sent (kept so the capture shows what was withheld).
        """
        if self.silent:
            return [(frame, "silent") for frame in frames]
        out: list[tuple[bytes, str]] = []
        for frame in frames:
            if self._roll(self.drop_pct):
                out.append((frame, "dropped"))
                continue
            label = ""
            if self._roll(self.corrupt_pct) and len(frame) >= 10:
                frame = _corrupt(frame, self._rng)
                label = "corrupt"
            out.append((frame, label))
            if self._roll(self.duplicate_pct):
                out.append((frame, "duplicate"))
        return out

    @staticmethod
    def on_wire(result: list[tuple[bytes, str]]) -> list[bytes]:
        return [frame for frame, label in result if label not in ("dropped", "silent")]

    def _roll(self, pct: float) -> bool:
        return pct > 0 and self._rng.random() * 100 < pct


def _corrupt(frame: bytes, rng: random.Random) -> bytes:
    """Flip one bit in a CRC so the frame is well-formed but fails its check."""
    data = bytearray(frame)
    crc_positions = [8, 9]  # header CRC
    at = 10
    while at < len(data):
        block = min(16, len(data) - at - 2)
        if block <= 0:
            break
        crc_positions += [at + block, at + block + 1]
        at += block + 2
    pos = rng.choice(crc_positions)
    data[pos] ^= 1 << rng.randint(0, 7)
    return bytes(data)


class Capture:
    """Append-only JSON Lines record of every frame on the wire, for test evidence.

    One object per line: time (ISO 8601 UTC, ms), dir (rx/tx), peer, hex,
    summary, and fault when a frame was altered or dropped on purpose.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._handle = open(path, "a", encoding="utf-8")
        self.count = 0

    def write(self, direction: str, peer: str, frame: bytes, fault: str = "") -> None:
        summary, _detail, ok = describe_frame(frame)
        now = time.time()
        record = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now * 1000) % 1000:03d}Z",
            "dir": direction,
            "peer": peer,
            "hex": frame.hex(),
            "summary": summary,
            "ok": ok,
        }
        if fault:
            record["fault"] = fault
        self._emit(record)

    def note(self, peer: str, text: str) -> None:
        now = time.time()
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now * 1000) % 1000:03d}Z"
        self._emit({"time": stamp, "dir": "note", "peer": peer, "summary": text})

    def _emit(self, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"))
        with self._lock:
            self._handle.write(line + "\n")
            self._handle.flush()
            self.count += 1

    def close(self) -> None:
        with self._lock:
            try:
                self._handle.close()
            except OSError:
                pass
