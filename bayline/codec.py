"""DNP3 link CRC, framing, and application parsing."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

START0 = 0x05
START1 = 0x64
POLY = 0xA6BC

FC_CONFIRM = 0
FC_READ = 1
FC_WRITE = 2
FC_SELECT = 3
FC_OPERATE = 4
FC_DIRECT_OPERATE = 5
FC_DIRECT_OPERATE_NR = 6
FC_IMMED_FREEZE = 7
FC_IMMED_FREEZE_NR = 8
FC_FREEZE_CLEAR = 9
FC_FREEZE_CLEAR_NR = 10
FC_COLD_RESTART = 13
FC_WARM_RESTART = 14
FC_ENABLE_UNSOL = 20
FC_DISABLE_UNSOL = 21
FC_DELAY_MEASURE = 23
FC_RECORD_TIME = 24
FC_AUTH_REQUEST = 32
FC_RESPONSE = 129
FC_UNSOLICITED = 130
FC_AUTH_RESPONSE = 131

DATA_FUNCTIONS = {2, 3, 4, 5, 6, 32, 129, 130, 131}

SIZES = {
    (1, 2): 1,
    (2, 1): 1,
    (2, 2): 7,
    (2, 3): 3,
    (10, 2): 1,
    (11, 1): 1,
    (11, 2): 7,
    (12, 1): 11,
    (20, 1): 5,
    (20, 2): 3,
    (20, 5): 4,
    (20, 6): 2,
    (21, 1): 5,
    (21, 2): 3,
    (21, 5): 4,
    (21, 6): 2,
    (22, 1): 5,
    (22, 2): 3,
    (22, 5): 11,
    (22, 6): 9,
    (30, 1): 5,
    (30, 2): 3,
    (30, 3): 4,
    (30, 4): 2,
    (30, 5): 5,
    (32, 1): 5,
    (32, 2): 3,
    (32, 3): 11,
    (32, 4): 9,
    (32, 5): 5,
    (32, 7): 11,
    (40, 1): 5,
    (40, 2): 3,
    (40, 3): 5,
    (41, 1): 5,
    (41, 2): 3,
    (41, 3): 5,
    (42, 1): 5,
    (42, 2): 3,
    (42, 3): 11,
    (42, 5): 5,
    (42, 7): 11,
    (50, 1): 6,
    (52, 1): 2,
    (52, 2): 2,
    (121, 1): 7,
    (122, 1): 7,
    (122, 2): 13,
}

FC_NAME = {
    0: "CONFIRM",
    1: "READ",
    2: "WRITE",
    3: "SELECT",
    4: "OPERATE",
    5: "DIRECT_OPERATE",
    6: "DIRECT_OPERATE_NR",
    7: "IMMED_FREEZE",
    8: "IMMED_FREEZE_NR",
    9: "FREEZE_CLEAR",
    10: "FREEZE_CLEAR_NR",
    13: "COLD_RESTART",
    14: "WARM_RESTART",
    20: "ENABLE_UNSOLICITED",
    21: "DISABLE_UNSOLICITED",
    23: "DELAY_MEASURE",
    24: "RECORD_CURRENT_TIME",
    32: "AUTH_REQUEST",
    129: "RESPONSE",
    130: "UNSOLICITED_RESPONSE",
    131: "AUTH_RESPONSE",
}

LINK_PRI = {0: "RESET_LINK", 1: "RESET_USER", 2: "TEST_LINK", 3: "CONFIRMED_USER_DATA", 4: "UNCONFIRMED_USER_DATA", 9: "REQUEST_LINK_STATUS"}
LINK_SEC = {0: "ACK", 1: "NACK", 11: "LINK_STATUS", 15: "NOT_SUPPORTED"}
GROUP_NAME = {
    0: "Device attribute",
    1: "Binary input",
    2: "Binary input event",
    10: "Binary output",
    11: "Binary output event",
    12: "CROB",
    20: "Counter",
    21: "Frozen counter",
    22: "Counter event",
    30: "Analog input",
    32: "Analog input event",
    40: "Analog output",
    41: "Analog output block",
    42: "Analog output event",
    50: "Time and date",
    52: "Time delay",
    60: "Class",
    80: "Internal indications",
    120: "Authentication",
}


def crc16_dnp(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ POLY if crc & 1 else crc >> 1
    return (crc ^ 0xFFFF) & 0xFFFF


def to_hex(data: bytes | bytearray, gap: str = " ") -> str:
    return gap.join(f"{b & 0xFF:02x}" for b in data)


def parse_hex(text: str) -> bytes | None:
    cleaned = "".join(ch for ch in text if ch in "0123456789abcdefABCDEF")
    if not cleaned or len(cleaned) % 2:
        return None
    return bytes(int(cleaned[i : i + 2], 16) for i in range(0, len(cleaned), 2))


def object_size(group: int, variation: int) -> int | None:
    return SIZES.get((group, variation))


def is_packed(group: int, variation: int) -> bool:
    return (group == 1 and variation == 1) or (group == 10 and variation == 1) or (group == 80 and variation == 1)


def push_u8(out: bytearray, n: int) -> None:
    out.append(n & 0xFF)


def push_u16(out: bytearray, n: int) -> None:
    out.append(n & 0xFF)
    out.append((n >> 8) & 0xFF)


def push_u32(out: bytearray, n: int) -> None:
    n &= 0xFFFFFFFF
    out.extend((n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >> 24) & 0xFF))


def push_i16(out: bytearray, n: int) -> None:
    push_u16(out, n + 0x10000 if n < 0 else n)


def push_i32(out: bytearray, n: int) -> None:
    push_u32(out, n & 0xFFFFFFFF)


def push_f32(out: bytearray, n: float) -> None:
    out.extend(struct.pack("<f", float(n)))


def push_time48(out: bytearray, ms: int) -> None:
    t = max(0, int(ms))
    for _ in range(6):
        out.append(t & 0xFF)
        t >>= 8


def read_uint(data: bytes, offset: int, width: int) -> int:
    n = 0
    for i in range(width):
        n |= data[offset + i] << (8 * i)
    return n


def read_i16(data: bytes, offset: int) -> int:
    n = data[offset] | (data[offset + 1] << 8)
    return n - 0x10000 if n & 0x8000 else n


def read_i32(data: bytes, offset: int) -> int:
    n = read_uint(data, offset, 4)
    return n - 0x100000000 if n & 0x80000000 else n


def read_f32(data: bytes, offset: int) -> float:
    return struct.unpack_from("<f", data, offset)[0]


def read_time48(data: bytes, offset: int) -> int:
    n = 0
    for i in range(5, -1, -1):
        n = (n << 8) | data[offset + i]
    return n


def _crc_bytes(data: bytes) -> bytes:
    c = crc16_dnp(data)
    return bytes((c & 0xFF, (c >> 8) & 0xFF))


def encode_frame(control: int, dest: int, src: int, user: bytes) -> bytes:
    if len(user) > 250:
        raise ValueError("DNP3 user data exceeds 250 octets")
    header = bytes((START0, START1, 5 + len(user), control & 0xFF, dest & 0xFF, (dest >> 8) & 0xFF, src & 0xFF, (src >> 8) & 0xFF))
    parts = bytearray(header)
    parts.extend(_crc_bytes(header))
    for i in range(0, len(user), 16):
        block = user[i : i + 16]
        parts.extend(block)
        parts.extend(_crc_bytes(block))
    return bytes(parts)


def frame_size(length_byte: int) -> int:
    user_len = length_byte - 5
    if user_len < 0 or user_len > 250:
        return -1
    blocks = 0 if user_len == 0 else (user_len + 15) // 16
    return 10 + user_len + blocks * 2


@dataclass
class LinkFrame:
    ok: bool
    error: str = ""
    control: int = 0
    dest: int = 0
    src: int = 0
    user: bytes = b""
    crc_ok: bool = False


def decode_frame(data: bytes) -> LinkFrame:
    def fail(error: str) -> LinkFrame:
        return LinkFrame(False, error)

    if len(data) < 10:
        return fail("Truncated link header")
    if data[0] != START0 or data[1] != START1:
        return fail("Bad start octets (expected 05 64)")
    length = data[2]
    if length < 5:
        return fail("Length shorter than the link header")
    user_len = length - 5
    crc_ok = crc16_dnp(data[:8]) == (data[8] | (data[9] << 8))
    control, dest, src = data[3], data[4] | (data[5] << 8), data[6] | (data[7] << 8)
    user = bytearray(user_len)
    offset = 10
    filled = 0
    while filled < user_len:
        take = min(16, user_len - filled)
        if offset + take + 2 > len(data):
            return fail("Truncated data block")
        block = data[offset : offset + take]
        got = data[offset + take] | (data[offset + take + 1] << 8)
        if crc16_dnp(block) != got:
            crc_ok = False
        user[filled : filled + take] = block
        filled += take
        offset += take + 2
    if offset != len(data):
        return LinkFrame(False, "Trailing octets after the frame", control, dest, src, bytes(user), crc_ok)
    return LinkFrame(True, "", control, dest, src, bytes(user), crc_ok)


@dataclass
class ParsedItem:
    index: int | None
    raw: bytes


@dataclass
class ParsedObject:
    group: int
    variation: int
    qualifier: int
    all: bool = False
    start: int = 0
    stop: int = 0
    indexes: list[int] = field(default_factory=list)
    items: list[ParsedItem] = field(default_factory=list)
    offset: int = 0
    end: int = 0


@dataclass
class ParsedApdu:
    ok: bool
    error: str = ""
    fir: bool = False
    fin: bool = False
    con: bool = False
    uns: bool = False
    seq: int = 0
    transport_fir: bool = False
    transport_fin: bool = False
    transport_seq: int = 0
    fc: int = 0
    iin1: int = 0
    iin2: int = 0
    has_iin: bool = False
    objects: list[ParsedObject] = field(default_factory=list)


def parse_apdu(user: bytes) -> ParsedApdu:
    empty = ParsedApdu(False)
    if len(user) < 3:
        empty.error = "User data shorter than a transport + application header"
        return empty
    th, ac, fc = user[0], user[1], user[2]
    has_iin = fc in (FC_RESPONSE, FC_UNSOLICITED, FC_AUTH_RESPONSE)
    cursor = 3
    iin1 = iin2 = 0
    if has_iin:
        if len(user) < 5:
            return ParsedApdu(False, "Response missing IIN", fc=fc, transport_fir=bool(th & 0x80), transport_fin=bool(th & 0x40), transport_seq=th & 0x3F)
        iin1, iin2 = user[3], user[4]
        cursor = 5
    expects = fc in DATA_FUNCTIONS
    objects: list[ParsedObject] = []

    def finish(ok: bool, error: str = "") -> ParsedApdu:
        return ParsedApdu(
            ok,
            error,
            fir=bool(ac & 0x80),
            fin=bool(ac & 0x40),
            con=bool(ac & 0x20),
            uns=bool(ac & 0x10),
            seq=ac & 0x0F,
            transport_fir=bool(th & 0x80),
            transport_fin=bool(th & 0x40),
            transport_seq=th & 0x3F,
            fc=fc,
            iin1=iin1,
            iin2=iin2,
            has_iin=has_iin,
            objects=objects,
        )

    while cursor < len(user):
        origin = cursor
        if cursor + 3 > len(user):
            return finish(False, "Truncated object header")
        group, variation, qualifier = user[cursor], user[cursor + 1], user[cursor + 2]
        cursor += 3
        prefix, rng = (qualifier >> 4) & 0x0F, qualifier & 0x0F
        obj = ParsedObject(group, variation, qualifier, all=rng == 6, offset=origin)
        count = 0
        indexed = False
        if rng in (0, 1, 2):
            width = (1, 2, 4)[rng]
            if cursor + width * 2 > len(user):
                return finish(False, "Truncated range")
            obj.start = read_uint(user, cursor, width)
            obj.stop = read_uint(user, cursor + width, width)
            cursor += width * 2
            if obj.stop < obj.start:
                return finish(False, "Range stop is before start")
            count = obj.stop - obj.start + 1
            if count > 1024:
                return finish(False, "Range too large")
            obj.indexes = list(range(obj.start, obj.stop + 1))
        elif rng == 6:
            count = 0
        elif rng in (7, 8, 9):
            width = (1, 2, 4)[rng - 7]
            if cursor + width > len(user):
                return finish(False, "Truncated count")
            count = read_uint(user, cursor, width)
            cursor += width
            indexed = prefix in (1, 2, 3)
            if not indexed:
                obj.indexes = list(range(count))
        elif rng == 11 and prefix == 5:
            if cursor >= len(user):
                return finish(False, "Truncated free-format count")
            count = user[cursor]
            cursor += 1
        else:
            return finish(False, f"Unsupported qualifier 0x{qualifier:02x}")
        if count > 1024:
            return finish(False, "Range too large")
        if not expects or count == 0 or variation == 0 or group == 60:
            obj.end = cursor
            objects.append(obj)
            continue
        if rng == 11 and prefix == 5:
            for _ in range(count):
                if cursor + 2 > len(user):
                    return finish(False, "Truncated sized object")
                sz = user[cursor] | (user[cursor + 1] << 8)
                cursor += 2
                if cursor + sz > len(user):
                    return finish(False, "Truncated sized object body")
                obj.items.append(ParsedItem(None, user[cursor : cursor + sz]))
                cursor += sz
            obj.end = cursor
            objects.append(obj)
            continue
        if is_packed(group, variation):
            nbytes = (count + 7) // 8
            if cursor + nbytes > len(user):
                return finish(False, "Truncated packed bit field")
            obj.items.append(ParsedItem(obj.start, user[cursor : cursor + nbytes]))
            cursor += nbytes
            obj.end = cursor
            objects.append(obj)
            continue
        size = object_size(group, variation)
        index_width = {1: 1, 2: 2, 3: 4}.get(prefix, 0) if indexed or prefix in (1, 2, 3) else 0
        if rng in (0, 1, 2):
            index_width = 0
        if size is None:
            return finish(False, f"No size for group {group} variation {variation}")
        for i in range(count):
            index: int | None = obj.indexes[i] if i < len(obj.indexes) else None
            if index_width:
                if cursor + index_width > len(user):
                    return finish(False, "Truncated object index")
                index = read_uint(user, cursor, index_width)
                cursor += index_width
                obj.indexes.append(index)
            if cursor + size > len(user):
                return finish(False, "Truncated object body")
            obj.items.append(ParsedItem(index, user[cursor : cursor + size]))
            cursor += size
        obj.end = cursor
        objects.append(obj)
    return finish(True)


def iin_short(iin1: int, iin2: int) -> str:
    names = []
    for i, name in enumerate(["ALL", "C1", "C2", "C3", "TIME", "LOCAL", "TROUBLE", "RESTART"]):
        if iin1 & (1 << i):
            names.append(name)
    for i, name in enumerate(["BAD_FC", "UNK_OBJ", "PARAM", "OVF", "BUSY", "CFG"]):
        if iin2 & (1 << i):
            names.append(name)
    return ",".join(names) if names else "none"


def describe_frame(data: bytes) -> tuple[str, str, bool]:
    link = decode_frame(data)
    if not link.ok and not link.user:
        return link.error or "Bad frame", to_hex(data), False
    pri = bool(link.control & 0x40)
    func = link.control & 0x0F
    fname = (LINK_PRI if pri else LINK_SEC).get(func, f"FC_{func}")
    if not link.crc_ok:
        return f"CRC FAIL · {fname}", to_hex(data), False
    if not link.user:
        return f"{fname}  DST {link.dest}  SRC {link.src}", to_hex(data), link.ok
    apdu = parse_apdu(link.user)
    fc_name = FC_NAME.get(apdu.fc, f"FC_{apdu.fc}")
    titles = []
    for obj in apdu.objects:
        if obj.group == 60:
            titles.append(f"Class {0 if obj.variation == 1 else obj.variation - 1}")
        elif obj.group == 120 and obj.variation == 1:
            titles.append("Challenge")
        elif obj.group == 120 and obj.variation == 3:
            titles.append("Aggressive")
        else:
            titles.append(f"{GROUP_NAME.get(obj.group, 'Group ' + str(obj.group))} g{obj.group}v{obj.variation}")
    core = " · ".join(titles[:4])
    iin = f"  IIN {iin_short(apdu.iin1, apdu.iin2)}" if apdu.has_iin else ""
    summary = f"{fc_name}{(' · ' + core) if core else ''}{iin}"
    return summary, to_hex(data), link.ok and link.crc_ok and apdu.ok
