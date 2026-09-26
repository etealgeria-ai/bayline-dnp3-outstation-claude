"""Riverside 12 kV point database and SAv5 session."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from bayline.crypto import CHALLENGE_LEN, MAC_LEN, SESSION_KEY_LEN, UPDATE_KEY_LEN

BI_ONLINE = 0x01
BI_STATE = 0x80
AI_ONLINE = 0x01
CTR_ONLINE = 0x01
RESTART_FLAG = 0x02
PROVISIONED_USER = 1
MAL = 4
KWA = 2
UK_METHOD = 4
KEY_OK = 1
KEY_NOT_INIT = 2
KEY_AUTH_FAIL = 4
ERR_AUTH_FAILED = 1
ERR_UNEXPECTED = 2
ERR_AGGRESSIVE = 4
ERR_AUTHORIZATION = 7
ERR_UK_METHOD = 8
ERR_SIGNATURE = 9
ERR_UNKNOWN_USER = 11
ERR_KEY_STATUS_LIMIT = 12
MAX_KEY_STATUS_REQUESTS = 2
CRITICAL = {3, 4, 5, 6, 7, 8, 9, 10, 13, 14}


@dataclass
class Point:
    kind: str
    index: int
    name: str
    units: str
    value: float
    flags: int
    clazz: int
    deadband: float
    static_var: int
    event_var: int
    last_event_value: float
    last_flags: int
    feedback: int | None = None
    op_counter: int | None = None
    frozen: float | None = None
    manual: bool = False
    low: float | None = None
    high: float | None = None


@dataclass
class DnpEvent:
    id: int
    kind: str
    index: int
    value: float
    flags: int
    time: int
    clazz: int
    variation: int
    held: bool = False


@dataclass
class SelectArm:
    group: int
    variation: int
    index: int
    body: bytes
    deadline: int


@dataclass
class PendingConfirm:
    seq: int
    unsol: bool
    event_ids: list[int]
    deadline: int


@dataclass
class OsSession:
    status: int = KEY_NOT_INIT
    ksq: int = 0
    csq: int = 1
    accepted_csq: int = 0
    control_key: bytes = b""
    monitor_key: bytes = b""
    key_challenge: bytes = b""
    last_status_mac: bytes = b""
    challenge_apdu: bytes = b""
    keys_at: int = 0
    key_status_count: int = 0
    auth_count: int = 0
    last_key_status: bytes = b""
    last_key_change: bytes = b""


@dataclass
class PendingAuth:
    seq: int
    csq: int
    user: int
    challenge_apdu: bytes
    critical_apdu: bytes
    deadline: int


@dataclass
class PendingUpdateKey:
    ksq: int
    user: int
    outstation_challenge: bytes


@dataclass
class AuthPolicy:
    controls: bool = True
    crob: bool = True
    analog: bool = True
    direct_operate: bool = True
    direct_operate_nr: bool = True
    select_operate: bool = True
    cold_restart: bool = True
    warm_restart: bool = True
    unsolicited: bool = True
    assign_class: bool = True
    initialize: bool = True
    time_write: bool = False
    file_transfer: bool = True


ROLES = {
    "Viewer": (2, False),
    "Operator": (1, True),
    "Engineer": (3, True),
    "Installer": (4, True),
    "SECADM": (5, True),
}


def role_can_control(sav: Sav5) -> bool:
    return ROLES.get(sav.role, (sav.user, True))[1]


@dataclass
class Sav5:
    enabled: bool = True
    version: int = 5
    aggressive: bool = False
    role: str = "Operator"
    user: int = PROVISIONED_USER
    update_key: bytes = field(default_factory=lambda: os.urandom(UPDATE_KEY_LEN))
    os: OsSession = field(default_factory=OsSession)
    pending: PendingAuth | None = None
    update_pending: PendingUpdateKey | None = None
    bypass: bool = False
    policy: AuthPolicy = field(default_factory=AuthPolicy)
    challenge_timeout_ms: int = 5000
    session_lifetime_s: int = 3600
    max_key_status_requests: int = MAX_KEY_STATUS_REQUESTS
    max_auth_messages: int = 1000
    max_error_messages: int = 5
    error_burst: int = 0
    allow_remote_update: bool = False
    # Lab fault injection (off by default).
    lab_challenge_reads: bool = False   # treat Read as critical, so every poll is challenged
    lab_fail_auth: int = 0              # reject this many otherwise-valid authentications
    ok_count: int = 0
    fail_count: int = 0
    challenges_sent: int = 0
    challenges_rx: int = 0
    key_changes: int = 0
    last_error: int = 0
    last_user: int = 0
    last_auth_time: int = 0
    last_result: str = "SAv5 selected. Session keys are not initialized."


@dataclass
class AuthProfile:
    version: int
    mal: int
    mac_len: int
    kwa: int
    key_len: int
    challenge_len: int
    label: str
    mac_name: str
    wrap_name: str


def auth_profile(sav: Sav5) -> AuthProfile:
    if sav.version == 2:
        return AuthProfile(2, 5, 8, 1, 16, 8, "SAv2", "HMAC-SHA-1-8", "AES-128")
    return AuthProfile(5, 4, 16, 2, 32, 16, "SAv5", "HMAC-SHA-256-16", "AES-256")


def update_key_material(sav: Sav5) -> bytes:
    return sav.update_key[: auth_profile(sav).key_len]


@dataclass
class LogItem:
    id: int
    time: int
    direction: str
    summary: str
    detail: str
    hex: str
    ok: bool


@dataclass
class Station:
    name: str = "Riverside 12 kV"
    location: str = "Riverside Substation"
    outstation: int = 4
    master: int = 100
    link_reset: bool = False
    expect_fcb: bool = True
    unsol_seq: int = 0
    tx_transport: int = 0
    restart: bool = True
    need_time: bool = True
    trouble: bool = False
    local: bool = False
    overflow: bool = False
    time_offset: int = 0
    select: SelectArm | None = None
    pending_confirm: PendingConfirm | None = None
    unsol: dict[str, bool] = field(default_factory=lambda: {"c1": False, "c2": False, "c3": False})
    confirm_timeout: int = 8000
    select_timeout: int = 10000
    event_max: int = 80
    proc_delay: int = 18
    energy_scale: float = 4
    points: list[Point] = field(default_factory=list)
    events: list[DnpEvent] = field(default_factory=list)
    next_event_id: int = 1
    log: list[LogItem] = field(default_factory=list)
    next_log_id: int = 1
    sim_on: bool = True
    scenario: str = "normal"
    scenario_since: int = 0
    fault_stage: int = 0
    sav5: Sav5 = field(default_factory=Sav5)
    security: list[int] = field(default_factory=lambda: [0] * 18)
    security_sent: list[int] = field(default_factory=lambda: [0] * 18)


def _flags(kind: str, closed: bool) -> int:
    if kind in ("bi", "bo"):
        return (BI_ONLINE | (BI_STATE if closed else 0)) | RESTART_FLAG
    if kind == "ctr":
        return CTR_ONLINE | RESTART_FLAG
    return AI_ONLINE | RESTART_FLAG


def _point(kind, index, name, value, units, clazz, deadband, static_var, event_var, feedback=None, op_counter=None) -> Point:
    flags = _flags(kind, value >= 0.5)
    return Point(kind, index, name, units, value, flags, clazz, deadband, static_var, event_var, value, flags, feedback, op_counter)


def create_station() -> Station:
    rows = [
        _point("bi", 0, "52-T1 transformer breaker", 1, "", 1, 0, 2, 2),
        _point("bi", 1, "52-F1 feeder breaker", 1, "", 1, 0, 2, 2),
        _point("bi", 2, "52-F2 feeder breaker", 1, "", 1, 0, 2, 2),
        _point("bi", 3, "89-BS bus tie", 1, "", 1, 0, 2, 2),
        _point("bi", 4, "27 bus undervoltage", 0, "", 1, 0, 2, 2),
        _point("bi", 5, "50-F1 instantaneous OC", 0, "", 1, 0, 2, 2),
        _point("bi", 6, "50-F2 instantaneous OC", 0, "", 1, 0, 2, 2),
        _point("bi", 7, "79-F1 recloser lockout", 0, "", 1, 0, 2, 2),
        _point("bi", 8, "63-T1 sudden pressure", 0, "", 1, 0, 2, 2),
        _point("bi", 9, "Station alarm", 0, "", 1, 0, 2, 2),
        _point("bi", 10, "Remote / local", 1, "", 1, 0, 2, 2),
        _point("bi", 11, "T1 high oil temperature", 0, "", 1, 0, 2, 2),
        _point("bo", 0, "52-T1 control", 1, "", 0, 0, 2, 2, feedback=0),
        _point("bo", 1, "52-F1 control", 1, "", 0, 0, 2, 2, feedback=1, op_counter=2),
        _point("bo", 2, "52-F2 control", 1, "", 0, 0, 2, 2, feedback=2, op_counter=3),
        _point("bo", 3, "89-BS control", 1, "", 0, 0, 2, 2, feedback=3),
        _point("ai", 0, "Bus voltage", 12.47, "kV", 2, 0.08, 5, 5),
        _point("ai", 1, "Feeder 1 current", 186, "A", 2, 10, 5, 5),
        _point("ai", 2, "Feeder 2 current", 142, "A", 2, 10, 5, 5),
        _point("ai", 3, "Transformer load", 6726, "kW", 2, 250, 5, 5),
        _point("ai", 4, "Transformer reactive", 2210, "kVAr", 2, 120, 5, 5),
        _point("ai", 5, "Frequency", 50.12, "Hz", 2, 0.03, 5, 7),
        _point("ai", 6, "T1 oil temperature", 68, "°C", 2, 1.5, 5, 5),
        _point("ai", 7, "Feeder 1 load", 3816, "kW", 2, 160, 5, 5),
        _point("ai", 8, "Feeder 2 load", 2910, "kW", 2, 160, 5, 5),
        _point("ai", 9, "Battery", 125.4, "VDC", 2, 0.8, 5, 5),
        _point("ai", 10, "Feeder 1 voltage", 12.47, "kV", 2, 0.05, 5, 5),
        _point("ai", 11, "Feeder 2 voltage", 12.47, "kV", 2, 0.05, 5, 5),
        _point("ctr", 0, "Feeder 1 energy", 184320, "kWh", 3, 50, 1, 1),
        _point("ctr", 1, "Feeder 2 energy", 142110, "kWh", 3, 50, 1, 1),
        _point("ctr", 2, "Feeder 1 operations", 146, "", 3, 1, 1, 5),
        _point("ctr", 3, "Feeder 2 operations", 121, "", 3, 1, 1, 5),
        _point("ao", 0, "Feeder 1 regulator setpoint", 12.47, "kV", 0, 0.01, 3, 5),
        _point("ao", 1, "Feeder 2 regulator setpoint", 12.47, "kV", 0, 0.01, 3, 5),
    ]
    for row in rows:
        if row.kind == "ao":
            row.low, row.high = 10.5, 14.4
    station = Station(points=rows)
    station.security[17] = 1
    station.security_sent[17] = 1
    return station


def find_point(station: Station, kind: str, index: int) -> Point | None:
    for point in station.points:
        if point.kind == kind and point.index == index:
            return point
    return None


def points_of(station: Station, kind: str) -> list[Point]:
    return sorted((p for p in station.points if p.kind == kind), key=lambda p: p.index)


def sync_binary_flag(point: Point) -> None:
    if point.kind not in ("bi", "bo"):
        return
    if point.value >= 0.5:
        point.flags |= BI_STATE
    else:
        point.flags &= ~BI_STATE


def outstation_now(station: Station, now: int) -> int:
    return now + station.time_offset


def reset_session_keys(sav: Sav5) -> None:
    ksq, csq = sav.os.ksq, sav.os.csq
    sav.os = OsSession(ksq=ksq, csq=csq)
    sav.pending = None
    sav.update_pending = None
    sav.bypass = False


def is_critical(fc: int) -> bool:
    return fc in CRITICAL


POINT_KINDS = ("bi", "bo", "ai", "ao", "ctr")


def points_to_config(station: Station) -> dict:
    """Serialise the point database and addressing to a JSON-ready dict."""
    rows = []
    for p in station.points:
        row = {
            "kind": p.kind,
            "index": p.index,
            "name": p.name,
            "value": p.value,
            "units": p.units,
            "class": p.clazz,
            "deadband": p.deadband,
            "static_var": p.static_var,
            "event_var": p.event_var,
        }
        for key in ("feedback", "op_counter", "low", "high"):
            if getattr(p, key) is not None:
                row[key] = getattr(p, key)
        rows.append(row)
    return {
        "name": station.name,
        "outstation": station.outstation,
        "master": station.master,
        "event_max": station.event_max,
        "simulate": station.sim_on,
        "points": rows,
    }


def station_from_config(config: dict) -> Station:
    """Build a station from a dict produced by points_to_config (or written by hand).

    Raises ValueError with a readable message on the first bad entry.
    """
    if not isinstance(config, dict) or not isinstance(config.get("points"), list) or not config["points"]:
        raise ValueError("Config needs a non-empty 'points' list.")
    rows: list[Point] = []
    seen: set[tuple[str, int]] = set()
    for n, raw in enumerate(config["points"]):
        where = f"points[{n}]"
        if not isinstance(raw, dict):
            raise ValueError(f"{where} must be an object.")
        kind = raw.get("kind")
        if kind not in POINT_KINDS:
            raise ValueError(f"{where}.kind must be one of {', '.join(POINT_KINDS)}.")
        index = raw.get("index")
        if not isinstance(index, int) or not 0 <= index <= 65535:
            raise ValueError(f"{where}.index must be an integer 0..65535.")
        if (kind, index) in seen:
            raise ValueError(f"{where}: duplicate {kind} {index}.")
        seen.add((kind, index))
        clazz = raw.get("class", 1 if kind in ("bi", "ai", "ctr") else 0)
        if clazz not in (0, 1, 2, 3):
            raise ValueError(f"{where}.class must be 0..3.")
        value = float(raw.get("value", 0))
        defaults = {"bi": (2, 2), "bo": (2, 2), "ai": (5, 5), "ao": (3, 5), "ctr": (1, 1)}[kind]
        point = _point(
            kind,
            index,
            str(raw.get("name", f"{kind.upper()} {index}")),
            value,
            str(raw.get("units", "")),
            clazz,
            float(raw.get("deadband", 0)),
            int(raw.get("static_var", defaults[0])),
            int(raw.get("event_var", defaults[1])),
            feedback=raw.get("feedback"),
            op_counter=raw.get("op_counter"),
        )
        point.low = raw.get("low")
        point.high = raw.get("high")
        rows.append(point)
    station = Station(points=rows)
    station.name = str(config.get("name", station.name))
    for key in ("outstation", "master"):
        if key in config:
            value = config[key]
            if not isinstance(value, int) or not 0 <= value <= 65519:
                raise ValueError(f"{key} must be a DNP3 address 0..65519.")
            setattr(station, key, value)
    if "event_max" in config:
        station.event_max = max(4, int(config["event_max"]))
    # The built-in yard model only makes sense for the built-in database.
    station.sim_on = bool(config.get("simulate", False))
    station.security[17] = 1
    station.security_sent[17] = 1
    return station
