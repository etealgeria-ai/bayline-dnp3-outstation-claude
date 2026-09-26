"""Slow analog movement so a polling master sees a live yard."""

from __future__ import annotations

import random

from bayline.outstation import write_point
from bayline.station import Station, find_point

PF = 1.73205080757 * 0.95
Q_RATIO = 0.328684


def simulate(station: Station, now: int, dt_sec: float) -> None:
    if not station.sim_on:
        return
    dt = min(2.0, max(0.05, dt_sec))
    t1 = _on(station, 0)
    f1 = _on(station, 1) and t1
    f2 = _on(station, 2) and t1
    kv = 12.47 if t1 else 0
    a1 = 186 if f1 else 0
    a2 = 142 if f2 else 0
    v1 = _setpoint(station, 0) if f1 else 0
    v2 = _setpoint(station, 1) if f2 else 0
    hz, temp, batt = 50.12, 68.0, 125.4
    _ease(station, 0, kv, 0.012, now)
    _ease(station, 10, v1, 0.008, now)
    _ease(station, 11, v2, 0.008, now)
    _ease(station, 1, a1, 1.2, now)
    _ease(station, 2, a2, 1.1, now)
    _ease(station, 5, hz, 0.004, now)
    _ease(station, 6, temp, 0.08, now)
    _ease(station, 9, batt, 0.04, now)
    fv1 = find_point(station, "ai", 10).value if find_point(station, "ai", 10) else v1
    fv2 = find_point(station, "ai", 11).value if find_point(station, "ai", 11) else v2
    i1 = find_point(station, "ai", 1).value if find_point(station, "ai", 1) else a1
    i2 = find_point(station, "ai", 2).value if find_point(station, "ai", 2) else a2
    kw1 = fv1 * max(0, i1) * PF if f1 and fv1 > 0 else 0
    kw2 = fv2 * max(0, i2) * PF if f2 and fv2 > 0 else 0
    _ease(station, 7, kw1, 18, now)
    _ease(station, 8, kw2, 16, now)
    _ease(station, 3, kw1 + kw2, 24, now)
    _ease(station, 4, (kw1 + kw2) * Q_RATIO, 12, now)
    for load_index, counter_index in ((7, 0), (8, 1)):
        load = find_point(station, "ai", load_index)
        counter = find_point(station, "ctr", counter_index)
        if load and counter and not counter.manual:
            write_point(station, counter, counter.value + (load.value * dt * station.energy_scale) / 3600, counter.flags, now, "sim")


def _ease(station: Station, index: int, target: float, jitter: float, now: int) -> None:
    point = find_point(station, "ai", index)
    if not point or point.manual:
        return
    span = jitter
    nxt = point.value + (target - point.value) * 0.28 + (random.random() - 0.5) * span
    write_point(station, point, nxt, point.flags, now, "sim")


def _setpoint(station: Station, index: int) -> float:
    point = find_point(station, "ao", index)
    if point and 10.5 <= point.value <= 14.4:
        return point.value
    return 12.47


def _on(station: Station, index: int) -> bool:
    point = find_point(station, "bi", index)
    return bool(point and point.value >= 0.5)
