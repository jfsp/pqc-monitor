"""
PQC-Monitor: time-bucketed trend aggregation.

The Trends tab used to plot one point per scan run on a category axis, so
runs a few minutes apart and runs months apart were spaced equally, and
partial runs (one-domain rescans, ad-hoc batches) were averaged as if they
described the whole portfolio. This module replaces that with calendar
buckets on a real time axis.

Two aggregation modes:

  snapshot  (default) state of the portfolio at the end of each bucket.
            Every in-scope domain contributes its most recent assessment
            made up to that moment (carry-forward). A domain whose latest
            assessment is older than ``stale_days`` drops out, so domains
            that stopped being scanned do not freeze the average forever.
            "monitored" is therefore the size of the live portfolio.

  activity  only assessments made inside the bucket (latest per domain in
            the bucket). Shows scan activity; buckets without scans are
            empty (None metrics).

Every bucket also carries ``assessed`` (distinct domains assessed inside
the bucket) and ``new_domains`` (domains assessed for the first time), in
both modes.

Granularity is day | week (ISO, Monday) | month | quarter, all in UTC.
``choose_granularity`` picks one from the shortest scan-schedule interval
and the span of the requested range; the caller may override it.

Pure functions only (no DB, no Flask) so the logic is unit-testable.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

GRANULARITIES = ("day", "week", "month", "quarter")
MODES = ("snapshot", "activity")
LEVELS = ("critical", "weak", "moderate", "ready")

# Auto granularity aims for a readable number of points.
AUTO_MIN_BUCKETS = 8
AUTO_MAX_BUCKETS = 90
# Hard cap for manual choices (e.g. "day" over several years).
HARD_MAX_BUCKETS = 1000

DEFAULT_INTERVAL_DAYS = 30
STALE_FACTOR = 3
STALE_MIN_DAYS = 7
STALE_MAX_DAYS = 400

RANGE_DAYS = {"30d": 30, "90d": 90, "180d": 180, "365d": 365, "730d": 730}


# ── Time helpers ─────────────────────────────────────────────────────────────

def parse_ts(value) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp; naive values are taken as UTC."""
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            try:
                dt = datetime.fromisoformat(s[:19])
            except ValueError:
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def floor_ts(dt: datetime, gran: str) -> datetime:
    d = dt.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    if gran == "day":
        return d
    if gran == "week":
        return d - timedelta(days=d.weekday())
    if gran == "month":
        return d.replace(day=1)
    if gran == "quarter":
        return d.replace(day=1, month=((d.month - 1) // 3) * 3 + 1)
    raise ValueError(f"unknown granularity {gran!r}")


def next_ts(dt: datetime, gran: str) -> datetime:
    """Start of the bucket after the one starting at ``dt`` (dt is floored)."""
    if gran == "day":
        return dt + timedelta(days=1)
    if gran == "week":
        return dt + timedelta(days=7)
    step = 1 if gran == "month" else 3
    m = dt.month - 1 + step
    return dt.replace(year=dt.year + m // 12, month=m % 12 + 1)


def bucket_count(start: datetime, end: datetime, gran: str) -> int:
    """Number of buckets covering [start, end]."""
    b = floor_ts(start, gran)
    n = 0
    while b <= end:
        n += 1
        if n > HARD_MAX_BUCKETS + 1:
            break
        b = next_ts(b, gran)
    return max(n, 1)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ── Parameter resolution ─────────────────────────────────────────────────────

def base_granularity(interval_days: Optional[int]) -> str:
    """Natural bucket size for a scan cadence."""
    i = interval_days or DEFAULT_INTERVAL_DAYS
    if i <= 1:
        return "day"
    if i <= 7:
        return "week"
    if i <= 45:
        return "month"
    return "quarter"


def choose_granularity(start: datetime, end: datetime,
                       min_interval_days: Optional[int]) -> tuple[str, str]:
    """
    Pick a granularity for [start, end].

    Starts from the cadence of the fastest scan schedule, then goes finer
    while there would be fewer than AUTO_MIN_BUCKETS points and coarser while
    there would be more than AUTO_MAX_BUCKETS. Returns (granularity, reason).
    """
    order = list(GRANULARITIES)
    g = base_granularity(min_interval_days)
    reason = (f"schedule every {min_interval_days or DEFAULT_INTERVAL_DAYS} d"
              + ("" if min_interval_days else " (default)"))
    idx = order.index(g)
    while idx > 0 and bucket_count(start, end, order[idx]) < AUTO_MIN_BUCKETS:
        idx -= 1
    if order[idx] != g:
        reason += f"; finer for a short span"
    else:
        while (idx < len(order) - 1
               and bucket_count(start, end, order[idx]) > AUTO_MAX_BUCKETS):
            idx += 1
        if order[idx] != g:
            reason += f"; coarser for a long span"
    return order[idx], reason


def default_stale_days(max_interval_days: Optional[int]) -> int:
    """A domain drops out of a snapshot after STALE_FACTOR missed cycles."""
    i = max_interval_days or DEFAULT_INTERVAL_DAYS
    return int(min(STALE_MAX_DAYS, max(STALE_MIN_DAYS, i * STALE_FACTOR)))


def resolve_range(range_key: str, first: datetime, now: datetime) -> datetime:
    """Start of the plotted window (never before the first assessment)."""
    days = RANGE_DAYS.get(range_key or "all")
    if days is None:
        return first
    return max(first, now - timedelta(days=days))


# ── Aggregation ──────────────────────────────────────────────────────────────

def _empty_metrics() -> dict:
    return {
        "monitored": 0, "scored": 0, "na": 0, "unknown": 0,
        "critical": 0, "weak": 0, "moderate": 0, "ready": 0,
        "avg_score": None, "pqc": 0, "pqc_pct": None,
    }


def aggregate(rows: Iterable[dict]) -> dict:
    """Metrics for one set of per-domain assessments (one row per domain)."""
    m = _empty_metrics()
    total = 0
    for r in rows:
        m["monitored"] += 1
        lvl = (r.get("level") or "").lower()
        if lvl == "na":
            m["na"] += 1
            continue
        if lvl in LEVELS:
            m[lvl] += 1
            m["scored"] += 1
            total += r.get("score") or 0
        else:
            m["unknown"] += 1
        if r.get("has_pqc"):
            m["pqc"] += 1
    if m["scored"]:
        m["avg_score"] = round(total / m["scored"], 1)
    tls = m["monitored"] - m["na"]
    if tls:
        m["pqc_pct"] = round(100.0 * m["pqc"] / tls, 1)
    return m


def compute_trends(rows: list[dict], *, granularity: Optional[str] = None,
                   mode: str = "snapshot", range_key: str = "all",
                   stale_days: Optional[int] = None,
                   min_interval_days: Optional[int] = None,
                   max_interval_days: Optional[int] = None,
                   now: Optional[datetime] = None) -> dict:
    """
    Bucket assessment rows over time.

    rows: dicts with domain, assessed_at, score, level, has_pqc (any order).
    Returns {"meta": {...}, "buckets": [...]}. ``buckets`` is empty when
    there are no rows.
    """
    now = parse_ts(now) if now else datetime.now(timezone.utc)
    mode = mode if mode in MODES else "snapshot"
    stale = int(stale_days) if stale_days else default_stale_days(max_interval_days)

    parsed = []
    for r in rows:
        ts = parse_ts(r.get("assessed_at"))
        if ts is None or ts > now:
            continue
        parsed.append((ts, r))
    parsed.sort(key=lambda x: x[0])

    meta = {
        "mode": mode, "range": range_key or "all",
        "stale_days": stale,
        "min_interval_days": min_interval_days,
        "max_interval_days": max_interval_days,
        "granularity": None, "granularity_auto": granularity is None,
        "granularity_reason": "", "start": None, "end": _iso(now),
        "first_assessment": None, "total_domains": 0,
    }
    if not parsed:
        meta["granularity"] = granularity or base_granularity(min_interval_days)
        return {"meta": meta, "buckets": []}

    first = parsed[0][0]
    start = resolve_range(range_key, first, now)
    meta["first_assessment"] = _iso(first)
    meta["total_domains"] = len({r.get("domain") for _, r in parsed})

    if granularity in GRANULARITIES:
        gran, reason = granularity, "manual"
        order = list(GRANULARITIES)
        while (bucket_count(start, now, gran) > HARD_MAX_BUCKETS
               and gran != order[-1]):
            gran = order[order.index(gran) + 1]
            reason = f"manual {granularity} exceeded {HARD_MAX_BUCKETS} points; using {gran}"
    else:
        gran, reason = choose_granularity(start, now, min_interval_days)
    meta["granularity"] = gran
    meta["granularity_reason"] = reason

    b_start = floor_ts(start, gran)
    meta["start"] = _iso(b_start)
    stale_td = timedelta(days=stale)

    latest: dict[str, tuple[datetime, dict]] = {}
    seen: set[str] = set()
    buckets = []
    i, n = 0, len(parsed)

    while b_start <= now:
        b_end = next_ts(b_start, gran)
        as_of = min(b_end, now)
        in_bucket: dict[str, dict] = {}
        new_domains = 0
        while i < n and parsed[i][0] < b_end:
            ts, r = parsed[i]
            dom = r.get("domain")
            latest[dom] = (ts, r)
            if dom not in seen:
                seen.add(dom)
                if ts >= b_start:
                    new_domains += 1
            if ts >= b_start:
                in_bucket[dom] = r
            i += 1

        if mode == "snapshot":
            cutoff = as_of - stale_td
            live = [r for ts, r in latest.values() if ts >= cutoff]
            m = aggregate(live)
            m["stale"] = len(latest) - len(live)
            t = as_of
        else:
            m = aggregate(in_bucket.values())
            if not in_bucket:
                m["avg_score"] = None
                m["pqc_pct"] = None
            m["stale"] = None
            t = b_start + (as_of - b_start) / 2

        m.update({
            "start": _iso(b_start), "end": _iso(b_end), "t": _iso(t),
            "partial": b_end > now,
            "assessed": len(in_bucket), "new_domains": new_domains,
        })
        buckets.append(m)
        b_start = b_end

    return {"meta": meta, "buckets": buckets}
