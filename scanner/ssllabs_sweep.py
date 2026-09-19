#!/usr/bin/env python3
"""
PQC-Monitor: throttled Qualys SSL Labs sweep

Collects SSL Labs reports for every serviceable HTTPS domain WITHOUT
tripping the API's rate limits. Runs as its own scheduled job (weekly by
default) — never inline in a scan run.

Why a separate job
──────────────────
`analyze?fromCache=on` starts a NEW assessment on a cache miss. Querying it
for thousands of domains inside a scan run therefore asks Qualys for
thousands of concurrent assessments; the 2026-09-04 monthly run got HTTP 429
for 2,915 of 3,168 domains. Each assessment takes ~1-2 min per endpoint and
SSL Labs caps concurrent assessments per client, so the work has to be
spread out and paced.

Flow per domain
───────────────
1. Acquire a concurrency slot (limit derived from /info, never above the
   configured ceiling; reduced by one on every 429).
2. Respect newAssessmentCoolOff between assessment starts (global).
3. analyze?fromCache=on&maxAge=<h>: READY → store immediately (no slot
   used by Qualys); DNS/IN_PROGRESS → poll every poll_seconds until READY
   or ERROR, or give up after assessment_timeout.
4. Store the summary (READY) or the error (ERROR) in domain_extra
   ('ssllabs') under the domain's latest run, the same place the on-demand
   refresh writes to. Errors are stored too, so a host SSL Labs cannot
   test is not retried until the next sweep.

Back-off
────────
429 → global pause (60 s, doubling to 10 min on repeats), concurrency - 1,
      domain re-queued.
529 / 503 → global pause 15 min, domain re-queued.
441/403 (bad or unregistered email) → the sweep aborts.
Network errors → up to 3 attempts per domain.

Targets: domains whose latest assessment is not level="na" and whose latest
run recorded a successful TLS handshake on 443 (SSL Labs only tests HTTPS).
Domains with an SSL Labs record newer than max_age_days are skipped, so an
interrupted sweep resumes where it stopped.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import logging
import random
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from scanner.ssllabs_client import SSLLabsClient

logger = logging.getLogger(__name__)

DEFAULT_CONCURRENCY = 6          # ceiling; SSL Labs usually allows ~25
DEFAULT_MAX_AGE_DAYS = 6         # weekly sweep → refresh anything older
DEFAULT_POLL_SECONDS = 15
DEFAULT_ASSESSMENT_TIMEOUT = 1200  # 20 min per host
PAUSE_429_MIN = 60
PAUSE_429_MAX = 600
PAUSE_OVERLOAD = 900             # 529 / 503
MAX_NETWORK_ATTEMPTS = 3


class SweepAborted(Exception):
    """Raised when continuing is pointless (auth failure)."""


class _AdjustableLimit:
    """Counting semaphore whose limit can be lowered while in use."""

    def __init__(self, limit: int):
        self._limit = max(1, limit)
        self._active = 0
        self._cv = threading.Condition()

    @property
    def limit(self) -> int:
        return self._limit

    def acquire(self, stop: threading.Event) -> bool:
        with self._cv:
            while self._active >= self._limit:
                if stop.is_set():
                    return False
                self._cv.wait(timeout=1.0)
            self._active += 1
            return True

    def release(self):
        with self._cv:
            self._active = max(0, self._active - 1)
            self._cv.notify_all()

    def decrease(self) -> int:
        with self._cv:
            self._limit = max(1, self._limit - 1)
            return self._limit


class SSLLabsSweep:
    """One sweep over the target domains. Create a new instance per run."""

    def __init__(self, db, client: SSLLabsClient,
                 concurrency: int = DEFAULT_CONCURRENCY,
                 max_age_days: float = DEFAULT_MAX_AGE_DAYS,
                 poll_seconds: float = DEFAULT_POLL_SECONDS,
                 assessment_timeout: float = DEFAULT_ASSESSMENT_TIMEOUT,
                 stop_event: Optional[threading.Event] = None,
                 clock: Callable[[], float] = time.monotonic):
        self.db = db
        self.client = client
        self.concurrency = max(1, int(concurrency))
        self.max_age_days = max_age_days
        self.poll_seconds = poll_seconds
        self.assessment_timeout = assessment_timeout
        self.stop = stop_event or threading.Event()
        self._clock = clock

        self._lock = threading.Lock()
        self._queue: deque = deque()
        self._attempts: dict = {}
        self._pause_until = 0.0
        self._pause_429 = PAUSE_429_MIN
        self._last_start = 0.0
        self._cooloff = 1.0
        self._aborted: Optional[str] = None
        self._run_ids: dict = {}
        self.stats = {"targets": 0, "skipped_fresh": 0, "ready": 0,
                      "cached": 0, "error": 0, "timeout": 0,
                      "rate_limited": 0, "overloaded": 0, "no_run": 0,
                      "gave_up": 0}

    def _inc(self, key: str):
        with self._lock:
            self.stats[key] += 1

    # ── Target selection ────────────────────────────────────────────

    def targets(self) -> list:
        """Serviceable domains with HTTPS on 443 lacking a fresh report."""
        latest = self.db.latest_run_ids_bulk()
        https = self.db.domains_with_tls_on_port(443)
        levels = self._latest_levels()
        candidates = sorted(d for d in https
                            if d in latest and levels.get(d) != "na")
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.max_age_days)
        existing = self.db.latest_extra_bulk("ssllabs")
        out = []
        for d in candidates:
            rec = existing.get(d) or {}
            ts = _parse_iso(rec.get("_recorded_at")) if isinstance(rec, dict) else None
            if ts and ts >= cutoff:
                self._inc("skipped_fresh")
                continue
            out.append(d)
        self._run_ids = latest
        return out

    def _latest_levels(self) -> dict:
        with self.db._connect() as conn:
            rows = conn.execute(
                "SELECT a.domain, a.level FROM assessments a "
                "INNER JOIN (SELECT domain, MAX(assessed_at) AS m "
                "            FROM assessments GROUP BY domain) l "
                "ON a.domain = l.domain AND a.assessed_at = l.m").fetchall()
        return {r["domain"]: (r["level"] or "").strip().lower() for r in rows}

    # ── Driver ──────────────────────────────────────────────────────

    def run(self, domains: Optional[list] = None, limit: Optional[int] = None) -> dict:
        if not self.client.available:
            logger.warning("SSL Labs sweep skipped: ssllabs.email not configured")
            return {**self.stats, "status": "unavailable"}

        todo = list(domains) if domains is not None else self.targets()
        if domains is not None and not self._run_ids:
            self._run_ids = self.db.latest_run_ids_bulk()
        if limit:
            todo = todo[:limit]
        self.stats["targets"] = len(todo)
        self._queue.extend(todo)

        workers = self._initial_concurrency()
        limiter = _AdjustableLimit(workers)
        logger.info("SSL Labs sweep: %d domain(s) to assess (%d fresh skipped), "
                    "concurrency %d, cool-off %.1fs",
                    len(todo), self.stats["skipped_fresh"], workers, self._cooloff)
        started = self._clock()

        threads = [threading.Thread(target=self._worker, args=(limiter,),
                                    name=f"ssllabs-{i}", daemon=True)
                   for i in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        status = ("aborted" if self._aborted else
                  "stopped" if self.stop.is_set() else "completed")
        elapsed = self._clock() - started
        logger.info("SSL Labs sweep %s in %.0f min: ready=%d (cached %d) error=%d "
                    "timeout=%d gave_up=%d 429s=%d overloads=%d%s",
                    status, elapsed / 60, self.stats["ready"], self.stats["cached"],
                    self.stats["error"], self.stats["timeout"], self.stats["gave_up"],
                    self.stats["rate_limited"], self.stats["overloaded"],
                    f" ({self._aborted})" if self._aborted else "")
        return {**self.stats, "status": status, "remaining": len(self._queue),
                "elapsed_seconds": round(elapsed)}

    def _initial_concurrency(self) -> int:
        info = self.client.info() or {}
        max_a = info.get("maxAssessments")
        cur_a = info.get("currentAssessments") or 0
        cool = info.get("newAssessmentCoolOff")
        if isinstance(cool, (int, float)) and cool > 0:
            self._cooloff = cool / 1000.0 + 0.2
        limit = self.concurrency
        if isinstance(max_a, int) and max_a > 0:
            # keep one slot of headroom for on-demand refreshes from the UI
            limit = min(limit, max(1, max_a - cur_a - 1))
        return max(1, limit)

    # ── Worker ──────────────────────────────────────────────────────

    def _next(self) -> Optional[str]:
        with self._lock:
            return self._queue.popleft() if self._queue else None

    def _requeue(self, domain: str):
        with self._lock:
            self._queue.append(domain)

    def _worker(self, limiter: _AdjustableLimit):
        while not self.stop.is_set() and not self._aborted:
            domain = self._next()
            if domain is None:
                return
            if not limiter.acquire(self.stop):
                self._requeue(domain)
                return
            try:
                self._process(domain, limiter)
            except SweepAborted as e:
                self._aborted = str(e)
            except Exception as e:  # never let one host kill the sweep
                logger.warning("SSL Labs sweep: %s failed: %s", domain, e)
                self._inc("gave_up")
            finally:
                limiter.release()
            self._progress()

    def _progress(self):
        done = (self.stats["ready"] + self.stats["error"] +
                self.stats["timeout"] + self.stats["gave_up"])
        if done and done % 50 == 0:
            logger.info("SSL Labs sweep progress: %d/%d done, %d queued",
                        done, self.stats["targets"], len(self._queue))

    def _wait(self, seconds: float) -> bool:
        """Sleep, interruptibly. False if stopped."""
        return not self.stop.wait(max(0.0, seconds))

    def _gate_start(self) -> bool:
        """Honour global pauses and the new-assessment cool-off."""
        while True:
            with self._lock:
                now = self._clock()
                wait = max(self._pause_until - now,
                           self._last_start + self._cooloff - now)
                if wait <= 0:
                    self._last_start = now
                    return True
            if not self._wait(min(wait, 30.0)):
                return False

    def _pause(self, seconds: float):
        with self._lock:
            self._pause_until = max(self._pause_until,
                                    self._clock() + seconds + random.uniform(0, 5))

    def _process(self, domain: str, limiter: _AdjustableLimit):
        if not self._gate_start():
            self._requeue(domain)
            return
        max_age_h = max(1, int(self.max_age_days * 24))
        code, body = self.client.analyze({"host": domain, "fromCache": "on",
                                          "maxAge": max_age_h, "all": "done"})
        if self._handle_http(domain, code, limiter):
            return
        with self._lock:
            self._pause_429 = PAUSE_429_MIN      # a success resets back-off
        status = (body or {}).get("status", "")
        if status == "READY":
            self._inc("cached")
            self._store(domain, body)
            return
        if status == "ERROR":
            self._store(domain, body)
            return

        # DNS / IN_PROGRESS — poll until finished
        deadline = self._clock() + self.assessment_timeout
        while self._clock() < deadline:
            if not self._wait(self.poll_seconds):
                return                                   # stopping
            code, body = self.client.analyze({"host": domain, "all": "done"})
            if code in (429, 529, 503):
                self._wait(self.poll_seconds * 2)
                continue
            if code != 200 or not body:
                continue
            status = body.get("status", "")
            if status in ("READY", "ERROR"):
                self._store(domain, body)
                return
        self._inc("timeout")
        logger.info("SSL Labs sweep: %s timed out after %ds", domain,
                    int(self.assessment_timeout))

    def _handle_http(self, domain: str, code: int, limiter) -> bool:
        """True if the response was not a usable 200 (already handled)."""
        if code == 200:
            return False
        if code == 429:
            self._inc("rate_limited")
            new_limit = limiter.decrease()
            with self._lock:
                pause = self._pause_429
                self._pause_429 = min(PAUSE_429_MAX, self._pause_429 * 2)
            if self.stats["rate_limited"] <= 5 or self.stats["rate_limited"] % 50 == 0:
                logger.warning("SSL Labs 429 (#%d): pausing %ds, concurrency now %d",
                               self.stats["rate_limited"], pause, new_limit)
            self._pause(pause)
            self._requeue(domain)
            return True
        if code in (529, 503):
            self._inc("overloaded")
            logger.warning("SSL Labs HTTP %d (service overloaded/maintenance): "
                           "pausing %d min", code, PAUSE_OVERLOAD // 60)
            self._pause(PAUSE_OVERLOAD)
            self._requeue(domain)
            return True
        if code in (401, 403, 441):
            raise SweepAborted(f"SSL Labs rejected credentials (HTTP {code}); "
                               f"check ssllabs.email registration")
        if code == 0:
            n = self._attempts.get(domain, 0) + 1
            self._attempts[domain] = n
            if n < MAX_NETWORK_ATTEMPTS:
                self._requeue(domain)
            else:
                self._inc("gave_up")
            return True
        # 400 (invalid host) and anything unexpected: record, don't retry
        self._inc("gave_up")
        logger.info("SSL Labs sweep: %s → HTTP %d, skipped", domain, code)
        return True

    def _store(self, domain: str, body: dict):
        summary = SSLLabsClient.summarize(domain, body)
        if summary.get("status") == "READY":
            self._inc("ready")
        else:
            self._inc("error")
        run_id = self._run_ids.get(domain) or \
            self.db.get_latest_run_id_for_domain(domain)
        if not run_id:
            self._inc("no_run")
            return
        self.db.save_domain_extra(run_id, domain, "ssllabs", summary)


def _parse_iso(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
