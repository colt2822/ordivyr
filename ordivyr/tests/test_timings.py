from ordivyr.board.timings import segments as S


def ev(ts, kind, **d): return {"ts": ts, "kind": kind, "detail": d or None}


def ph(r): return [(x["phase"], x["start"], x["end"], x["attempt"]) for x in r["segments"]]


def test_normal_run_with_validation():
    r = S(0, [ev(1, "submitted"), ev(2, "claimed", attempt=1), ev(3, "state", state="running"), ev(7, "state", state="validating"), ev(9, "commit")], 99)
    assert ph(r) == [("queued", 0, 2, 1), ("running", 2, 7, 1), ("validating", 7, 9, 1)] and not r["purged"] and not r["segments"][-1]["open"]


def test_retry_starts_a_new_queued_segment_under_next_attempt():
    r = S(0, [ev(1, "claimed", attempt=1), ev(4, "attempt_failed", attempt=1), ev(6, "claimed", attempt=2), ev(8, "commit")], 99)
    assert ph(r) == [("queued", 0, 1, 1), ("running", 1, 4, 1), ("queued", 4, 6, 2), ("running", 6, 8, 2)]


def test_final_failure_drops_the_speculative_requeue_segment():
    r = S(0, [ev(1, "claimed", attempt=1), ev(4, "attempt_failed"), ev(4.0001, "failed")], 99)
    assert ph(r) == [("queued", 0, 1, 1), ("running", 1, 4, 1)]


def test_held_period_is_not_running_time():
    r = S(0, [ev(1, "claimed"), ev(3, "needs_approval"), ev(10, "approved"), ev(11, "claimed", attempt=2), ev(12, "commit")], 99)
    assert [x[0] for x in ph(r)] == ["queued", "running", "held", "queued", "running"] and ph(r)[2][1:3] == (3, 10)


def test_live_job_has_an_open_segment_ending_now_and_purged_events_are_flagged():
    r = S(0, [ev(1, "claimed")], 50); assert r["segments"][-1] == {"phase": "running", "start": 1.0, "end": 50.0, "attempt": 1, "open": True}
    assert S(0, [], 5) == {"segments": [], "purged": True}
