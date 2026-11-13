import asyncio

from pf_common.health import run_checks


async def _ok() -> None:
    return None


async def _fails() -> None:
    raise ConnectionError("dial tcp 10.0.0.5:5432: refused")


async def _hangs() -> None:
    await asyncio.sleep(30)


def test_all_checks_pass() -> None:
    assert asyncio.run(run_checks({"b": _ok, "a": _ok})) == {"a": "ok", "b": "ok"}


def test_failures_and_timeouts_are_reported_without_detail() -> None:
    results = asyncio.run(
        run_checks({"postgres": _fails, "broker": _hangs, "cache": _ok}, timeout_seconds=0.05)
    )

    assert results == {"broker": "unavailable", "cache": "ok", "postgres": "unavailable"}


def test_no_checks() -> None:
    assert asyncio.run(run_checks({})) == {}
