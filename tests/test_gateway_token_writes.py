"""tokens.map must never admit a token that tokens.json no longer lists.

Covers the race between a token change and a concurrent config write (a
reload or start that read tokens.json before a revoke), nested lock use, and
a failure at every step of a token change.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from stremioguard import comet_gateway as gateway_mod
from stremioguard.comet_gateway import CometGatewayManager
from tests.conftest import make_comet_gateway_config

BOUND = 10.0  # seconds: a deadlock fails the test instead of hanging it


def _manager(root: Path) -> CometGatewayManager:
    return CometGatewayManager(make_comet_gateway_config(root))


def _admitted(manager: CometGatewayManager) -> set[str]:
    text = manager.config.tokens_map_file.read_text(encoding="utf-8")
    body = text.split("map $gateway_token $gateway_token_id", 1)[0]
    return {
        line.split('"~^', 1)[1].split('$"', 1)[0] for line in body.splitlines() if '"~^' in line
    }


def _listed(manager: CometGatewayManager) -> set[str]:
    return {str(entry["token"]) for entry in manager.load_tokens().values()}


def _run_bounded(target, *args) -> threading.Thread:  # type: ignore[no-untyped-def]
    thread = threading.Thread(target=target, args=args, daemon=True)
    thread.start()
    return thread


def test_a_concurrent_write_cannot_bring_a_revoked_token_back(tmp_path: Path) -> None:
    seed = _manager(tmp_path)
    token_id, token = seed.add_token("victim")
    seed.add_token("keeper")

    # A reload that has read tokens.json, then stalls before writing tokens.map.
    writer = _manager(tmp_path)
    has_read = threading.Event()
    go = threading.Event()
    real_load = writer.load_tokens

    def stalled_load() -> dict[str, dict[str, object]]:
        tokens = real_load()
        has_read.set()
        go.wait(BOUND)
        return tokens

    writer.load_tokens = stalled_load  # type: ignore[method-assign]
    stale = _run_bounded(writer.write_nginx_configs)
    assert has_read.wait(BOUND)

    revoker = _manager(tmp_path)
    revoke = _run_bounded(revoker.revoke_token, token_id)
    revoke.join(1.0)  # without the lock the revoke finishes here, before the stale write
    go.set()
    stale.join(BOUND)
    revoke.join(BOUND)
    assert not stale.is_alive() and not revoke.is_alive()

    assert token not in _listed(seed)
    assert token not in _admitted(seed), "the stale write reinstated a revoked token"


def test_nested_lock_use_in_one_thread_completes(tmp_path: Path) -> None:
    outer = _manager(tmp_path)
    other_instance = _manager(tmp_path)
    outer.add_token("first")
    done = threading.Event()

    def nested() -> None:
        with outer._token_lock():
            outer.write_nginx_configs()
            other_instance.write_nginx_configs()
            with other_instance._token_lock():
                other_instance.add_token("inner")
        done.set()

    thread = _run_bounded(nested)
    thread.join(BOUND)
    assert done.is_set(), "nested token-lock use deadlocked"
    assert len(_listed(outer)) == 2


def test_another_thread_waits_for_the_holder(tmp_path: Path) -> None:
    holder = _manager(tmp_path)
    holder.add_token("first")
    acquired = threading.Event()
    with holder._token_lock():
        thread = _run_bounded(lambda: (_manager(tmp_path).add_token("second"), acquired.set()))
        time.sleep(0.5)
        assert not acquired.is_set(), "a second thread got past a held token lock"
    thread.join(BOUND)
    assert acquired.is_set()


def _fail_on(monkeypatch: pytest.MonkeyPatch, manager: CometGatewayManager, step: str) -> None:
    """Make one step of a token change raise ENOSPC: first map, state save, or final map."""
    if step == "save":

        def failing_save(state: dict[str, object]) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(manager, "save_state", failing_save)
        return
    real_write = gateway_mod.atomic_write_text
    calls = {"map": 0}
    target_call = 1 if step == "first map" else 2

    def failing_write(path: Path, content: str, *, mode: int = 0o600) -> None:
        if path == manager.config.tokens_map_file:
            calls["map"] += 1
            if calls["map"] == target_call:
                raise OSError(28, "No space left on device")
        real_write(path, content, mode=mode)

    monkeypatch.setattr(gateway_mod, "atomic_write_text", failing_write)


@pytest.mark.parametrize("step", ["first map", "save", "final map"])
@pytest.mark.parametrize("operation", ["add", "revoke", "rotate"])
def test_no_failed_step_leaves_an_unlisted_token_admitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, step: str
) -> None:
    manager = _manager(tmp_path)
    victim_id, victim = manager.add_token("victim")
    manager.add_token("keeper")
    listed_before = _listed(manager)

    _fail_on(monkeypatch, manager, step)
    with pytest.raises(OSError, match="No space"):
        if operation == "add":
            manager.add_token("new")
        elif operation == "revoke":
            manager.revoke_token(victim_id)
        else:
            manager.rotate_token(victim_id)
    monkeypatch.undo()

    admitted, listed = _admitted(manager), _listed(manager)
    assert admitted <= listed, f"admitted but unlisted after {operation} failed at {step}"
    if operation in {"revoke", "rotate"} and step != "first map":
        assert victim not in admitted, "a failed revoke left the token working"
    if step != "final map":
        assert listed == listed_before

    # The operator runs the command again and it completes.
    if operation == "revoke" and victim_id in {i for i in manager.load_tokens()}:
        manager.revoke_token(victim_id)
        assert victim not in _admitted(manager) | _listed(manager)
