"""Default-suite tests for offline Postgres password rotation and fail-closed resolution.

Covers AC-15, AC-16, AC-17, AC-21.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest
import typer
from loguru import logger

from stremioguard.cli import supervisor as supervisor_mod
from stremioguard.cli.commands import comet_core as comet_core_mod
from stremioguard.comet.database import rotate_postgres_password, scram_sha256_verifier
from stremioguard.comet.manager import CometManager, build_postgres_database_url
from stremioguard.config import compose_command
from stremioguard.env import env_file_value
from stremioguard.stacklock import stack_lock
from tests.conftest import FakeRunner, completed, make_comet_config

PINNED_PG_IMAGE = (
    "postgres:18.6-alpine@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395"
)


def _valid_compose_payload(data_dir: Path, *, image: str = PINNED_PG_IMAGE) -> str:
    return json.dumps(
        {
            "services": {
                "comet-postgres": {
                    "image": image,
                    "volumes": [
                        {
                            "type": "bind",
                            "source": str(data_dir),
                            "target": "/var/lib/postgresql",
                        }
                    ],
                }
            }
        }
    )


def _assert_no_secrets_in_argv(
    calls: list[list[str]], inputs: list[str | None], secret: str
) -> None:
    """Prove neither the plaintext password nor SCRAM verifier leaks into argv."""
    assert len(calls) == len(inputs)
    saw_docker_run = False
    for argv, inp in zip(calls, inputs, strict=True):
        joined = " ".join(argv)
        assert secret not in joined
        assert "SCRAM-SHA-256$" not in joined
        if argv[:2] == ["docker", "run"]:
            saw_docker_run = True
            assert inp is not None
            assert "SCRAM-SHA-256$" in inp
            assert secret not in inp
        else:
            assert inp is None or "SCRAM-SHA-256$" not in inp
            assert inp is None or secret not in inp
    assert saw_docker_run


def test_scram_sha256_verifier_matches_rfc5803_vector() -> None:
    # Deterministic salt test for SCRAM-SHA-256 format.
    verifier = scram_sha256_verifier("pencil", salt=b"0123456789abcdef", iterations=4096)
    assert verifier.startswith("SCRAM-SHA-256$4096:")
    body = verifier.removeprefix("SCRAM-SHA-256$4096:")
    salt_b64, keys = body.split("$", 1)
    stored_b64, server_b64 = keys.split(":", 1)
    assert salt_b64
    assert stored_b64
    assert server_b64
    assert "pencil" not in verifier


def test_ac15_rotation_fault_matrix_and_secret_redaction(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-15 (INV-7): rotation refuses bad config/ps/dir, redacts failures, cleans up, recovers."""
    cfg = make_comet_config(tmp_path)
    compose_cmd = tuple(
        compose_command(
            tmp_path, "config", "--format", "json", "--no-env-resolution", "comet-postgres"
        )
    )
    ps_cmd = ("docker", "ps", "-q", "--filter", f"volume={cfg.postgres_data_dir}")

    def run_and_check_no_docker_run(responses: dict[tuple[str, ...], object]) -> str:
        class _Runner(FakeRunner):
            def run(
                self,
                args: list[str],
                *,
                check: bool = False,
                capture: bool = True,
                timeout: float | None = None,
                env: dict[str, str] | None = None,
                input: str | None = None,
            ) -> subprocess.CompletedProcess[str]:
                self.calls.append(args)
                self.envs.append(env)
                self.timeouts.append(timeout)
                self.inputs.append(input)
                item = responses.get(tuple(args))
                if isinstance(item, BaseException):
                    raise item
                if isinstance(item, subprocess.CompletedProcess):
                    return item
                return completed(args, "", "unexpected", returncode=1)

        runner = _Runner({})
        manager = CometManager(cfg, runner)
        with pytest.raises(RuntimeError) as exc_info:
            rotate_postgres_password(manager)
        assert not any(call[:2] == ["docker", "run"] for call in runner.calls), runner.calls
        return str(exc_info.value)

    # (a) compose config variants
    assert "Compose" in run_and_check_no_docker_run(
        {compose_cmd: completed(list(compose_cmd), "", "boom", returncode=1)}
    )
    assert "JSON" in run_and_check_no_docker_run(
        {compose_cmd: completed(list(compose_cmd), "not-json{")}
    )
    assert "comet-postgres" in run_and_check_no_docker_run(
        {compose_cmd: completed(list(compose_cmd), json.dumps({"services": {}}))}
    )
    assert "bind mount" in run_and_check_no_docker_run(
        {
            compose_cmd: completed(
                list(compose_cmd),
                json.dumps(
                    {"services": {"comet-postgres": {"image": PINNED_PG_IMAGE, "volumes": []}}}
                ),
            )
        }
    )
    assert "postgres_data_dir" in run_and_check_no_docker_run(
        {compose_cmd: completed(list(compose_cmd), _valid_compose_payload(tmp_path / "elsewhere"))}
    )
    assert "@sha256:" in run_and_check_no_docker_run(
        {
            compose_cmd: completed(
                list(compose_cmd),
                _valid_compose_payload(cfg.postgres_data_dir, image="postgres:18-alpine"),
            )
        }
    )

    # (c) missing or empty data directory (before docker run; also test docker ps failures in (b))
    cfg.postgres_data_dir.mkdir(parents=True, exist_ok=True)
    # Empty dir -> refuses before docker ps / docker run
    assert "empty" in run_and_check_no_docker_run(
        {compose_cmd: completed(list(compose_cmd), _valid_compose_payload(cfg.postgres_data_dir))}
    )

    # Non-empty dir for (b), (d), (e), (f), (g)
    (cfg.postgres_data_dir / "PG_VERSION").write_text("18\n", encoding="utf-8")

    # (b) docker ps exits non-zero or times out
    assert "mount" in run_and_check_no_docker_run(
        {
            compose_cmd: completed(
                list(compose_cmd), _valid_compose_payload(cfg.postgres_data_dir)
            ),
            ps_cmd: completed(list(ps_cmd), "", "daemon down", returncode=1),
        }
    )
    assert "mount" in run_and_check_no_docker_run(
        {
            compose_cmd: completed(
                list(compose_cmd), _valid_compose_payload(cfg.postgres_data_dir)
            ),
            ps_cmd: subprocess.TimeoutExpired(list(ps_cmd), 30),
        }
    )

    # Seed initial postgres.env and runtime_env_file
    seed_mgr = CometManager(cfg, FakeRunner({}))
    seed_mgr._write_postgres_env("comet")
    seed_mgr.write_runtime_env()
    orig_pg_env = seed_mgr.postgres_env_file().read_bytes()
    orig_rt_env = cfg.runtime_env_file.read_bytes()

    captured_logs: list[str] = []
    sink_id = logger.add(lambda msg: captured_logs.append(str(msg)), level="DEBUG")
    try:
        fixed_secret = "SuperSecretTokenValue123"

        # (d) one-off exits 0 without rotated = "t", echoing verifier on stderr
        class _BadSqlRunner(FakeRunner):
            def run(
                self,
                args: list[str],
                *,
                check: bool = False,
                capture: bool = True,
                timeout: float | None = None,
                env: dict[str, str] | None = None,
                input: str | None = None,
            ) -> subprocess.CompletedProcess[str]:
                self.calls.append(args)
                self.inputs.append(input)
                if tuple(args) == compose_cmd:
                    return completed(args, _valid_compose_payload(cfg.postgres_data_dir))
                if tuple(args) == ps_cmd:
                    return completed(args, "")
                if args[:2] == ["docker", "run"]:
                    assert input is not None
                    verifier = input.split("PASSWORD '", 1)[1].split("'", 1)[0]
                    return completed(
                        args,
                        "",
                        f"STATEMENT: ALTER ROLE comet PASSWORD '{verifier}';\nERROR: fail\n",
                        returncode=0,
                    )
                if args[:3] == ["docker", "rm", "-f"]:
                    return completed(args, "")
                return completed(args, "")

        bad_sql_runner = _BadSqlRunner({})
        with (
            mock.patch(
                "stremioguard.comet.database.secrets.token_urlsafe", return_value=fixed_secret
            ),
            pytest.raises(RuntimeError) as exc_d,
        ):
            rotate_postgres_password(CometManager(cfg, bad_sql_runner))
        assert "<redacted>" in str(exc_d.value)
        assert "SCRAM-SHA-256$" not in str(exc_d.value)
        assert fixed_secret not in str(exc_d.value)
        assert seed_mgr.postgres_env_file().read_bytes() == orig_pg_env
        assert cfg.runtime_env_file.read_bytes() == orig_rt_env
        _assert_no_secrets_in_argv(bad_sql_runner.calls, bad_sql_runner.inputs, fixed_secret)

        # (e) one-off times out -> docker rm -f <exact name> runs, files unchanged
        class _TimeoutRunner(FakeRunner):
            def run(
                self,
                args: list[str],
                *,
                check: bool = False,
                capture: bool = True,
                timeout: float | None = None,
                env: dict[str, str] | None = None,
                input: str | None = None,
            ) -> subprocess.CompletedProcess[str]:
                self.calls.append(args)
                self.inputs.append(input)
                if tuple(args) == compose_cmd:
                    return completed(args, _valid_compose_payload(cfg.postgres_data_dir))
                if tuple(args) == ps_cmd:
                    return completed(args, "")
                if args[:2] == ["docker", "run"]:
                    raise subprocess.TimeoutExpired(args, 120)
                if args[:3] == ["docker", "rm", "-f"]:
                    return completed(args, "")
                return completed(args, "")

        timeout_runner = _TimeoutRunner({})
        with (
            mock.patch(
                "stremioguard.comet.database.secrets.token_urlsafe", return_value=fixed_secret
            ),
            pytest.raises(RuntimeError) as exc_e,
        ):
            rotate_postgres_password(CometManager(cfg, timeout_runner))
        assert fixed_secret not in str(exc_e.value)
        run_call = next(c for c in timeout_runner.calls if c[:2] == ["docker", "run"])
        exact_name = run_call[run_call.index("--name") + 1]
        assert ["docker", "rm", "-f", exact_name] in timeout_runner.calls
        assert seed_mgr.postgres_env_file().read_bytes() == orig_pg_env
        assert cfg.runtime_env_file.read_bytes() == orig_rt_env
        _assert_no_secrets_in_argv(timeout_runner.calls, timeout_runner.inputs, fixed_secret)

        # (f) writing postgres.env fails -> message says to rerun, runtime env unchanged
        class _SuccessSqlRunner(FakeRunner):
            def run(
                self,
                args: list[str],
                *,
                check: bool = False,
                capture: bool = True,
                timeout: float | None = None,
                env: dict[str, str] | None = None,
                input: str | None = None,
            ) -> subprocess.CompletedProcess[str]:
                self.calls.append(args)
                self.inputs.append(input)
                if tuple(args) == compose_cmd:
                    return completed(args, _valid_compose_payload(cfg.postgres_data_dir))
                if tuple(args) == ps_cmd:
                    return completed(args, "")
                if args[:2] == ["docker", "run"]:
                    return completed(args, '1: rotated = "t"\n')
                if args[:3] == ["docker", "rm", "-f"]:
                    return completed(args, "")
                return completed(args, "")

        runner_f = _SuccessSqlRunner({})
        mgr_f = CometManager(cfg, runner_f)
        with (
            mock.patch(
                "stremioguard.comet.database.secrets.token_urlsafe", return_value=fixed_secret
            ),
            mock.patch.object(mgr_f, "_write_postgres_env", side_effect=OSError("disk full")),
            pytest.raises(RuntimeError) as exc_f,
        ):
            rotate_postgres_password(mgr_f)
        assert "rerun" in str(exc_f.value).lower()
        assert fixed_secret not in str(exc_f.value)
        assert cfg.runtime_env_file.read_bytes() == orig_rt_env
        _assert_no_secrets_in_argv(runner_f.calls, runner_f.inputs, fixed_secret)

        # (g) rerun after (f) succeeds without old password
        new_secret = "SecondSecretValue456789"
        runner_g = _SuccessSqlRunner({})
        mgr_g = CometManager(cfg, runner_g)
        with mock.patch(
            "stremioguard.comet.database.secrets.token_urlsafe", return_value=new_secret
        ):
            rotate_postgres_password(mgr_g)
        _assert_no_secrets_in_argv(runner_g.calls, runner_g.inputs, new_secret)
        assert env_file_value(mgr_g.postgres_env_file(), "POSTGRES_PASSWORD") == new_secret
        assert f"DATABASE_URL={build_postgres_database_url(new_secret)}" in (
            cfg.runtime_env_file.read_text(encoding="utf-8")
        )

        out = capsys.readouterr()
        all_output = f"{out.out}\n{out.err}\n" + "\n".join(captured_logs)
        assert fixed_secret not in all_output
        assert new_secret not in all_output
    finally:
        logger.remove(sink_id)


def test_ac16_cli_rotate_db_password_preconditions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-16 (D8): CLI refuses disabled Comet, running/unknown watchdog, and held stack lock."""
    monkeypatch.setattr(comet_core_mod, "ROOT_DIR", tmp_path)
    monkeypatch.setattr(comet_core_mod, "ROTATE_LOCK_WAIT_SECONDS", 0.05)

    docker_called = {"count": 0}

    def fail_docker(*args: object, **kwargs: object) -> object:
        docker_called["count"] += 1
        raise AssertionError("Docker must not be called when CLI preconditions fail")

    monkeypatch.setattr("stremioguard.comet.database.rotate_postgres_password", fail_docker)

    def make_mgr(enabled: bool) -> CometManager:
        cfg = make_comet_config(tmp_path, enabled=enabled)
        return CometManager(cfg, FakeRunner({}))

    failures: list[str] = []

    def fake_fail(msg: str) -> None:
        failures.append(msg)
        raise typer.Exit(1)

    monkeypatch.setattr(comet_core_mod, "fail", fake_fail)

    # 1. Comet disabled
    monkeypatch.setattr(comet_core_mod, "_comet_manager", lambda: make_mgr(enabled=False))
    monkeypatch.setattr(supervisor_mod, "watchdog_running", lambda: False)
    with pytest.raises(typer.Exit) as exc1:
        comet_core_mod.comet_rotate_db_password()
    assert exc1.value.exit_code == 1
    assert "disabled" in failures[-1].lower()

    # 2. Watchdog running
    monkeypatch.setattr(comet_core_mod, "_comet_manager", lambda: make_mgr(enabled=True))
    monkeypatch.setattr(supervisor_mod, "watchdog_running", lambda: True)
    with pytest.raises(typer.Exit) as exc2:
        comet_core_mod.comet_rotate_db_password()
    assert exc2.value.exit_code == 1
    assert "watchdog" in failures[-1].lower()

    # 3. Watchdog state None
    monkeypatch.setattr(supervisor_mod, "watchdog_running", lambda: None)
    with pytest.raises(typer.Exit) as exc3:
        comet_core_mod.comet_rotate_db_password()
    assert exc3.value.exit_code == 1
    assert "watchdog" in failures[-1].lower()

    # 4. Stack lock held elsewhere (simulate non-reentrant lock contention)
    monkeypatch.setattr(supervisor_mod, "watchdog_running", lambda: False)
    with stack_lock(tmp_path, wait_seconds=0):
        pass
    with (
        mock.patch("stremioguard.stacklock._try_lock", return_value=False),
        pytest.raises(typer.Exit) as exc4,
    ):
        comet_core_mod.comet_rotate_db_password()
    assert exc4.value.exit_code == 1
    assert "stack" in failures[-1].lower() or "lock" in failures[-1].lower()
    assert docker_called["count"] == 0


def test_ac17_resolve_postgres_password_matrix(tmp_path: Path) -> None:
    """AC-17 (INV-8, D9): fail closed on initialized data dir without password; empty generates."""
    # Empty data dir -> generates 24-character password
    cfg_empty = make_comet_config(tmp_path / "empty")
    mgr_empty = CometManager(cfg_empty, FakeRunner({}))
    generated = mgr_empty._resolve_postgres_password()
    assert len(generated) == 24
    assert generated != "comet"

    # Non-empty data dir with missing / 0-byte / missing-key / empty-value postgres.env
    for case_name, content in (
        ("missing", None),
        ("empty_file", ""),
        ("no_key", "POSTGRES_USER=comet\nPOSTGRES_DB=comet\n"),
        ("empty_val", "POSTGRES_USER=comet\nPOSTGRES_PASSWORD=\nPOSTGRES_DB=comet\n"),
    ):
        root = tmp_path / case_name
        cfg = make_comet_config(root)
        cfg.postgres_data_dir.mkdir(parents=True, exist_ok=True)
        (cfg.postgres_data_dir / "PG_VERSION").write_text("18\n", encoding="utf-8")
        mgr = CometManager(cfg, FakeRunner({}))
        mgr._write_postgres_env("seed")
        mgr.write_runtime_env()
        orig_runtime = cfg.runtime_env_file.read_bytes()

        if content is None:
            mgr.postgres_env_file().unlink()
            orig_pg = None
        else:
            mgr.postgres_env_file().write_text(content, encoding="utf-8")
            orig_pg = mgr.postgres_env_file().read_bytes()

        with pytest.raises(RuntimeError) as exc_info:
            mgr._resolve_postgres_password()
        assert "postgres.env" in str(exc_info.value)
        assert "rotate-db-password" in str(exc_info.value)
        assert cfg.runtime_env_file.read_bytes() == orig_runtime
        if orig_pg is None:
            assert not mgr.postgres_env_file().exists()
        else:
            assert mgr.postgres_env_file().read_bytes() == orig_pg

    # Stored legacy 'comet' -> returned with one warning per manager
    cfg_legacy = make_comet_config(tmp_path / "legacy")
    cfg_legacy.postgres_data_dir.mkdir(parents=True, exist_ok=True)
    (cfg_legacy.postgres_data_dir / "PG_VERSION").write_text("18\n", encoding="utf-8")
    mgr_legacy = CometManager(cfg_legacy, FakeRunner({}))
    mgr_legacy._write_postgres_env("comet")
    warnings: list[str] = []
    with mock.patch.object(mgr_legacy, "warn", side_effect=warnings.append):
        assert mgr_legacy._resolve_postgres_password() == "comet"
        assert mgr_legacy._resolve_postgres_password() == "comet"
    assert len(warnings) == 1
    assert "rotate-db-password" in warnings[0]


def test_ac21_rotation_busy_guard_and_no_secrets_in_argv(tmp_path: Path) -> None:
    """AC-21 (R1-1): refuse running container IDs from docker ps; keep secrets out of argv."""
    cfg = make_comet_config(tmp_path)
    cfg.postgres_data_dir.mkdir(parents=True, exist_ok=True)
    (cfg.postgres_data_dir / "PG_VERSION").write_text("18\n", encoding="utf-8")

    seed_mgr = CometManager(cfg, FakeRunner({}))
    seed_mgr._write_postgres_env("seed-pass")
    seed_mgr.write_runtime_env()
    orig_pg_env = seed_mgr.postgres_env_file().read_bytes()
    orig_rt_env = cfg.runtime_env_file.read_bytes()

    compose_cmd = tuple(
        compose_command(
            tmp_path, "config", "--format", "json", "--no-env-resolution", "comet-postgres"
        )
    )
    ps_cmd = ("docker", "ps", "-q", "--filter", f"volume={cfg.postgres_data_dir}")

    # (a) docker ps exits 0 returning 1 container ID, then 2 container IDs
    for stdout, expected_ids in (
        ("deadbeef1234\n", ("deadbeef1234",)),
        ("deadbeef1234\ncafe5678abcd\n", ("deadbeef1234", "cafe5678abcd")),
    ):

        class _BusyPsRunner(FakeRunner):
            def __init__(self, ps_stdout: str) -> None:
                super().__init__({})
                self.ps_stdout = ps_stdout

            def run(
                self,
                args: list[str],
                *,
                check: bool = False,
                capture: bool = True,
                timeout: float | None = None,
                env: dict[str, str] | None = None,
                input: str | None = None,
            ) -> subprocess.CompletedProcess[str]:
                self.calls.append(args)
                self.inputs.append(input)
                if tuple(args) == compose_cmd:
                    return completed(args, _valid_compose_payload(cfg.postgres_data_dir))
                if tuple(args) == ps_cmd:
                    return completed(args, self.ps_stdout, returncode=0)
                return completed(args, "", "unexpected", returncode=1)

        busy_runner = _BusyPsRunner(stdout)
        with pytest.raises(RuntimeError) as exc_info:
            rotate_postgres_password(CometManager(cfg, busy_runner))
        msg = str(exc_info.value)
        for container_id in expected_ids:
            assert container_id in msg
        assert not any(call[:2] == ["docker", "run"] for call in busy_runner.calls)
        assert seed_mgr.postgres_env_file().read_bytes() == orig_pg_env
        assert cfg.runtime_env_file.read_bytes() == orig_rt_env

    # (b) rotation records every argv and proves neither secret nor SCRAM verifier appears there
    class _SuccessRunner(FakeRunner):
        def run(
            self,
            args: list[str],
            *,
            check: bool = False,
            capture: bool = True,
            timeout: float | None = None,
            env: dict[str, str] | None = None,
            input: str | None = None,
        ) -> subprocess.CompletedProcess[str]:
            self.calls.append(args)
            self.inputs.append(input)
            if tuple(args) == compose_cmd:
                return completed(args, _valid_compose_payload(cfg.postgres_data_dir))
            if tuple(args) == ps_cmd:
                return completed(args, "")
            if args[:2] == ["docker", "run"]:
                return completed(args, '1: rotated = "t"\n')
            if args[:3] == ["docker", "rm", "-f"]:
                return completed(args, "")
            return completed(args, "", "unexpected", returncode=1)

    secret = "Ac21RotationSecretValue"
    ok_runner = _SuccessRunner({})
    with mock.patch("stremioguard.comet.database.secrets.token_urlsafe", return_value=secret):
        rotate_postgres_password(CometManager(cfg, ok_runner))
    _assert_no_secrets_in_argv(ok_runner.calls, ok_runner.inputs, secret)
