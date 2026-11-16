"""Opt-in real-Docker proofs for Postgres auth and offline password rotation (AC-12, AC-13, AC-14).

Run with:
  STREMIOGUARD_DOCKER_TESTS=1 .venv/bin/python -m pytest -s -v tests/test_postgres_docker.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from loguru import logger

from stremioguard.comet.database import rotate_postgres_password
from stremioguard.comet.manager import CometManager, build_postgres_database_url
from stremioguard.config import SubprocessRunner
from stremioguard.env import env_file_value
from tests.conftest import make_comet_config

PREFIX = os.environ.get("STREMIOGUARD_DOCKER_TEST_PREFIX", "sgfix8-")
REPO_ROOT = Path(__file__).resolve().parent.parent
POSTGRES_IMAGE = "postgres@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395"
COMET_IMAGE = "g0ldyy/comet@sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea"
BUSYBOX_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"

LEGACY_PG_FLAGS = [
    "postgres",
    "-c",
    "shared_buffers=128MB",
    "-c",
    "effective_cache_size=384MB",
    "-c",
    "maintenance_work_mem=64MB",
    "-c",
    "checkpoint_completion_target=0.9",
    "-c",
    "wal_buffers=8MB",
    "-c",
    "random_page_cost=1.1",
    "-c",
    "effective_io_concurrency=200",
    "-c",
    "work_mem=8MB",
    "-c",
    "max_connections=100",
]

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="needs real Docker containers; set STREMIOGUARD_DOCKER_TESTS=1",
)


def _docker(
    *args: str, check: bool = True, timeout: float = 30.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _compose(
    project: str, compose_file: Path, *args: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-p", project, "-f", str(compose_file), *args],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60.0,
    )


def _empty_subuid_dir(data_dir: Path) -> None:
    if data_dir.exists():
        _docker(
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{data_dir}:/pgdata",
            BUSYBOX_IMAGE,
            "sh",
            "-c",
            "rm -rf /pgdata/* /pgdata/.[!.]* /pgdata/..?* 2>/dev/null || true",
            check=False,
        )


def _wait_pg_ready(container_id: str, timeout_seconds: float = 45.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        res = _docker("exec", container_id, "pg_isready", "-U", "comet", "-d", "comet", check=False)
        if res.returncode == 0:
            return
        time.sleep(0.5)
    logs = _docker("logs", container_id, check=False)
    raise AssertionError(
        f"Postgres {container_id} did not become ready:\n{logs.stdout}\n{logs.stderr}"
    )


def _psql(
    owner_name: str,
    host: str,
    password: str,
    query: str = "SELECT 1;",
) -> subprocess.CompletedProcess[str]:
    return _docker(
        "run",
        "--rm",
        "--network",
        f"container:{owner_name}",
        "-e",
        f"PGPASSWORD={password}",
        "--entrypoint",
        "psql",
        POSTGRES_IMAGE,
        "-h",
        host,
        "-U",
        "comet",
        "-d",
        "comet",
        "-t",
        "-A",
        "-c",
        query,
        check=False,
    )


def _write_pg_test_compose(
    work_dir: Path, data_dir: Path, env_file: Path, owner_name: str
) -> tuple[Path, list[str]]:
    res = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            f"{PREFIX}config",
            "-f",
            str(REPO_ROOT / "docker-compose.yml"),
            "config",
            "--format",
            "json",
            "--no-env-resolution",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    repo_cfg = json.loads(res.stdout)
    repo_pg = repo_cfg["services"]["comet-postgres"]
    configs = repo_cfg.get("configs", {})
    referenced = {
        c["source"]: {"content": configs[c["source"]]["content"]}
        for c in repo_pg.get("configs", [])
        if isinstance(c, dict) and c.get("source") in configs
    }
    pg_service = {
        "image": repo_pg["image"],
        "restart": "no",
        "command": repo_pg["command"],
        "configs": repo_pg["configs"],
        "healthcheck": repo_pg["healthcheck"],
        "volumes": [f"{data_dir}:/var/lib/postgresql/"],
        "network_mode": f"container:{owner_name}",
        "env_file": [str(env_file)],
    }
    for field in ("cap_drop", "cap_add", "security_opt", "read_only", "tmpfs"):
        if field in repo_pg:
            pg_service[field] = repo_pg[field]
    doc = {"services": {"comet-postgres": pg_service}, "configs": referenced}
    compose_path = work_dir / "pg-compose.yml"
    compose_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return compose_path, list(repo_pg["healthcheck"]["test"])


@contextmanager
def _postgres_namespace_sandbox(tmp_path: Path) -> Iterator[dict[str, object]]:
    suffix = uuid.uuid4().hex[:8]
    owner_name = f"{PREFIX}pgowner-{suffix}"
    legacy_pg_name = f"{PREFIX}pglegacy-{suffix}"
    project = f"{PREFIX}pg-{suffix}"

    root = tmp_path / "stack"
    root.mkdir()
    shutil.copy2(REPO_ROOT / "docker-compose.yml", root / "docker-compose.yml")
    cfg = make_comet_config(root)
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    cfg.postgres_data_dir.mkdir(parents=True, exist_ok=True)

    env_file = cfg.state_dir / "postgres.env"
    env_file.write_text(
        "POSTGRES_USER=comet\nPOSTGRES_PASSWORD=comet\nPOSTGRES_DB=comet\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)

    owner_created = False
    legacy_created = False
    compose_path: Path | None = None
    try:
        _docker(
            "run",
            "-d",
            "--name",
            owner_name,
            "--network",
            "none",
            BUSYBOX_IMAGE,
            "sleep",
            "600",
        )
        owner_created = True

        # Initialize the data directory the legacy way (without hba_file / listen_addresses).
        _docker(
            "run",
            "-d",
            "--name",
            legacy_pg_name,
            "--network",
            f"container:{owner_name}",
            "-v",
            f"{cfg.postgres_data_dir}:/var/lib/postgresql/",
            "-e",
            "POSTGRES_USER=comet",
            "-e",
            "POSTGRES_PASSWORD=comet",
            "-e",
            "POSTGRES_DB=comet",
            POSTGRES_IMAGE,
            *LEGACY_PG_FLAGS,
        )
        legacy_created = True
        _wait_pg_ready(legacy_pg_name)

        compose_path, healthcheck_cmd = _write_pg_test_compose(
            tmp_path, cfg.postgres_data_dir, env_file, owner_name
        )
        yield {
            "suffix": suffix,
            "root": root,
            "cfg": cfg,
            "env_file": env_file,
            "owner_name": owner_name,
            "legacy_pg_name": legacy_pg_name,
            "project": project,
            "compose_path": compose_path,
            "healthcheck_cmd": healthcheck_cmd,
        }
    finally:
        if compose_path is not None:
            _compose(project, compose_path, "down", "-v", check=False)
        if legacy_created:
            _docker("rm", "-f", "-v", legacy_pg_name, check=False)
        if owner_created:
            _docker("rm", "-f", "-v", owner_name, check=False)
        _empty_subuid_dir(cfg.postgres_data_dir)


def _hba_sha256(data_dir: Path) -> str:
    out = _docker(
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{data_dir}:/pgdata:ro",
        BUSYBOX_IMAGE,
        "sh",
        "-c",
        'f=$(find /pgdata -name pg_hba.conf | head -n 1); test -n "$f" && sha256sum "$f"',
    ).stdout.strip()
    assert out
    return out.split()[0]


def test_ac12_ac13_ac14_real_postgres_hba_rotation_and_busy_guards(tmp_path: Path) -> None:
    """AC-12, AC-13, AC-14 (INV-6, INV-7): managed pg_hba, offline rotation, and busy guards."""
    with _postgres_namespace_sandbox(tmp_path) as sb:
        root = Path(str(sb["root"]))
        cfg = sb["cfg"]
        assert isinstance(cfg, type(make_comet_config(tmp_path)))
        env_file = Path(str(sb["env_file"]))
        owner_name = str(sb["owner_name"])
        legacy_pg_name = str(sb["legacy_pg_name"])
        project = str(sb["project"])
        compose_path = Path(str(sb["compose_path"]))
        healthcheck_cmd = list(sb["healthcheck_cmd"])  # type: ignore[arg-type]

        # --- AC-12 control: legacy init reproduces M1 (no-password TCP login succeeds) ---
        ctrl = _psql(owner_name, "127.0.0.1", "", "SELECT current_user;")
        assert ctrl.returncode == 0 and "comet" in ctrl.stdout, ctrl.stderr

        _docker("rm", "-f", "-v", legacy_pg_name)
        hba_before = _hba_sha256(cfg.postgres_data_dir)

        # Start managed comet-postgres from repository config
        _compose(project, compose_path, "up", "-d")
        pg_cid = _compose(project, compose_path, "ps", "-q", "comet-postgres").stdout.strip()
        assert pg_cid
        _wait_pg_ready(pg_cid)

        # Check 127.0.0.1 refuses empty & wrong passwords and accepts comet;
        # ::1 refuses all connections because listen_addresses=127.0.0.1 binds IPv4 loopback only.
        r_empty = _psql(owner_name, "127.0.0.1", "")
        assert r_empty.returncode != 0, r_empty.stdout
        r_wrong = _psql(owner_name, "127.0.0.1", "wrong-pw")
        assert r_wrong.returncode != 0, r_wrong.stdout
        r_ok = _psql(owner_name, "127.0.0.1", "comet", "SELECT 1;")
        assert r_ok.returncode == 0 and r_ok.stdout.strip() == "1", r_ok.stderr

        for pw in ("", "wrong-pw", "comet"):
            r_v6 = _psql(owner_name, "::1", pw)
            assert r_v6.returncode != 0, (pw, r_v6.stdout)

        # SHOW hba_file & pg_hba_file_rules
        hba_show = _psql(owner_name, "127.0.0.1", "comet", "SHOW hba_file;")
        assert hba_show.returncode == 0 and hba_show.stdout.strip() == "/etc/postgresql/pg_hba.conf"

        rules_res = _psql(
            owner_name,
            "127.0.0.1",
            "comet",
            "SELECT type || '|' || database::text || '|' || user_name::text || '|' || "
            "coalesce(address,'') || '|' || auth_method "
            "FROM pg_hba_file_rules ORDER BY rule_number;",
        )
        assert rules_res.returncode == 0
        rules = [ln.strip() for ln in rules_res.stdout.splitlines() if ln.strip()]
        assert rules == [
            "local|{all}|{all}||trust",
            "host|{all}|{all}|127.0.0.1|scram-sha-256",
            "host|{all}|{all}|::1|scram-sha-256",
        ], rules

        # Only 127.0.0.1:5432 is listening
        tcp_proc = _docker("exec", owner_name, "cat", "/proc/net/tcp", "/proc/net/tcp6").stdout
        listen_5432 = [
            ln.strip().split()[1]
            for ln in tcp_proc.splitlines()
            if len(ln.split()) > 3 and ln.split()[3] == "0A" and ln.split()[1].endswith(":1538")
        ]
        assert listen_5432 == ["0100007F:1538"], listen_5432

        # Compose healthcheck command exits 0
        assert healthcheck_cmd[0] == "CMD-SHELL"
        hc_res = _docker("exec", pg_cid, "sh", "-c", healthcheck_cmd[1], check=False)
        assert hc_res.returncode == 0, hc_res.stderr

        # Data dir's own pg_hba.conf unchanged
        assert _hba_sha256(cfg.postgres_data_dir) == hba_before

        # --- AC-14: busy container guards (running Postgres, paused busybox, other mount) ---
        seed_mgr = CometManager(cfg, SubprocessRunner())
        seed_mgr.write_runtime_env()
        orig_pg_env = env_file.read_bytes()
        orig_rt_env = cfg.runtime_env_file.read_bytes()

        class _NoOneOffRunner:
            def __init__(self) -> None:
                self._real = SubprocessRunner()
                self.calls: list[list[str]] = []
                self.inputs: list[str | None] = []

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
                self.calls.append(list(args))
                self.inputs.append(input)
                if args[:2] == ["docker", "run"]:
                    raise AssertionError(f"one-off docker run must not execute: {args}")
                return self._real.run(
                    args, check=check, capture=capture, timeout=timeout, env=env, input=input
                )

        # Verify temp compose resolves data dir inside temp root before any rotation call
        resolved_pg = json.loads(
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "-p",
                    f"{PREFIX}rotcheck",
                    "-f",
                    str(root / "docker-compose.yml"),
                    "config",
                    "--format",
                    "json",
                    "--no-env-resolution",
                    "comet-postgres",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )["services"]["comet-postgres"]["volumes"][0]["source"]
        assert Path(resolved_pg).resolve() == cfg.postgres_data_dir.resolve()
        assert Path(resolved_pg).resolve().is_relative_to(root.resolve())

        # (a) running Postgres
        no_run = _NoOneOffRunner()
        with pytest.raises(RuntimeError) as exc_14a:
            rotate_postgres_password(CometManager(cfg, no_run))
        assert pg_cid[:12] in str(exc_14a.value)
        assert env_file.read_bytes() == orig_pg_env
        assert cfg.runtime_env_file.read_bytes() == orig_rt_env
        assert _psql(owner_name, "127.0.0.1", "comet", "SELECT 1;").returncode == 0

        _compose(project, compose_path, "stop")

        # (b) paused busybox mounting data dir
        paused_name = f"{PREFIX}paused-{sb['suffix']}"
        paused_created = False
        try:
            paused_id = _docker(
                "run",
                "-d",
                "--name",
                paused_name,
                "--network",
                "none",
                "-v",
                f"{cfg.postgres_data_dir}:/var/lib/postgresql/",
                BUSYBOX_IMAGE,
                "sleep",
                "120",
            ).stdout.strip()
            paused_created = True
            _docker("pause", paused_name)
            with pytest.raises(RuntimeError) as exc_14b:
                rotate_postgres_password(CometManager(cfg, _NoOneOffRunner()))
            assert paused_id[:12] in str(exc_14b.value)
            assert env_file.read_bytes() == orig_pg_env
            assert cfg.runtime_env_file.read_bytes() == orig_rt_env
        finally:
            if paused_created:
                _docker("rm", "-f", "-v", paused_name, check=False)

        # (c) busybox mounting data dir at another path
        other_name = f"{PREFIX}other-{sb['suffix']}"
        other_created = False
        try:
            other_id = _docker(
                "run",
                "-d",
                "--name",
                other_name,
                "--network",
                "none",
                "-v",
                f"{cfg.postgres_data_dir}:/elsewhere",
                BUSYBOX_IMAGE,
                "sleep",
                "120",
            ).stdout.strip()
            other_created = True
            with pytest.raises(RuntimeError) as exc_14c:
                rotate_postgres_password(CometManager(cfg, _NoOneOffRunner()))
            assert other_id[:12] in str(exc_14c.value)
            assert env_file.read_bytes() == orig_pg_env
            assert cfg.runtime_env_file.read_bytes() == orig_rt_env
        finally:
            if other_created:
                _docker("rm", "-f", "-v", other_name, check=False)

        # --- AC-13: real offline rotation with Postgres stopped ---
        class _RecordingRunner:
            def __init__(self) -> None:
                self._real = SubprocessRunner()
                self.calls: list[list[str]] = []
                self.inputs: list[str | None] = []

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
                self.calls.append(list(args))
                self.inputs.append(input)
                return self._real.run(
                    args, check=check, capture=capture, timeout=timeout, env=env, input=input
                )

        rec_runner = _RecordingRunner()
        captured_logs: list[str] = []
        sink_id = logger.add(lambda msg: captured_logs.append(str(msg)), level="DEBUG")
        try:
            rotate_postgres_password(CometManager(cfg, rec_runner))
        finally:
            logger.remove(sink_id)

        new_pw = env_file_value(env_file, "POSTGRES_PASSWORD")
        assert new_pw is not None and len(new_pw) == 24 and new_pw != "comet"
        assert env_file.stat().st_mode & 0o777 == 0o600

        new_rt_lines = cfg.runtime_env_file.read_text(encoding="utf-8").splitlines()
        orig_rt_lines = orig_rt_env.decode("utf-8").splitlines()
        assert len(new_rt_lines) == len(orig_rt_lines)
        for old_ln, new_ln in zip(orig_rt_lines, new_rt_lines, strict=True):
            if old_ln.startswith("DATABASE_URL="):
                assert new_ln == f"DATABASE_URL={build_postgres_database_url(new_pw)}"
            else:
                assert new_ln == old_ln

        # Verify secret/verifier hygiene
        run_idx = next(i for i, c in enumerate(rec_runner.calls) if c[:2] == ["docker", "run"])
        sql_input = rec_runner.inputs[run_idx]
        assert sql_input is not None and "SCRAM-SHA-256$" in sql_input
        for argv in rec_runner.calls:
            joined = " ".join(argv)
            assert new_pw not in joined
            assert "SCRAM-SHA-256$" not in joined
        for inp in rec_runner.inputs:
            if inp is not None:
                assert new_pw not in inp
        all_logs = "\n".join(captured_logs)
        assert new_pw not in all_logs
        assert "SCRAM-SHA-256$" not in all_logs

        # One-off container is gone
        leftover = _docker(
            "ps", "-a", "-q", "--filter", "name=stremioguard-comet-dbpw-"
        ).stdout.strip()
        assert leftover == "", leftover

        # Start Postgres again; verify new password works, comet/empty fail, Comet is healthy
        _compose(project, compose_path, "start")
        _wait_pg_ready(pg_cid)
        assert _psql(owner_name, "127.0.0.1", new_pw, "SELECT 1;").returncode == 0
        assert _psql(owner_name, "127.0.0.1", "comet", "SELECT 1;").returncode != 0
        assert _psql(owner_name, "127.0.0.1", "", "SELECT 1;").returncode != 0

        comet_name = f"{PREFIX}comet-{sb['suffix']}"
        comet_created = False
        try:
            _docker(
                "run",
                "-d",
                "--name",
                comet_name,
                "--network",
                f"container:{owner_name}",
                "--env-file",
                str(cfg.runtime_env_file),
                COMET_IMAGE,
            )
            comet_created = True
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                hc = _docker(
                    "exec",
                    comet_name,
                    "/app/.venv/bin/python",
                    "-c",
                    "import urllib.request; print(urllib.request.urlopen("
                    "'http://127.0.0.1:8000/health', timeout=2).read().decode())",
                    check=False,
                )
                if hc.returncode == 0 and '"status":"ok"' in hc.stdout.replace(" ", ""):
                    break
                time.sleep(0.5)
            else:
                logs = _docker("logs", comet_name, check=False)
                raise AssertionError(f"Comet never became healthy:\n{logs.stdout}\n{logs.stderr}")
        finally:
            if comet_created:
                _docker("rm", "-f", "-v", comet_name, check=False)
