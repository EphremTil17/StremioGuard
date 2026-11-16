"""Opt-in real-Docker proofs for offline deep validation (AC-9, AC-11).

Run with:
  STREMIOGUARD_DOCKER_TESTS=1 .venv/bin/python -m pytest -s -v tests/test_comet_validation_docker.py
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from stremioguard.comet.manager import extract_image_source
from stremioguard.comet.validation import ephemeral_boot_check
from stremioguard.config import SubprocessRunner
from stremioguard.overrides import write_override_bundle

COMET_IMAGE_NEW = (
    "g0ldyy/comet@sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea"
)
COMET_IMAGE_OLD = (
    "g0ldyy/comet@sha256:dca62133336e02784d02aaad861381820674d1c8e3e98a03797610b81ee4defe"
)
BUSYBOX_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="needs real Docker containers; set STREMIOGUARD_DOCKER_TESTS=1",
)


class _InspectingRunner:
    """Wraps SubprocessRunner, records argv, and inspects the candidate during boot."""

    def __init__(self, *, inspect_network: bool = True) -> None:
        self._real = SubprocessRunner()
        self._inspect_network = inspect_network
        self.calls: list[list[str]] = []
        self.container_ids: list[str] = []
        self.observed_network_modes: list[str] = []
        self.observed_net_ifaces: list[list[str]] = []

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
        result = self._real.run(
            args, check=check, capture=capture, timeout=timeout, env=env, input=input
        )
        if args[:3] == ["docker", "run", "-d"] and result.returncode == 0:
            cid = (result.stdout or "").strip()
            if cid:
                self.container_ids.append(cid)
                if self._inspect_network:
                    mode = subprocess.run(
                        ["docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", cid],
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.strip()
                    ifaces = subprocess.run(
                        ["docker", "exec", cid, "ls", "/sys/class/net"],
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.split()
                    self.observed_network_modes.append(mode)
                    self.observed_net_ifaces.append(ifaces)
        return result


def test_ac9_ephemeral_boot_check_real_comet_images_offline(tmp_path: Path) -> None:
    """AC-9 (INV-5): real ephemeral_boot_check passes on both pinned Comet images offline."""
    runner = _InspectingRunner(inspect_network=True)
    durations: list[str] = []

    # 1. Live shape against 31a41fa6
    generated_root = tmp_path / "generated"
    with extract_image_source(runner, COMET_IMAGE_NEW) as source_root:
        assert (source_root / "comet").exists()
        write_override_bundle(
            repo_dir=source_root,
            state_dir=generated_root,
            result_format_style="plain",
            patch_episode_pack_results=True,
            gateway_addon_base_url="https://comet.example.com/comet/tok123",
            gateway_enabled=True,
            image_digest="sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea",
            patch_fingerprint="ac9-test",
        )
        manifest = json.loads((generated_root / "bundle-manifest.json").read_text(encoding="utf-8"))
        outputs = manifest.get("outputs", {})
        assert isinstance(outputs, dict) and outputs

        start_new = time.monotonic()
        res_new = ephemeral_boot_check(runner, COMET_IMAGE_NEW, outputs, generated_root)
        dur_new = time.monotonic() - start_new
        durations.append(f"31a41fa6: {dur_new:.2f}s")
        assert res_new == {"status": "passed", "stage": "deep", "detail": ""}

    # 2. Old image dca62133 with outputs={}
    start_old = time.monotonic()
    res_old = ephemeral_boot_check(runner, COMET_IMAGE_OLD, {}, tmp_path)
    dur_old = time.monotonic() - start_old
    durations.append(f"dca62133: {dur_old:.2f}s")
    assert res_old == {"status": "passed", "stage": "deep", "detail": ""}

    assert runner.observed_network_modes == ["none", "none"]
    assert runner.observed_net_ifaces == [["lo"], ["lo"]]

    for argv in runner.calls:
        joined = " ".join(argv)
        assert "network create" not in joined, argv
        assert "wget" not in argv, argv

    assert len(runner.container_ids) == 2
    for cid in runner.container_ids:
        check_gone = subprocess.run(
            ["docker", "inspect", cid], check=False, capture_output=True, text=True
        )
        assert check_gone.returncode != 0, cid

    nets = subprocess.run(
        ["docker", "network", "ls", "--filter", "name=stremioguard-comet-deep-", "-q"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert nets == "", nets

    print("\nAC-9 durations: " + ", ".join(durations))


def test_ac11_ephemeral_boot_check_timeout_and_cleanup_on_unresponsive_image(
    tmp_path: Path,
) -> None:
    """AC-11 (INV-5): busybox candidate fails within timeout_seconds + 6s and container is gone."""
    runner = _InspectingRunner(inspect_network=False)
    timeout_seconds = 6
    start = time.monotonic()
    res = ephemeral_boot_check(runner, BUSYBOX_IMAGE, {}, tmp_path, timeout_seconds=timeout_seconds)
    elapsed = time.monotonic() - start

    assert res["status"] == "failed"
    assert "never became reachable" in str(res["detail"])
    assert elapsed < timeout_seconds + 6.0, f"took {elapsed:.2f}s >= {timeout_seconds + 6.0}s"
    assert len(runner.container_ids) == 1
    check_gone = subprocess.run(
        ["docker", "inspect", runner.container_ids[0]],
        check=False,
        capture_output=True,
        text=True,
    )
    assert check_gone.returncode != 0
