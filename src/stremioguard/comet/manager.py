from __future__ import annotations

import dataclasses
import hashlib
import json
import secrets
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from loguru import logger

from stremioguard.comet.lock import CometLock
from stremioguard.comet.probe import PlaybackProbeResult, probe_playback_url
from stremioguard.comet.state import STATE_FILE_NAME, CandidateDigest, CometState
from stremioguard.comet.validation import ephemeral_boot_check, import_smoke_test
from stremioguard.comet_gateway import (
    COMET_GATEWAY_CONTAINER_PORT,
    CometGatewayConfig,
    CometGatewayManager,
)
from stremioguard.config import (
    GENERATED_COMPOSE_FILE,
    CometConfig,
    Runner,
    SubprocessRunner,
)
from stremioguard.env import atomic_write_text, ensure_directory, env_file_value
from stremioguard.overrides import write_override_bundle
from stremioguard.preflight import require_docker, verify_bind_addresses
from stremioguard.publishing import StackPublisher

ADVISORY_CHECK_INTERVAL_SECONDS = 24 * 3600

# A cached "passed" result is only reusable for a request at the same or a
# LOWER stage — a compile-only-era cache entry (no "stage" key) must never
# satisfy today's mandatory import-smoke requirement, and an import-level
# cache entry must never satisfy an explicit --deep request.
_VALIDATION_STAGE_RANK = {"import": 1, "deep": 2}


@contextmanager
def extract_image_source(runner: Runner, image_ref: str) -> Iterator[Path]:
    container_id: str | None = None
    with tempfile.TemporaryDirectory(prefix="stremioguard-comet-") as directory:
        temp_root = Path(directory)
        source_root = temp_root / "image-root"
        source_root.mkdir()
        try:
            created = runner.run(["docker", "create", image_ref], check=True)
            container_id = (created.stdout or "").strip()
            if not container_id:
                raise RuntimeError("Docker created no temporary container ID")
            runner.run(["docker", "cp", f"{container_id}:/app/comet", str(source_root)], check=True)
            yield source_root
        finally:
            if container_id:
                runner.run(["docker", "rm", "-f", container_id], check=False, capture=False)


class CometManager:
    def __init__(self, config: CometConfig, runner: Runner | None = None) -> None:
        self.config = config
        self.runner = runner or SubprocessRunner()
        self._warned_legacy_postgres = False

    def log(self, message: str) -> None:
        logger.info(message)

    def warn(self, message: str) -> None:
        logger.warning(message)

    def success(self, message: str) -> None:
        logger.success(message)

    def load_lock(self) -> CometLock:
        return CometLock.load(self.config.lock_file)

    def state_file(self) -> Path:
        return self.config.state_dir / STATE_FILE_NAME

    def load_state(self) -> CometState:
        return CometState.load(self.state_file())

    def save_state(self, state: CometState) -> None:
        ensure_directory(self.config.state_dir)
        state.save(self.state_file())

    def active_image_ref(self) -> str:
        """The digest-pinned reference compose/validation must use.

        Returns `<repo>@<digest>` once `state.json` has resolved an active
        digest. Falls back to the floating repo/tag string only for the
        one-time pre-migration window before `prepare_runtime` has ever run
        for this install — never once state exists (Phase 4 / plan 4.2)."""
        state = self.load_state()
        if state.active_digest:
            return f"{self.config.image}@{state.active_digest}"
        return self.config.image

    def repo_exists(self) -> bool:
        return (self.config.repo_dir / ".git").exists()

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self.runner.run(["git", *args], check=check)

    def clone_if_missing(self) -> None:
        if self.repo_exists():
            return
        lock = self.load_lock()
        self.config.vendor_dir.mkdir(parents=True, exist_ok=True)
        self.log(f"Cloning Comet into {self.config.repo_dir}.")
        self._git("clone", lock.upstream_url, str(self.config.repo_dir))

    def fetch_and_checkout_pinned(self) -> None:
        lock = self.load_lock()
        self.clone_if_missing()

        dirty = self._git("-C", str(self.config.repo_dir), "status", "--porcelain", check=False)
        if (dirty.stdout or "").strip():
            self.warn(
                f"Comet checkout at {self.config.repo_dir} has local changes. "
                "Leaving them in place, but switching commits may fail."
            )

        self.log("Fetching latest upstream refs for Comet.")
        self._git("-C", str(self.config.repo_dir), "fetch", "origin")
        self.log(f"Checking out pinned Comet commit {lock.pinned_commit}.")
        self._git("-C", str(self.config.repo_dir), "checkout", "--detach", lock.pinned_commit)

    def current_commit(self) -> str | None:
        if not self.repo_exists():
            return None
        result = self._git("-C", str(self.config.repo_dir), "rev-parse", "HEAD", check=False)
        if result.returncode != 0:
            return None
        return (result.stdout or "").strip() or None

    def stremio_host_port(self) -> int:
        return self.config.stremio_host_port

    def stremio_container_port(self) -> int:
        return self.config.stremio_container_port

    def root_compose_file(self) -> Path:
        return self.config.root_dir / "docker-compose.yml"

    def root_override_file(self) -> Path:
        return self.config.root_dir / GENERATED_COMPOSE_FILE

    def gateway_config(self) -> CometGatewayConfig:
        return CometGatewayConfig.from_env(self.config.root_dir)

    def gateway_manager(self) -> CometGatewayManager:
        return CometGatewayManager(self.gateway_config(), self.runner)

    def gateway_addon_base_url(self) -> str | None:
        gateway_config = self.gateway_config()
        if not gateway_config.enabled:
            return None
        gateway_manager = self.gateway_manager()
        default_token = gateway_manager.default_token()
        if not default_token:
            return None
        if not gateway_config.public_base_url:
            return f"/comet/{default_token}"
        return gateway_manager.addon_base_url(default_token)

    def write_stack_override_file(self) -> None:
        # Publishes the compose override from the existing bundle manifest.
        # Bundle GENERATION happens only in prepare_runtime, rendered from the
        # active image's own source — regenerating here from the vendored
        # checkout would clobber the image-derived bundle and reopen the
        # vendored-vs-image coherence gap.
        ensure_directory(self.config.state_dir)
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.postgres_data_dir.mkdir(parents=True, exist_ok=True)
        gateway_config = self.gateway_config()
        gateway_manager = CometGatewayManager(gateway_config, self.runner)
        if gateway_config.enabled:
            gateway_manager.prepare_runtime()
        publisher = StackPublisher(self.config.root_dir, self.root_override_file())
        publisher.publish()

    def postgres_env_file(self) -> Path:
        return self.config.state_dir / "postgres.env"

    def _resolve_postgres_password(self) -> str:
        env_path = self.postgres_env_file()
        if env_path.exists():
            existing = env_file_value(env_path, "POSTGRES_PASSWORD")
            if existing:
                return existing
        # Postgres bakes its password into the data directory at first init, so a
        # data dir that predates postgres.env was created with the legacy
        # 'comet' password and cannot be rotated in place. Keep it and tell the
        # user how to adopt a generated password.
        data_dir = self.config.postgres_data_dir
        if data_dir.exists() and any(data_dir.iterdir()):
            if not self._warned_legacy_postgres:
                self.warn(
                    "Postgres data was initialized with the legacy 'comet' password. "
                    "To adopt a generated password, run `./stremio comet stop`, delete "
                    f"{data_dir}, then start again."
                )
                self._warned_legacy_postgres = True
            return "comet"
        return secrets.token_urlsafe(18)

    def _write_postgres_env(self, password: str) -> None:
        ensure_directory(self.config.state_dir)
        content = "\n".join(
            [
                "# Generated by ./stremio; do not edit by hand.",
                "POSTGRES_USER=comet",
                f"POSTGRES_PASSWORD={password}",
                "POSTGRES_DB=comet",
                "",
            ]
        )
        atomic_write_text(self.postgres_env_file(), content, mode=0o600)

    def render_runtime_env(self) -> str:
        existing = self.config.runtime_env_file if self.config.runtime_env_file.exists() else None
        admin_password = (
            env_file_value(existing, "ADMIN_DASHBOARD_PASSWORD") if existing else None
        ) or secrets.token_urlsafe(18)
        configure_password = (
            (env_file_value(existing, "CONFIGURE_PAGE_PASSWORD") if existing else None)
            or self.config.configure_page_password
            or secrets.token_urlsafe(18)
        )
        proxy_password = (
            env_file_value(existing, "PROXY_DEBRID_STREAM_PASSWORD") if existing else None
        ) or secrets.token_urlsafe(18)
        gateway_config = self.gateway_config()
        public_base_url = "" if gateway_config.enabled else self.config.public_base_url or ""
        api_key = self.config.default_debrid_apikey or ""
        return "\n".join(
            [
                "# Generated by ./stremio comet install; do not edit by hand.",
                "DATABASE_TYPE=postgresql",
                f"DATABASE_URL=comet:{self._resolve_postgres_password()}@127.0.0.1:5432/comet",
                f"PUBLIC_BASE_URL={public_base_url}",
                f"ADMIN_DASHBOARD_PASSWORD={admin_password}",
                f"CONFIGURE_PAGE_PASSWORD={configure_password}",
                f"PROXY_DEBRID_STREAM={'True' if self.config.proxy_debrid_stream else 'False'}",
                f"PROXY_DEBRID_STREAM_PASSWORD={proxy_password}",
                f"PROXY_DEBRID_STREAM_MAX_CONNECTIONS={self.config.proxy_max_connections}",
                f"SCRAPE_TORRENTIO={self.config.scrape_torrentio}",
                f"TORRENTIO_URL={self.config.torrentio_url}",
                f"SCRAPE_ZILEAN={self.config.scrape_zilean}",
                f"ZILEAN_URL={self.config.zilean_url}",
                f"PROXY_DEBRID_STREAM_DEBRID_DEFAULT_SERVICE={self.config.default_debrid_service}",
                f"PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY={api_key}",
                "",
            ]
        )

    def write_runtime_env(self) -> None:
        ensure_directory(self.config.state_dir)
        # Resolve and persist the Postgres password first so postgres.env and the
        # DATABASE_URL rendered below agree on the same value.
        self._write_postgres_env(self._resolve_postgres_password())
        atomic_write_text(self.config.runtime_env_file, self.render_runtime_env(), mode=0o600)

    def _managed_patch_fingerprint(self) -> str:
        digest = hashlib.sha256()
        override_root = Path(__file__).resolve().parent.parent / "overrides"
        project_root = override_root.parent.parent
        files = sorted(override_root.rglob("*.py")) + [
            Path(__file__).resolve().parent.parent / "metadata.py"
        ]
        for path in files:
            if not path.is_file():
                continue
            digest.update(str(path.relative_to(project_root)).encode())
            digest.update(path.read_bytes())
        return digest.hexdigest()

    def _image_digest(self, image_ref: str | None = None) -> str:
        image_ref = image_ref or self.config.image
        result = self.runner.run(
            ["docker", "image", "inspect", image_ref, "--format", "{{json .RepoDigests}}"],
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "unknown Docker error").strip()
            raise RuntimeError(f"Unable to inspect Comet image {image_ref!r}: {detail}")
        try:
            digests = json.loads((result.stdout or "").strip() or "[]")
        except json.JSONDecodeError:
            digests = []
        if isinstance(digests, list):
            for value in digests:
                if isinstance(value, str) and "@" in value:
                    return value.rsplit("@", 1)[1]
        image_id = self.runner.run(
            ["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"], check=False
        )
        value = (image_id.stdout or "").strip()
        if image_id.returncode == 0 and value:
            return value
        raise RuntimeError(f"Comet image {image_ref!r} has no inspectable digest or image ID.")

    def ensure_image(self, image_ref: str | None = None) -> str:
        image_ref = image_ref or self.config.image
        result = self.runner.run(["docker", "image", "inspect", image_ref], check=False)
        if result.returncode != 0:
            self.log(f"Pulling Comet image {image_ref}.")
            self.runner.run(["docker", "pull", image_ref], check=True, capture=False)
        return self._image_digest(image_ref)

    def _remote_digest(self, tag: str = "latest") -> str | None:
        """Resolve the manifest-list digest of `<image>:<tag>` WITHOUT pulling.

        Uses `docker buildx imagetools inspect`, which returns the same
        manifest-list digest form recorded in `RepoDigests` after a pull (both
        are index/manifest-list digests, directly comparable). Advisory only:
        any failure (missing buildx, offline, hung registry, rate limit)
        returns None rather than raising — callers must treat this as
        best-effort.
        """
        try:
            result = self.runner.run(
                [
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                    f"{self.config.image}:{tag}",
                    "--format",
                    "{{json .Manifest.Digest}}",
                ],
                check=False,
                timeout=20,
            )
        except subprocess.TimeoutExpired:
            return None
        if result.returncode != 0:
            return None
        raw = (result.stdout or "").strip().strip('"')
        return raw or None

    def _compatibility_cache_valid(
        self, image_digest: str, source_commit: str, patch_fingerprint: str, *, deep: bool = False
    ) -> bool:
        cache_file = self.config.state_dir / "compatibility.json"
        if not cache_file.exists():
            return False
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        required_rank = _VALIDATION_STAGE_RANK["deep" if deep else "import"]
        cached_rank = _VALIDATION_STAGE_RANK.get(cached.get("stage"), 0)
        return (
            cached_rank >= required_rank
            and all(
                cached.get(key) == value
                for key, value in {
                    "image": self.config.image,
                    "image_digest": image_digest,
                    "source_commit": source_commit,
                    "patch_fingerprint": patch_fingerprint,
                }.items()
            )
            and cached.get("status") == "passed"
        )

    def _manifest_cache_valid(self, image_digest: str, patch_fingerprint: str) -> bool:
        manifest_path = self.config.state_dir / "bundle-manifest.json"
        if not manifest_path.exists():
            return False
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            return (
                manifest.get("image_digest") == image_digest
                and manifest.get("patch_fingerprint") == patch_fingerprint
                and manifest.get("format_style") == self.config.result_format_style
                and manifest.get("patch_episode_pack") == self.config.patch_episode_pack_results
                and manifest.get("gateway_addon_base_url") == self.gateway_addon_base_url()
            )
        except Exception:
            return False

    def _compatibility_diagnostic(self, error: Exception, source_root: Path) -> str:
        text = str(error)
        lowered = text.lower()
        if "orchestration" in lowered or "episode-pack" in lowered:
            patch = "episode-pack orchestration"
            source_file = "comet/services/orchestration.py"
            optional = True
        elif "stream" in lowered:
            patch = "stream formatting and playback"
            source_file = "comet/api/endpoints/stream.py"
            optional = False
        elif "torrentio" in lowered:
            patch = "Torrentio normalization"
            source_file = "comet/scrapers/torrentio.py"
            optional = False
        elif "filter" in lowered:
            patch = "torrent filtering"
            source_file = "comet/services/filtering.py"
            optional = False
        else:
            patch = "managed Comet overrides"
            source_file = "comet/services/orchestration.py"
            optional = False
        actual = source_root / source_file
        nearby = "<source file was not copied from the image>"
        if actual.exists():
            nearby = "".join(
                actual.read_text(encoding="utf-8", errors="replace").splitlines(True)[:30]
            ).rstrip()
        action = (
            "Update the StremioGuard patch generator for this release, or disable the optional "
            "episode-pack patch with COMET_PATCH_EPISODE_PACK_RESULTS=0."
            if optional
            else (
                "Update the required StremioGuard patch for this Comet release "
                "before starting the deployment."
            )
        )
        return (
            "Comet compatibility check failed.\n\n"
            f"Image: {self.config.image}\n"
            f"Digest: {self._image_digest(self.active_image_ref())}\n"
            f"Patch: {patch}\n"
            f"File: {source_file}\n"
            f"Failure type: {type(error).__name__}\n"
            f"Expected anchor or error: {text}\n\n"
            f"Nearby upstream code:\n{nearby}\n\n"
            f"Recommended action:\n{action}"
        )

    def validate_compatibility(self, *, force: bool = False, deep: bool = False) -> None:
        image_ref = self.active_image_ref()
        image_digest = self.ensure_image(image_ref)
        source_commit = self.current_commit() or self.load_lock().pinned_commit
        patch_fingerprint = self._managed_patch_fingerprint()
        if not force and self._compatibility_cache_valid(
            image_digest, source_commit, patch_fingerprint, deep=deep
        ):
            return

        with tempfile.TemporaryDirectory(prefix="stremioguard-comet-") as directory:
            temp_root = Path(directory)
            generated_root = temp_root / "generated"
            with extract_image_source(self.runner, image_ref) as source_root:
                image_repo = source_root / "comet"
                if not image_repo.exists():
                    raise RuntimeError("the image does not contain /app/comet")
                try:
                    write_override_bundle(
                        repo_dir=source_root,
                        state_dir=generated_root,
                        result_format_style=self.config.result_format_style,
                        patch_episode_pack_results=self.config.patch_episode_pack_results,
                        gateway_addon_base_url=self.gateway_addon_base_url(),
                        gateway_enabled=self.gateway_config().enabled,
                        image_digest=image_digest,
                        patch_fingerprint=patch_fingerprint,
                    )
                    generated_files = sorted(generated_root.glob("*.py"))
                    for generated_file in generated_files:
                        compile(
                            generated_file.read_text(encoding="utf-8"),
                            str(generated_file),
                            "exec",
                        )
                    manifest = json.loads(
                        (generated_root / "bundle-manifest.json").read_text(encoding="utf-8")
                    )
                except Exception as error:
                    diag = self._compatibility_diagnostic(error, source_root)
                    raise RuntimeError(diag) from error

            outputs = manifest.get("outputs", {})
            smoke = import_smoke_test(self.runner, image_ref, outputs, generated_root)
            if smoke["status"] != "passed":
                raise RuntimeError(
                    "Comet compatibility check failed at the import-smoke stage.\n\n"
                    f"{smoke['detail']}"
                )
            if deep:
                deep_result = ephemeral_boot_check(self.runner, image_ref, outputs, generated_root)
                if deep_result["status"] != "passed":
                    raise RuntimeError(
                        "Comet compatibility check failed at the ephemeral-boot stage.\n\n"
                        f"{deep_result['detail']}"
                    )

        cache = {
            "status": "passed",
            "image": self.config.image,
            "image_digest": image_digest,
            "source_commit": source_commit,
            "patch_fingerprint": patch_fingerprint,
            "patch_count": len(generated_files),
            "stage": "deep" if deep else "import",
        }
        ensure_directory(self.config.state_dir)
        atomic_write_text(
            self.config.state_dir / "compatibility.json",
            json.dumps(cache, indent=2) + "\n",
            mode=0o600,
        )
        self.success(
            "Comet compatibility check passed.\n"
            f"Image: {self.config.image}\n"
            f"Digest: {image_digest}\n"
            f"Patches: {len(generated_files)} validated"
        )

    def require_commands(self) -> None:
        require_docker(
            self.runner,
            install_missing=False,
            log=self.log,
            warn=self.warn,
        )

    def _compose_command(self, *args: str) -> list[str]:
        return [
            "docker",
            "compose",
            "-f",
            str(self.root_compose_file()),
            "-f",
            str(self.root_override_file()),
            *args,
        ]

    def compose(
        self, *args: str, check: bool = True, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        if not self.root_override_file().exists():
            self.write_stack_override_file()
        return self.runner.run(self._compose_command(*args), check=check, capture=capture)

    def compose_fresh(
        self, *args: str, check: bool = True, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        self.write_stack_override_file()
        return self.runner.run(self._compose_command(*args), check=check, capture=capture)

    def install(self, *, deep: bool = False) -> None:
        self.prepare_runtime(deep=deep)
        if sys.stdin.isatty():
            import typer

            if typer.confirm(
                "The current Comet image will be checked against the installed "
                "StremioGuard patches.\nRun compatibility check now?",
                default=True,
            ):
                self.validate_compatibility(deep=deep)
            else:
                self.warn(
                    "Skipped compatibility validation; the next Comet start will "
                    "validate the image automatically."
                )
        else:
            self.validate_compatibility(deep=deep)

    def _validate_digest(self, digest: str, *, deep: bool = False) -> dict[str, object]:
        """Render + compile the override bundle from `digest`'s own image
        source, in an isolated temp dir; then import-smoke-test every applied
        override against the candidate image itself, and optionally
        (`deep=True`) boot it ephemerally and probe /health + /manifest.json.
        Never touches the live state_dir or bundle-manifest.json, and never
        touches running services.

        Returns {"status": "passed"|"failed", "detail": str, "degraded": [...]}.
        `degraded` lists OPTIONAL patches that failed to apply even on a
        "passed" result (write_override_bundle only raises for a patch this
        deployment shape actually requires; optional skips are non-fatal).
        """
        image_ref = f"{self.config.image}@{digest}"
        pull_check = self.runner.run(["docker", "image", "inspect", image_ref], check=False)
        if pull_check.returncode != 0:
            self.runner.run(["docker", "pull", image_ref], check=True, capture=False)

        patch_fingerprint = self._managed_patch_fingerprint()
        try:
            with tempfile.TemporaryDirectory(prefix="stremioguard-comet-") as directory:
                generated_root = Path(directory) / "generated"
                with extract_image_source(self.runner, image_ref) as source_root:
                    if not (source_root / "comet").exists():
                        raise RuntimeError("the image does not contain /app/comet")
                    write_override_bundle(
                        repo_dir=source_root,
                        state_dir=generated_root,
                        result_format_style=self.config.result_format_style,
                        patch_episode_pack_results=self.config.patch_episode_pack_results,
                        gateway_addon_base_url=self.gateway_addon_base_url(),
                        gateway_enabled=self.gateway_config().enabled,
                        image_digest=digest,
                        patch_fingerprint=patch_fingerprint,
                    )
                    for generated_file in sorted(generated_root.glob("*.py")):
                        compile(
                            generated_file.read_text(encoding="utf-8"),
                            str(generated_file),
                            "exec",
                        )
                    manifest = json.loads(
                        (generated_root / "bundle-manifest.json").read_text(encoding="utf-8")
                    )

                outputs = manifest.get("outputs", {})
                smoke = import_smoke_test(self.runner, image_ref, outputs, generated_root)
                if smoke["status"] != "passed":
                    raise RuntimeError(f"import-smoke test failed:\n{smoke['detail']}")
                if deep:
                    deep_result = ephemeral_boot_check(
                        self.runner, image_ref, outputs, generated_root
                    )
                    if deep_result["status"] != "passed":
                        raise RuntimeError(f"ephemeral-boot check failed:\n{deep_result['detail']}")
        except Exception as error:
            return {"status": "failed", "detail": str(error), "degraded": [], "applied": []}
        return {
            "status": "passed",
            "detail": "",
            "degraded": manifest.get("skipped", []),
            "applied": manifest.get("applied", []),
        }

    def _bootstrap_active_digest(self, *, deep: bool = False) -> None:
        """First-run digest resolution (plan 4.3): validate the newest image;
        fall back to the maintainer-tested digest from the lock file if a
        REQUIRED patch fails, so a new install can never be bricked by an
        upstream release StremioGuard's patches don't cover yet."""
        self.log(f"Resolving initial Comet image digest for {self.config.image}:latest.")
        self.runner.run(
            ["docker", "pull", f"{self.config.image}:latest"], check=True, capture=False
        )
        latest_digest = self._image_digest(f"{self.config.image}:latest")
        report = self._validate_digest(latest_digest, deep=deep)

        if report["status"] == "passed":
            degraded = report.get("degraded") or []
            accept_latest = True
            names = ""
            if degraded:
                names = ", ".join(
                    f"{d['name']} ({d['reason']})"
                    for d in degraded  # type: ignore[union-attr]
                )
                if sys.stdin.isatty():
                    import typer

                    accept_latest = typer.confirm(
                        f"Comet {self.config.image}:latest ({latest_digest}) has degraded "
                        f"optional features: {names}\nUse it as the active version anyway? "
                        "(Declining falls back to the last maintainer-validated image.)",
                        default=True,
                    )
            if accept_latest:
                if degraded:
                    self.warn(
                        f"Comet {self.config.image}@{latest_digest} is active with degraded "
                        f"optional features: {names}"
                    )
                else:
                    self.success(
                        f"Comet image {self.config.image}@{latest_digest} fully validated "
                        "and set as the active version."
                    )
                self.save_state(dataclasses.replace(self.load_state(), active_digest=latest_digest))
                return
            latest_problem = f"declined: degraded optional features ({names})"
        else:
            latest_problem = (
                f"not yet compatible with a required StremioGuard patch:\n{report['detail']}"
            )

        lock = self.load_lock()
        tested_digest = lock.tested_digest
        self.warn(
            f"The newest Comet image ({self.config.image}:latest -> {latest_digest}) is "
            f"{latest_problem}\n\n"
            f"Falling back to the last maintainer-validated image ({tested_digest})."
        )
        fallback_report = self._validate_digest(tested_digest, deep=deep)
        if fallback_report["status"] != "passed":
            raise RuntimeError(
                "Comet compatibility check failed for the maintainer-tested fallback "
                "digest in vendor/comet.lock.json. This indicates a bug in the "
                "StremioGuard patch generators, not your configuration.\n\n"
                f"Newest image ({latest_digest}): {latest_problem}\n\n"
                f"Fallback digest ({tested_digest}) failure:\n{fallback_report['detail']}"
            )
        self.save_state(dataclasses.replace(self.load_state(), active_digest=tested_digest))
        self.warn(
            f"Comet is running on {self.config.image}@{tested_digest}, the last "
            "maintainer-validated image — not the newest upstream release. Update "
            "StremioGuard and run `./stremio comet update` once support ships."
        )

    def prepare_runtime(self, *, deep: bool = False) -> None:
        self.write_runtime_env()
        state = self.load_state()
        if state.active_digest is None:
            self._bootstrap_active_digest(deep=deep)
            state = self.load_state()

        image_ref = f"{self.config.image}@{state.active_digest}"
        image_digest = self.ensure_image(image_ref)
        patch_fingerprint = self._managed_patch_fingerprint()

        if self._manifest_cache_valid(image_digest, patch_fingerprint):
            self.write_stack_override_file()
            return

        self.log(
            "Cache miss for Comet override bundle. "
            f"Extracting and rendering from image: {image_ref}"
        )
        with extract_image_source(self.runner, image_ref) as source_root:
            write_override_bundle(
                repo_dir=source_root,
                state_dir=self.config.state_dir,
                result_format_style=self.config.result_format_style,
                patch_episode_pack_results=self.config.patch_episode_pack_results,
                gateway_addon_base_url=self.gateway_addon_base_url(),
                gateway_enabled=self.gateway_config().enabled,
                image_digest=image_digest,
                patch_fingerprint=patch_fingerprint,
            )
        self.write_stack_override_file()

    def check_bind_addresses(self) -> None:
        verify_bind_addresses(
            self.runner,
            list(self.config.bind_addresses),
            log=self.log,
            warn=self.warn,
        )

    def _comet_services(self) -> list[str]:
        services = [self.config.postgres_service_name, self.config.service_name]
        if self.gateway_config().enabled:
            services.append(self.gateway_config().service_name)
        return services

    def start(self) -> None:
        self.require_commands()
        self.prepare_runtime()
        self.validate_compatibility()
        self.check_bind_addresses()
        self.log("Starting Comet stack.")
        self.compose_fresh("up", "-d", *self._comet_services(), capture=False)
        self.advisory_update_check()

    def advisory_update_check(self) -> None:
        """Throttled, start-time nudge (plan 5.2): compare against `:latest`
        at most once per `ADVISORY_CHECK_INTERVAL_SECONDS` and log a single
        line if a newer digest exists. Never pulls, never validates, never
        raises — a registry hiccup must not affect a start/restart."""
        try:
            state = self.load_state()
            if state.active_digest is None:
                return
            if state.last_remote_check:
                elapsed = datetime.now(UTC) - datetime.fromisoformat(state.last_remote_check)
                if elapsed < timedelta(seconds=ADVISORY_CHECK_INTERVAL_SECONDS):
                    return
            new_digest = self.check_remote()
            if new_digest:
                self.log(
                    f"Comet update available ({self.config.image}@{new_digest}) — "
                    "run `./stremio comet update`."
                )
        except Exception:
            # loguru wants opt(exception=True); stdlib-style exc_info= is a no-op.
            logger.opt(exception=True).debug("Comet advisory update check failed.")

    def resolve_remote_digest(self) -> str | None:
        """Resolve the remote `:latest` digest and record the check timestamp.
        Returns None ONLY when the registry probe fails — unlike check_remote,
        an unchanged digest is still returned, so callers that must tell
        "up to date" apart from "could not reach the registry" (the explicit
        `comet update check` command) can. Never pulls, never touches running
        services."""
        remote_digest = self._remote_digest()
        state = self.load_state()
        self.save_state(
            dataclasses.replace(
                state, last_remote_check=datetime.now(UTC).isoformat(timespec="seconds")
            )
        )
        return remote_digest

    def check_remote(self) -> str | None:
        """Resolve the remote `:latest` digest and record the check timestamp.
        Returns the new digest if it differs from active, else None (including
        when the probe fails — advisory contract; use resolve_remote_digest to
        distinguish). Never pulls, never touches running services — safe to
        call frequently."""
        state = self.load_state()
        remote_digest = self.resolve_remote_digest()
        if remote_digest is None or remote_digest == state.active_digest:
            return None
        return remote_digest

    def validate_candidate(self, digest: str, *, deep: bool = False) -> dict[str, object]:
        """Validate `digest` in isolation and record it as the candidate.
        Never touches running services or the live bundle manifest."""
        report = self._validate_digest(digest, deep=deep)
        state = self.load_state()
        candidate = CandidateDigest(
            digest=digest,
            checked_at=datetime.now(UTC).isoformat(timespec="seconds"),
            validation=report,
        )
        self.save_state(dataclasses.replace(state, candidate=candidate))
        return report

    def promote_candidate(self) -> None:
        """Swap the candidate digest in as active and restart the Comet trio.

        Re-validates in isolation first — the stored candidate report may be
        stale (patch sources or config can change between check and apply) —
        so a promotion can never apply a digest that hasn't passed against
        the exact bits it will run with."""
        state = self.load_state()
        if state.candidate is None:
            raise RuntimeError("No candidate digest recorded. Run a remote check first.")
        digest = state.candidate.digest
        report = self._validate_digest(digest)
        if report["status"] != "passed":
            raise RuntimeError(
                f"Candidate {digest} failed re-validation and cannot be promoted:\n"
                f"{report['detail']}"
            )
        self.save_state(
            CometState(
                active_digest=digest,
                previous_digest=state.active_digest,
                candidate=None,
                last_remote_check=state.last_remote_check,
            )
        )
        self.prepare_runtime()
        self.validate_compatibility(force=True)
        self.log(f"Promoted Comet to {self.config.image}@{digest}. Restarting the Comet stack.")
        self.compose_fresh("up", "-d", *self._comet_services(), capture=False)

    def rollback(self) -> None:
        """Swap active/previous digest one level deep and restart."""
        state = self.load_state()
        if not state.previous_digest:
            raise RuntimeError("No previous digest recorded; nothing to roll back to.")
        self.save_state(
            CometState(
                active_digest=state.previous_digest,
                previous_digest=state.active_digest,
                candidate=None,
                last_remote_check=state.last_remote_check,
            )
        )
        self.prepare_runtime()
        self.validate_compatibility(force=True)
        self.log(f"Rolled back Comet to {self.config.image}@{state.previous_digest}. Restarting.")
        self.compose_fresh("up", "-d", *self._comet_services(), capture=False)

    def stop(self) -> None:
        self.require_commands()
        self.log("Stopping Comet stack.")
        services = []
        gateway_config = self.gateway_config()
        if gateway_config.enabled:
            services.append(gateway_config.service_name)
        services.extend([self.config.service_name, self.config.postgres_service_name])
        self.compose(
            "stop",
            *services,
            check=False,
            capture=False,
        )

    def status(self) -> None:
        current = self.current_commit()
        lock = self.load_lock()
        self.log(f"Vendored repo: {self.config.repo_dir}")
        self.log(f"Pinned commit: {lock.pinned_commit}")
        self.log(f"Current commit: {current or 'missing'}")
        if current and current != lock.pinned_commit:
            self.warn("Comet checkout is not on the pinned commit.")
        self.require_commands()
        gateway_config = self.gateway_config()
        services = [self.config.service_name, self.config.postgres_service_name]
        if gateway_config.enabled:
            services.append(gateway_config.service_name)
        result = self.compose(
            "ps",
            *services,
            check=False,
        )
        self.log((result.stdout or "").rstrip() or "No Comet compose output available.")
        network_mode = self.network_mode()
        self.log(
            "Network mode: "
            f"{network_mode or 'unknown'} (expected to share gluetun namespace when enabled)"
        )
        health = self.healthcheck()
        self.log(
            f"HTTP health: {'ok' if health else 'unreachable'} "
            "(checked from inside the Comet container)"
        )

    def service_container_id(self, service_name: str) -> str | None:
        result = self.runner.run(self._compose_command("ps", "-q", service_name), check=False)
        if result.returncode != 0:
            return None
        return next(
            (line.strip() for line in (result.stdout or "").splitlines() if line.strip()), None
        )

    def healthcheck(self) -> bool:
        container_id = self.service_container_id(self.config.service_name)
        if not container_id or not self.container_health_status(container_id):
            return False
        result = self.runner.run(
            ["docker", "exec", container_id, "wget", "-qO-", "http://127.0.0.1:8000/health"],
            check=False,
            timeout=5,
        )
        if result.returncode != 0:
            return False
        return '{"status":"ok"}' in (result.stdout or "").replace(" ", "")

    def container_health_status(self, container_id: str | None = None) -> str | None:
        container_id = container_id or self.service_container_id(self.config.service_name)
        if not container_id:
            return None
        result = self.runner.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", container_id],
            check=False,
        )
        if result.returncode != 0:
            return None
        return (result.stdout or "").strip() or None

    def public_ip(self, container_name: str) -> str | None:
        for url in ("https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"):
            result = self.runner.run(
                ["docker", "exec", container_name, "wget", "-qO-", url],
                check=False,
                timeout=10,
            )
            if result.returncode == 0:
                return (result.stdout or "").strip() or None
        return None

    def gluetun_container_id(self) -> str | None:
        return self.service_container_id("gluetun")

    def network_mode(self) -> str | None:
        result = self.runner.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{.HostConfig.NetworkMode}}",
                self.service_container_id(self.config.service_name) or "",
            ],
            check=False,
        )
        if result.returncode != 0:
            return None
        return (result.stdout or "").strip() or None

    def host_healthcheck(self) -> bool:
        url = f"{self.base_url_for_checks()}/health"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                body = response.read(128).decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, TimeoutError):
            return False
        return response.status == 200 and '"status":"ok"' in body.replace(" ", "")

    def base_url_for_checks(self) -> str:
        if self.gateway_config().enabled:
            return f"http://127.0.0.1:{self.config.host_port}"
        address = self.config.bind_addresses[0] if self.config.bind_addresses else "127.0.0.1"
        host = "127.0.0.1" if address == "0.0.0.0" else address
        return f"http://{host}:{self.config.host_port}"

    def _verify_doctor_image_and_manifest(self) -> None:
        comet_id = self.service_container_id(self.config.service_name)
        if not comet_id:
            raise RuntimeError("Comet container is not running.")

        active_image_ref = self.active_image_ref()
        running_image_id = self.runner.run(
            ["docker", "inspect", comet_id, "--format", "{{.Image}}"],
            check=True,
        ).stdout.strip()
        active_image_id = self.runner.run(
            ["docker", "image", "inspect", active_image_ref, "--format", "{{.Id}}"],
            check=True,
        ).stdout.strip()
        if running_image_id != active_image_id:
            raise RuntimeError(
                f"Running container's image ({running_image_id}) does not match "
                f"active image ({active_image_id})."
            )

        # Check mounted bundle manifest matches active digest
        manifest_path = self.config.state_dir / "bundle-manifest.json"
        if not manifest_path.exists():
            raise RuntimeError("Bundle manifest is missing.")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_digest = manifest.get("image_digest")
        except Exception as error:
            raise RuntimeError(f"Failed to read bundle manifest: {error}") from error

        active_digest = self._image_digest(active_image_ref)
        if manifest_digest != active_digest:
            raise RuntimeError(
                f"Mounted bundle manifest digest ({manifest_digest}) does not match "
                f"active image digest ({active_digest})."
            )

    def doctor(self) -> None:
        self.require_commands()
        self._verify_doctor_image_and_manifest()

        if not self.healthcheck():
            raise RuntimeError(
                "Comet health endpoint is not healthy from inside the container "
                f"({self.config.container_name} -> 127.0.0.1:8000/health)."
            )
        if not self.host_healthcheck():
            self.warn(
                "Host-side /health probe did not respond at "
                f"{self.base_url_for_checks()}/health. This can happen on WSL or "
                "multi-interface hosts even when container health is fine."
            )

        gateway_config = self.gateway_config()
        comet_is_gateway_gated = gateway_config.enabled
        port_output = self.compose("ps", "gluetun", check=False).stdout or ""
        if comet_is_gateway_gated:
            for address in self.config.bind_addresses:
                raw_comet_publish = f"{address}:{self.config.host_port}->8000/tcp"
                if address != "127.0.0.1" and raw_comet_publish in port_output:
                    raise RuntimeError(
                        "Comet gateway is enabled but Comet's raw host port is still "
                        f"published on {address}."
                    )
                expected_gateway = (
                    f"{address}:{gateway_config.host_port}->{COMET_GATEWAY_CONTAINER_PORT}/tcp"
                )
                if expected_gateway not in port_output:
                    raise RuntimeError(
                        "Comet gateway port publishing does not include expected mapping "
                        f"{expected_gateway!r}."
                    )
            if f"127.0.0.1:{self.config.host_port}->8000/tcp" not in port_output:
                raise RuntimeError(
                    "Comet gateway is enabled but raw Comet is not available on loopback "
                    "for local operator diagnostics."
                )
        else:
            for address in self.config.bind_addresses:
                expected = f"{address}:{self.config.host_port}->8000/tcp"
                if address == "0.0.0.0":
                    expected = f"0.0.0.0:{self.config.host_port}->8000/tcp"
                if expected not in port_output:
                    raise RuntimeError(
                        f"Comet port publishing does not include expected mapping {expected!r}."
                    )
        runtime_env = self.config.runtime_env_file
        proxy_setting = (env_file_value(runtime_env, "PROXY_DEBRID_STREAM") or "").strip().lower()
        if proxy_setting not in {"true", "1", "yes", "on"}:
            raise RuntimeError("Comet runtime env does not enable PROXY_DEBRID_STREAM.")
        if not env_file_value(runtime_env, "CONFIGURE_PAGE_PASSWORD"):
            raise RuntimeError("Comet runtime env is missing CONFIGURE_PAGE_PASSWORD.")
        if "0.0.0.0:" in port_output and "0.0.0.0" not in self.config.bind_addresses:
            raise RuntimeError("Comet appears to be exposed on all interfaces unexpectedly.")
        gluetun_id = self.gluetun_container_id()
        network_mode = self.network_mode()
        if not gluetun_id or network_mode != f"container:{gluetun_id}":
            raise RuntimeError(
                "Comet is not sharing gluetun's network namespace "
                f"(observed network mode: {network_mode or 'unknown'})."
            )
        gluetun_id = self.gluetun_container_id()
        comet_id = self.service_container_id(self.config.service_name)
        gluetun_ip = self.public_ip(gluetun_id) if gluetun_id else None
        comet_ip = self.public_ip(comet_id) if comet_id else None
        if not gluetun_ip or not comet_ip:
            raise RuntimeError("Could not compare Comet and gluetun public egress IPs.")
        if gluetun_ip != comet_ip:
            raise RuntimeError(
                f"Comet public IP {comet_ip} does not match gluetun public IP {gluetun_ip}."
            )
        self.success("Comet doctor checks passed.")

    def probe_playback(self, url: str, *, expect_proxy: bool = True) -> PlaybackProbeResult:
        result = probe_playback_url(url)
        if expect_proxy and result.classification != "proxied":
            raise RuntimeError(
                f"Expected proxied playback but observed {result.classification}"
                + (f" -> {result.location}" if result.location else "")
            )
        if not expect_proxy and result.classification != "redirected":
            raise RuntimeError(f"Expected redirected playback but observed {result.classification}")
        return result
