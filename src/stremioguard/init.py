"""Interactive first-run setup prompts for external access and Stremio settings."""

from __future__ import annotations

import ipaddress
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import typer
from loguru import logger

from stremioguard.env import (
    DEFAULT_STREMIO_HOST_PORT,
    env_file_value,
    env_flag_enabled,
    env_needs_init,
    env_port_value,
    write_env_setting,
)


def existing_setup_summary(env_path: Path) -> list[str]:
    """Return a redacted, .env-derived summary for interactive re-initialization.

    `.env` is the only configuration authority. Generated `.stremio` files are
    runtime state, so they deliberately do not participate in this decision.
    """
    stremio_enabled = env_flag_enabled("STREMIO_ENABLED", True, env_path=env_path)
    comet_enabled = env_flag_enabled("COMET_ENABLED", True, env_path=env_path)
    if stremio_enabled and comet_enabled:
        profile = "Unified (Stremio + Comet)"
    elif comet_enabled:
        profile = "Comet-only"
    elif stremio_enabled:
        profile = "Stremio-only"
    else:
        profile = "No active service profile"

    provider = env_file_value(env_path, "VPN_SERVICE_PROVIDER") or "nordvpn"
    vpn_type = env_file_value(env_path, "VPN_TYPE") or "wireguard"
    credential_status = "configured" if not env_needs_init(env_path) else "needs setup"
    bind_addresses = env_file_value(env_path, "STREMIO_BIND_ADDRS") or "not published"
    public_url = (
        env_file_value(env_path, "EXTERNAL_BASE_URL")
        or env_file_value(env_path, "COMET_GATEWAY_PUBLIC_BASE_URL")
        or env_file_value(env_path, "COMET_PUBLIC_BASE_URL")
    )
    location_filters = ", ".join(
        f"{key.removeprefix('SERVER_').lower()}={value}"
        for key in (
            "SERVER_COUNTRIES",
            "SERVER_REGIONS",
            "SERVER_CITIES",
            "SERVER_HOSTNAMES",
            "SERVER_CATEGORIES",
        )
        if (value := env_file_value(env_path, key))
    )

    summary = [
        "Current setup from .env (secrets are never displayed):",
        f"  Profile: {profile}",
        f"  VPN: {provider} / {vpn_type} ({credential_status})",
        f"  Published addresses: {bind_addresses}",
    ]
    if public_url:
        summary.append(f"  Public URL: {_redacted_public_url(public_url)}")
    if comet_enabled:
        gateway = (
            "enabled"
            if env_flag_enabled("COMET_GATEWAY_ENABLED", True, env_path=env_path)
            else "disabled"
        )
        summary.append(f"  Comet gateway: {gateway}")
    if location_filters:
        summary.append(f"  VPN server filters: {location_filters}")
    return summary


def _redacted_public_url(value: str) -> str:
    """Show only a URL origin; paths, queries, and user-info may be sensitive."""
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return "configured (redacted)"
    if parsed.scheme not in {"http", "https"} or not host:
        return "configured (redacted)"
    authority = f"{host}:{port}" if port else host
    prefix = "<credentials-redacted>@" if parsed.username or parsed.password else ""
    return urlunsplit((parsed.scheme, f"{prefix}{authority}", "", "", ""))


def configured_profile_choice(env_path: Path) -> str:
    """Map persisted enabled-service flags to the init profile menu."""
    stremio_enabled = env_flag_enabled("STREMIO_ENABLED", True, env_path=env_path)
    comet_enabled = env_flag_enabled("COMET_ENABLED", True, env_path=env_path)
    if comet_enabled and not stremio_enabled:
        return "2"
    if stremio_enabled and not comet_enabled:
        return "3"
    return "1"


def configured_access_choice(env_path: Path, *, comet_only: bool) -> str:
    """Return the persisted access-mode choice, defaulting safely to LAN."""
    public_url_key = (
        "COMET_GATEWAY_PUBLIC_BASE_URL"
        if comet_only and env_flag_enabled("COMET_GATEWAY_ENABLED", True, env_path=env_path)
        else "COMET_PUBLIC_BASE_URL"
        if comet_only
        else "EXTERNAL_BASE_URL"
    )
    return "2" if env_file_value(env_path, public_url_key) else "1"


def configure_external_access(env_path: Path, is_proxied: bool, comet_only: bool = False) -> None:
    logger.info("Inbound access:")
    typer.echo("")
    if comet_only:
        gateway_active = env_flag_enabled("COMET_GATEWAY_ENABLED", True, env_path=env_path)
        default_port = 18001 if gateway_active else 18000
        port_raw = env_file_value(
            env_path, "COMET_GATEWAY_HOST_PORT" if gateway_active else "COMET_HOST_PORT"
        )
        host_port = default_port
        if port_raw is not None and port_raw != "":
            with suppress(ValueError):
                host_port = int(port_raw)

        if is_proxied:
            bind_addrs = _prompt_proxy_bind_address(
                host_port=host_port, default_address=_first_bind_address(env_path)
            )
        else:
            bind_addrs = _prompt_direct_bind_addresses(
                host_port=host_port, default_addresses=_existing_bind_addresses(env_path)
            )

        bind_value = ",".join(bind_addrs)
        write_env_setting(env_path, "STREMIO_BIND_ADDRS", bind_value)
        if bind_addrs:
            logger.info(f"Comet will bind {host_port} on {bind_value}.")
        else:
            logger.info(f"Comet will not publish {host_port} on any host interface.")

        if is_proxied:
            bind_addr = bind_addrs[0] if bind_addrs else "<this-host-LAN-IP>"
            upstream = bind_addr if bind_addr != "0.0.0.0" else "<this-host-LAN-IP>"
            comet_url = (
                env_file_value(
                    env_path,
                    "COMET_GATEWAY_PUBLIC_BASE_URL" if gateway_active else "COMET_PUBLIC_BASE_URL",
                )
                or ""
            )
            if comet_url:
                logger.info(f"Clients will reach Comet via {comet_url}.")
            _print_reverse_proxy_checklist(
                upstream=upstream,
                host_port=host_port,
                is_comet=True,
                gateway_active=gateway_active,
            )
        return

    host_port = env_port_value(env_path, "STREMIO_HOST_PORT", DEFAULT_STREMIO_HOST_PORT)
    write_env_setting(env_path, "STREMIO_HOST_PORT", str(host_port))

    if is_proxied:
        bind_addrs = _prompt_proxy_bind_address(
            host_port=host_port, default_address=_first_bind_address(env_path)
        )
    else:
        bind_addrs = _prompt_direct_bind_addresses(
            host_port=host_port, default_addresses=_existing_bind_addresses(env_path)
        )

    bind_value = ",".join(bind_addrs)
    write_env_setting(env_path, "STREMIO_BIND_ADDRS", bind_value)
    if bind_addrs:
        logger.info(f"Stremio will bind {host_port} on {bind_value}.")
    else:
        logger.info(f"Stremio will not publish {host_port} on any host interface.")

    if is_proxied:
        existing_url = env_file_value(env_path, "EXTERNAL_BASE_URL") or ""
        domain = _prompt_public_domain(
            existing_url.removeprefix("https://").removeprefix("http://")
        )
        external_url = f"https://{domain}"
        write_env_setting(env_path, "EXTERNAL_BASE_URL", external_url)
        logger.info(f"Clients will reach Stremio via {external_url}.")
        bind_addr = bind_addrs[0] if bind_addrs else "<this-host-LAN-IP>"
        upstream = bind_addr if bind_addr != "0.0.0.0" else "<this-host-LAN-IP>"
        _print_reverse_proxy_checklist(
            upstream=upstream,
            host_port=host_port,
            is_comet=False,
            gateway_active=False,
        )
    else:
        write_env_setting(env_path, "EXTERNAL_BASE_URL", "")
        logger.info(
            "No public domain configured. Stremio will use the same host and port clients "
            "connect to, such as a local IP and port."
        )


def _print_reverse_proxy_checklist(
    upstream: str,
    host_port: int,
    is_comet: bool,
    gateway_active: bool,
) -> None:
    typer.echo("")
    typer.echo("WARNING: REVERSE PROXY REQUIREMENTS")
    typer.echo("To expose this service securely and ensure it functions correctly:")
    typer.echo("")
    typer.echo("  * Domain Name & DNS: Ensure your domain/subdomain is registered and pointing")
    typer.echo("    to your proxy's public IP (e.g. via Cloudflare).")
    typer.echo(
        f"  * Upstream Destination: Point your reverse proxy to http://{upstream}:{host_port}"
    )
    if is_comet:
        if gateway_active:
            typer.echo("    (targeting the secure token gateway).")
        else:
            typer.echo("    (targeting raw Comet - NOT RECOMMENDED for public exposure).")
    else:
        typer.echo("    (targeting the Stremio Streaming Server).")
    typer.echo(
        "  * Custom Headers (CRITICAL): Your proxy must be configured with specific headers."
    )
    if is_comet:
        typer.echo("    - Forward 'Host', 'X-Forwarded-Host', and 'X-Forwarded-Proto'.")
        typer.echo(
            "    - Clear 'X-Forwarded-For' and 'X-Real-IP' to protect debrid access privacy."
        )
        typer.echo("    - Reference Nginx configuration templates at docs/comet-gateway.md.")
    else:
        typer.echo(
            "    - Forward 'Host', 'Upgrade', 'Connection' (WebSockets), and 'X-Forwarded-Proto'."
        )
        typer.echo("    - Reference Nginx configuration templates at docs/secure-access.md.")
    typer.echo("")


def _prompt_proxy_bind_address(
    *,
    host_port: int = DEFAULT_STREMIO_HOST_PORT,
    default_address: str | None = None,
) -> list[str]:
    typer.echo("")
    typer.echo("Your reverse proxy needs to reach Stremio on this host.")
    typer.echo("")
    typer.echo("  If your proxy runs in Docker (NPM, Dockerized Caddy/Traefik):")
    typer.echo("    Enter this host's LAN IP (e.g., 192.168.1.100).")
    typer.echo("    Find it with: ip -4 addr show | grep 'inet ' or hostname -I")
    typer.echo("    Note: 127.0.0.1 will NOT work from a Docker container.")
    typer.echo("")
    typer.echo("  If your proxy runs directly on this host (apt-installed nginx, Caddy binary):")
    typer.echo("    127.0.0.1 is fine — proxy and Stremio share the host network.")
    while True:
        raw = typer.prompt(
            f"Bind address for port {host_port}", default=default_address or ""
        ).strip()
        if raw == "0.0.0.0":
            return [raw]
        try:
            ip = ipaddress.IPv4Address(raw)
        except ValueError:
            typer.echo(f"  Not a valid IPv4 address: {raw!r}")
            continue
        if ip.is_loopback:
            typer.echo(
                "  Loopback only works if your reverse proxy runs directly on the host "
                "(not in Docker)."
            )
            confirm = (
                typer.prompt("  Proxy is host-native (not Docker)? [y/N]", default="n")
                .strip()
                .lower()
            )
            if confirm not in {"y", "yes"}:
                continue
        return [str(ip)]


def _prompt_direct_bind_addresses(
    *,
    host_port: int = DEFAULT_STREMIO_HOST_PORT,
    default_addresses: list[str] | None = None,
) -> list[str]:
    typer.echo("")
    typer.echo(f"Which addresses should publish Stremio's streaming port ({host_port})?")
    typer.echo("")
    typer.echo("  Clients connect directly to these addresses (no reverse proxy).")
    typer.echo("  Common setups:")
    typer.echo("    1 address  — LAN IP only, or Tailscale IP only")
    typer.echo("    2 addresses — LAN IP + Tailscale IP (both reachable)")
    typer.echo("    0 addresses — container-only; no host port published")
    typer.echo("")
    typer.echo("  Find your IPs with:")
    typer.echo("    LAN:       ip -4 addr show | grep 'inet ' or hostname -I")
    typer.echo("    Tailscale: tailscale ip -4")
    while True:
        raw = typer.prompt(
            "How many bind addresses?",
            default=str(len(default_addresses)) if default_addresses is not None else "1",
        ).strip()
        try:
            count = int(raw)
        except ValueError:
            typer.echo(f"  Not a valid number: {raw!r}")
            continue
        if count < 0:
            typer.echo("  Count must be 0 or greater.")
            continue
        if count > 8:
            typer.echo("  Refusing more than 8; use 0.0.0.0 if you need every interface.")
            continue
        break

    addresses: list[str] = []
    for index in range(count):
        while True:
            default_address = (
                default_addresses[index]
                if default_addresses is not None and index < len(default_addresses)
                else None
            )
            address = _prompt_single_bind_addr(
                host_port=host_port, index=index + 1, default_address=default_address
            )
            if address in addresses:
                typer.echo(f"  Address {address} is already listed.")
                continue
            addresses.append(address)
            break
    return addresses


def _prompt_single_bind_addr(
    *,
    host_port: int = DEFAULT_STREMIO_HOST_PORT,
    index: int | None = None,
    default_address: str | None = None,
) -> str:
    typer.echo("")
    label = f" #{index}" if index is not None else ""
    typer.echo(f"Bind address{label} for port {host_port}:")
    while True:
        raw = typer.prompt("Address", default=default_address or "").strip()
        if raw == "0.0.0.0":
            return raw
        try:
            ip = ipaddress.IPv4Address(raw)
        except ValueError:
            typer.echo(f"  Not a valid IPv4 address: {raw!r}")
            continue
        if ip.is_loopback:
            typer.echo("  Loopback (127.x.x.x) makes Stremio unreachable from LAN and Tailscale.")
            confirm = typer.prompt("  Bind on loopback anyway? [y/N]", default="n").strip().lower()
            if confirm not in {"y", "yes"}:
                continue
        return str(ip)


def _prompt_public_domain(default: str | None = None) -> str:
    typer.echo("")
    typer.echo("What domain will clients use? (e.g., stremio.example.com)")
    typer.echo(
        "  Assumes you have: domain registered, DNS configured, reverse proxy with a valid "
        "cert, and the proxy upstream pointed at this host's LAN IP on port 11470."
    )
    while True:
        raw = typer.prompt("Domain", default=default or "").strip().lower().rstrip("/")
        if raw.startswith(("http://", "https://")):
            typer.echo("  Enter just the hostname, no scheme.")
            continue
        if not raw or "/" in raw or " " in raw or "." not in raw:
            typer.echo(f"  Doesn't look like a hostname: {raw!r}")
            continue
        return raw


def _existing_bind_addresses(env_path: Path) -> list[str]:
    raw = env_file_value(env_path, "STREMIO_BIND_ADDRS") or ""
    return [address.strip() for address in raw.split(",") if address.strip()]


def _first_bind_address(env_path: Path) -> str | None:
    addresses = _existing_bind_addresses(env_path)
    return addresses[0] if addresses else None


def configure_optional_stremio_settings(env_path: Path) -> None:
    logger.info("Optional Stremio tweaks:")
    apply_patches = typer.confirm(
        "Enable the Stremio compatibility patch bundle?",
        default=env_flag_enabled("STREMIO_APPLY_PATCHES", True, env_path=env_path),
    )
    write_env_setting(env_path, "STREMIO_APPLY_PATCHES", "1" if apply_patches else "0")
    if not apply_patches:
        logger.warning(
            "Compatibility patch bundle disabled. This restores upstream behavior and may "
            "break HTTPS reverse-proxy redirects, internal self-probe rewriting, and the "
            "casting endpoint stub."
        )

    skip_hw_probe = typer.confirm(
        "Skip repeated hardware probe checks to keep reconnect logs quieter?",
        default=env_flag_enabled("STREMIO_SKIP_HW_PROBE", True, env_path=env_path),
    )
    write_env_setting(env_path, "STREMIO_SKIP_HW_PROBE", "1" if skip_hw_probe else "0")
    if skip_hw_probe:
        logger.info("Hardware probe skip enabled for quieter /device-info reconnect logs.")
    elif apply_patches:
        logger.warning(
            "Hardware probe skip disabled. Stremio may re-run qsv/nvenc/vaapi checks on "
            "reconnect and produce noisy logs."
        )
    else:
        logger.warning(
            "Hardware probe skip disabled and compatibility patches are off, so upstream "
            "hardware probing behavior will be used in full."
        )


def prompt_provider(default: str | None = None) -> str:
    normalized_default = (default or "nordvpn").strip().lower()
    default_choice = "2" if normalized_default == "other" else "1"
    typer.echo("")
    typer.echo("VPN provider:")
    typer.echo("  1) NordVPN  (guided WireGuard or OpenVPN setup)")
    typer.echo("  2) Other    (manual setup — you edit .env yourself)")
    choice = typer.prompt("Choose [1-2]", default=default_choice).strip().lower()
    if choice in {"1", "nordvpn"}:
        return "nordvpn"
    return "other"


def print_manual_setup_pointer() -> None:
    logger.info("Manual setup selected. Next steps:")
    typer.echo("  1. Open .env in your editor.")
    typer.echo("  2. Set VPN_SERVICE_PROVIDER to your gluetun-supported provider")
    typer.echo("     (mullvad, protonvpn, surfshark, expressvpn, etc.).")
    typer.echo("  3. Set VPN_TYPE (wireguard or openvpn) and the relevant credentials.")
    typer.echo("  4. Reference: https://github.com/qdm12/gluetun-wiki/tree/main/setup/providers")
    typer.echo("  5. Run `./stremio start` once .env is populated.")
