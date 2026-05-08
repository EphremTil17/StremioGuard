"""Interactive first-run setup prompts for external access and Stremio settings."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import typer
from loguru import logger

from stremioguard.env import (
    DEFAULT_STREMIO_HOST_PORT,
    env_file_value,
    env_port_value,
    write_env_setting,
)


def configure_external_access(env_path: Path) -> None:
    logger.info("Inbound access:")
    typer.echo("")
    typer.echo("How will clients reach Stremio?")
    typer.echo("  1) LAN + Tailscale only — no public domain  [default]")
    typer.echo("  2) Reverse-proxied behind a domain (NPM, Caddy, Traefik, raw nginx)")
    choice = typer.prompt("Choose [1-2]", default="1").strip().lower()
    proxied = choice in {"2", "proxy", "domain", "reverse-proxy"}
    host_port = env_port_value(env_path, "STREMIO_HOST_PORT", DEFAULT_STREMIO_HOST_PORT)
    write_env_setting(env_path, "STREMIO_HOST_PORT", str(host_port))

    if proxied:
        bind_addrs = _prompt_proxy_bind_address(host_port=host_port)
    else:
        bind_addrs = _prompt_direct_bind_addresses(host_port=host_port)

    bind_value = ",".join(bind_addrs)
    write_env_setting(env_path, "STREMIO_BIND_ADDRS", bind_value)
    if bind_addrs:
        logger.info(f"Stremio will bind {host_port} on {bind_value}.")
    else:
        logger.info(f"Stremio will not publish {host_port} on any host interface.")

    if proxied:
        domain = _prompt_public_domain()
        external_url = f"https://{domain}"
        write_env_setting(env_path, "EXTERNAL_BASE_URL", external_url)
        logger.info(f"Clients will reach Stremio via {external_url}.")
        bind_addr = bind_addrs[0] if bind_addrs else "<this-host-LAN-IP>"
        upstream = bind_addr if bind_addr != "0.0.0.0" else "<this-host-LAN-IP>"
        logger.info(f"Point your reverse proxy upstream at http://{upstream}:{host_port}.")
    else:
        write_env_setting(env_path, "EXTERNAL_BASE_URL", "")
        logger.info(
            "No public domain configured. Stremio will use the same host and port clients "
            "connect to, such as a local IP and port."
        )


def _prompt_proxy_bind_address(
    *,
    host_port: int = DEFAULT_STREMIO_HOST_PORT,
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
        raw = typer.prompt(f"Bind address for port {host_port}").strip()
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
        raw = typer.prompt("How many bind addresses?", default="1").strip()
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
            address = _prompt_single_bind_addr(host_port=host_port, index=index + 1)
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
) -> str:
    typer.echo("")
    label = f" #{index}" if index is not None else ""
    typer.echo(f"Bind address{label} for port {host_port}:")
    while True:
        raw = typer.prompt("Address").strip()
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


def _prompt_public_domain() -> str:
    typer.echo("")
    typer.echo("What domain will clients use? (e.g., stremio.example.com)")
    typer.echo(
        "  Assumes you have: domain registered, DNS configured, reverse proxy with a valid "
        "cert, and the proxy upstream pointed at this host's LAN IP on port 11470."
    )
    while True:
        raw = typer.prompt("Domain").strip().lower().rstrip("/")
        if raw.startswith(("http://", "https://")):
            typer.echo("  Enter just the hostname, no scheme.")
            continue
        if not raw or "/" in raw or " " in raw or "." not in raw:
            typer.echo(f"  Doesn't look like a hostname: {raw!r}")
            continue
        return raw


def configure_optional_stremio_settings(env_path: Path) -> None:
    logger.info("Optional Stremio tweaks:")
    apply_patches = typer.confirm("Enable the Stremio compatibility patch bundle?", default=True)
    write_env_setting(env_path, "STREMIO_APPLY_PATCHES", "1" if apply_patches else "0")
    if not apply_patches:
        logger.warning(
            "Compatibility patch bundle disabled. This restores upstream behavior and may "
            "break HTTPS reverse-proxy redirects, internal self-probe rewriting, and the "
            "casting endpoint stub."
        )

    skip_hw_probe = typer.confirm(
        "Skip repeated hardware probe checks to keep reconnect logs quieter?", default=True
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


def _infer_auth_domain(env_path: Path) -> str:
    external_url = env_file_value(env_path, "EXTERNAL_BASE_URL") or ""
    if "://" in external_url:
        host_part = external_url.split("://", 1)[1].rstrip("/")
        if ":" in host_part:
            host_part = host_part.rsplit(":", 1)[0]
        return host_part
    return ""


def configure_auth_access(env_path: Path) -> None:
    logger.info("Token-based authentication setup:")
    typer.echo("")
    typer.echo("This adds an nginx reverse-proxy that validates a short token in the URL path.")
    typer.echo("Each device gets a unique URL like https://streamio.example.com/<token>/")
    typer.echo("")

    host_port = env_port_value(env_path, "AUTH_HOST_PORT", 11471)
    write_env_setting(env_path, "AUTH_HOST_PORT", str(host_port))
    logger.info(f"Auth proxy will publish on host port {host_port}.")

    default_domain = _infer_auth_domain(env_path)
    domain = (
        typer.prompt(
            "Domain for token URLs (e.g., streamio.example.com)",
            default=default_domain or "",
        )
        .strip()
        .lower()
        .rstrip("/")
    )
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1]
    write_env_setting(env_path, "AUTH_DOMAIN", domain)

    write_env_setting(env_path, "AUTH_ENABLED", "1")
    logger.success('Auth proxy enabled. Use `./stremio auth add "label"` to create tokens.')
    typer.echo("")
    typer.echo("After creating tokens, update your reverse proxy upstream:")
    typer.echo("  Old: http://<bind-addr>:11470")
    typer.echo(f"  New: http://<bind-addr>:{host_port}")
    typer.echo("  Keep any network allowlists you want; the token is an application-layer gate.")
