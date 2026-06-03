from __future__ import annotations

import secrets

import typer
from loguru import logger

from stremioguard.comet_gateway import CometGatewayConfig, CometGatewayManager
from stremioguard.config import CometConfig
from stremioguard.env import fail, write_env_setting

SUPPORTED_DEBRID_PROVIDERS = (
    "realdebrid",
    "torbox",
    "alldebrid",
    "premiumize",
    "debridlink",
    "easydebrid",
    "offcloud",
    "pikpak",
)


def prompt_comet_setup(config: CometConfig, is_proxied: bool = False) -> None:
    if not config.env_file.exists():
        fail(f"{config.env_file} is missing. Run `./stremio init` first.")

    typer.echo("")
    typer.echo("3. Comet Proxy Port")
    typer.echo("Choose the internal host port where the raw Comet service will listen.")
    host_port = typer.prompt("Comet host port", default=str(config.host_port)).strip()
    try:
        parsed_port = int(host_port)
    except ValueError:
        fail(f"COMET_HOST_PORT must be a TCP port number; got {host_port!r}.")
    if parsed_port < 1 or parsed_port > 65535:
        fail(f"COMET_HOST_PORT must be between 1 and 65535; got {parsed_port!r}.")
    write_env_setting(config.env_file, "COMET_ENABLED", "1")
    write_env_setting(config.env_file, "COMET_HOST_PORT", str(parsed_port))
    write_env_setting(config.env_file, "COMET_SCRAPE_TORRENTIO", config.scrape_torrentio)
    write_env_setting(config.env_file, "COMET_TORRENTIO_URL", config.torrentio_url)
    write_env_setting(config.env_file, "COMET_SCRAPE_ZILEAN", config.scrape_zilean)
    write_env_setting(config.env_file, "COMET_ZILEAN_URL", config.zilean_url)
    write_env_setting(config.env_file, "COMET_RESULT_FORMAT_STYLE", config.result_format_style)

    typer.echo("")
    typer.echo("4. Comet Compatibility Patches")
    typer.echo(
        "Preserve more episode results from season packs "
        "when Comet consumes Torrentio/Zilean scraper results."
    )
    patch_episode_pack_results = typer.confirm(
        "Apply the Comet episode-pack preservation patch?",
        default=config.patch_episode_pack_results,
    )
    write_env_setting(
        config.env_file,
        "COMET_PATCH_EPISODE_PACK_RESULTS",
        "1" if patch_episode_pack_results else "0",
    )

    typer.echo("")
    typer.echo("5. Comet Admin Authentication")
    typer.echo(
        "Protect the Comet configure page (/configure) so other users cannot change settings."
    )
    configure_password = typer.prompt(
        "Configure page password",
        hide_input=True,
        confirmation_prompt=True,
        default=config.configure_page_password or secrets.token_urlsafe(12),
        show_default=False,
    ).strip()
    if not configure_password:
        fail("A configure page password is required for shared-domain Comet access.")
    write_env_setting(config.env_file, "COMET_CONFIGURE_PAGE_PASSWORD", configure_password)

    typer.echo("")
    typer.echo("6. Comet Debrid Stream Proxying")
    typer.echo(
        "Optionally proxy playback streams through this server (and your VPN)\n"
        "instead of direct client-to-debrid connections."
    )
    proxy_enabled = typer.confirm("Enable Comet debrid stream proxying?", default=True)
    write_env_setting(config.env_file, "COMET_PROXY_DEBRID_STREAM", "1" if proxy_enabled else "0")
    max_connections = typer.prompt(
        "Per-IP proxy max connections (-1 for unlimited)",
        default=str(config.proxy_max_connections),
    ).strip()
    try:
        parsed_max_connections = int(max_connections)
    except ValueError:
        fail(f"COMET_PROXY_MAX_CONNECTIONS must be an integer; got {max_connections!r}.")
    if parsed_max_connections < -1 or parsed_max_connections == 0:
        fail(
            "COMET_PROXY_MAX_CONNECTIONS must be -1 for unlimited or a positive integer; "
            f"got {parsed_max_connections!r}."
        )
    write_env_setting(
        config.env_file,
        "COMET_PROXY_MAX_CONNECTIONS",
        str(parsed_max_connections),
    )

    typer.echo("")
    typer.echo("7. Comet Token Gateway Gating")
    typer.echo(
        "The gateway protects public addon URLs with temporary tokens "
        "while keeping /configure locked."
    )
    gateway_enabled = True
    if is_proxied:
        typer.echo("")
        typer.echo("WARNING: PUBLIC DEPLOYMENT DETECTED")
        typer.echo(
            "Disabling the Comet gateway exposes raw Comet (and private keys) "
            "directly to the public internet."
        )
        if not typer.confirm("Keep the Comet gateway enabled for security?", default=True):
            typer.echo("")
            typer.echo("CRITICAL: Exposing raw Comet is highly discouraged and insecure.")
            if typer.confirm(
                "Are you absolutely sure you want to disable the gateway and expose raw Comet?",
                default=False,
            ):
                gateway_enabled = False
    else:
        gateway_enabled = typer.confirm("Enable the token-managed Comet gateway?", default=True)
    write_env_setting(config.env_file, "COMET_GATEWAY_ENABLED", "1" if gateway_enabled else "0")
    if gateway_enabled:
        gateway_config = CometGatewayConfig.from_env(config.root_dir)
        typer.echo("")
        gateway_port = typer.prompt(
            "Comet gateway host port",
            default=str(gateway_config.host_port),
        ).strip()
        try:
            parsed_gateway_port = int(gateway_port)
        except ValueError:
            fail(f"COMET_GATEWAY_HOST_PORT must be a TCP port number; got {gateway_port!r}.")
        if parsed_gateway_port < 1 or parsed_gateway_port > 65535:
            fail(
                f"COMET_GATEWAY_HOST_PORT must be between 1 and 65535; got {parsed_gateway_port!r}."
            )
        write_env_setting(config.env_file, "COMET_GATEWAY_HOST_PORT", str(parsed_gateway_port))

        typer.echo("")
        typer.echo("Comet Gateway Public Base URL:")
        typer.echo(
            "Enter the public domain proxy endpoint (e.g. https://comet.example.com).\n"
            "If left blank, the gateway will dynamically reconstruct URLs "
            "from Nginx request headers."
        )
        gateway_public_base_url = typer.prompt(
            "Gateway public base URL (blank to infer from Nginx headers)",
            default=gateway_config.public_base_url or "",
        ).strip()
        write_env_setting(
            config.env_file,
            "COMET_GATEWAY_PUBLIC_BASE_URL",
            gateway_public_base_url.rstrip("/"),
        )
        write_env_setting(
            config.env_file,
            "COMET_GATEWAY_TOKEN_LENGTH",
            str(gateway_config.token_length),
        )

        refreshed_gateway = CometGatewayManager(CometGatewayConfig.from_env(config.root_dir))
        if not refreshed_gateway.list_tokens() and typer.confirm(
            "Create the default shared Comet addon token now?",
            default=True,
        ):
            token_id, token_value = refreshed_gateway.add_token("Shared Addon")
            logger.info(f"Created default Comet gateway token {token_id}.")
            typer.echo(f"  Addon base: {refreshed_gateway.addon_base_url(token_value)}")
    elif is_proxied:
        typer.echo("")
        typer.echo("Comet Public Base URL:")
        typer.echo(
            "Enter the public domain proxy endpoint (e.g. https://comet.example.com).\n"
            "This URL is required when exposing raw Comet without the gateway token gate."
        )
        comet_public_base_url = typer.prompt(
            "Comet public base URL",
            default=config.public_base_url or "",
        ).strip()
        if not comet_public_base_url:
            fail(
                "A Comet public base URL is required when the gateway is disabled "
                "for a reverse-proxied deployment."
            )
        write_env_setting(
            config.env_file,
            "COMET_PUBLIC_BASE_URL",
            comet_public_base_url.rstrip("/"),
        )

    typer.echo("")
    typer.echo("8. Fallback Debrid Setup")
    typer.echo(
        "Optionally configure a server-owned fallback debrid account. Leave this disabled\n"
        "if users will input their own debrid API keys in Comet's /configure page."
    )
    use_server_defaults = typer.confirm(
        "Set server-owned fallback debrid credentials now?",
        default=False,
    )
    if use_server_defaults:
        default_service = _prompt_debrid_provider(config.default_debrid_service)
        write_env_setting(config.env_file, "COMET_DEFAULT_DEBRID_SERVICE", default_service)
        api_key = typer.prompt("Default debrid API key", hide_input=True).strip()
        if not api_key:
            fail("A debrid API key is required when server-owned fallback credentials are enabled.")
        write_env_setting(config.env_file, "COMET_DEFAULT_DEBRID_APIKEY", api_key)
    else:
        write_env_setting(config.env_file, "COMET_DEFAULT_DEBRID_SERVICE", "realdebrid")
        write_env_setting(config.env_file, "COMET_DEFAULT_DEBRID_APIKEY", "")


def _prompt_debrid_provider(default: str) -> str:
    normalized_default = default if default in SUPPORTED_DEBRID_PROVIDERS else "realdebrid"
    default_choice = str(SUPPORTED_DEBRID_PROVIDERS.index(normalized_default) + 1)
    typer.echo("Choose the fallback debrid provider:")
    for index, provider in enumerate(SUPPORTED_DEBRID_PROVIDERS, start=1):
        typer.echo(f"  {index}) {provider}")
    choice = typer.prompt("Provider", default=default_choice).strip().lower()
    if choice.isdigit():
        selected_index = int(choice) - 1
        if 0 <= selected_index < len(SUPPORTED_DEBRID_PROVIDERS):
            return SUPPORTED_DEBRID_PROVIDERS[selected_index]
    if choice in SUPPORTED_DEBRID_PROVIDERS:
        return choice
    fail(f"Unsupported debrid provider choice: {choice!r}.")
