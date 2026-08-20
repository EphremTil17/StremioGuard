"""Dynamic NordVPN server recommendation resolver and endpoint cache."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from loguru import logger

RECOMMENDATIONS_API_URL = "https://api.nordvpn.com/v1/servers/recommendations"
DEFAULT_CACHE_TTL_SECONDS = 3600.0  # 1 hour
DEFAULT_TIMEOUT_SECONDS = 8.0

# NordVPN country name to country_id mapping for fast API filtering
NORDVPN_COUNTRY_IDS: dict[str, int] = {
    "united states": 228,
    "united kingdom": 227,
    "canada": 38,
    "germany": 81,
    "france": 74,
    "netherlands": 153,
    "australia": 13,
    "japan": 108,
    "brazil": 30,
    "sweden": 208,
    "switzerland": 209,
}


def _fetch_nordvpn_recommendations(
    country_id: int | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    """Fetch live server recommendations from NordVPN API."""
    url = (
        f"{RECOMMENDATIONS_API_URL}?filters[country_id]={country_id}&limit=100"
        if country_id
        else f"{RECOMMENDATIONS_API_URL}?limit=100"
    )
    headers = {
        "User-Agent": "StremioGuard/1.0",
        "Accept": "application/json",
    }
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        raw_body = response.read().decode("utf-8")
        data = json.loads(raw_body)
        if isinstance(data, list):
            return [s for s in data if isinstance(s, dict)]
    return []


def _server_load(s: dict[str, Any]) -> int:
    load_val = s.get("load")
    if isinstance(load_val, int):
        return load_val
    return 100


def _find_best_server(
    servers: list[dict[str, Any]],
    country: str | None = None,
    city: str | None = None,
) -> tuple[str, str] | None:
    """Filter and select the lowest-load online server matching country and city."""
    normalized_country = country.strip().lower() if country else None
    normalized_city = city.strip().lower() if city else None

    matching_servers: list[dict[str, Any]] = []

    for server in servers:
        if server.get("status") != "online":
            continue

        station = str(server.get("station") or "").strip()
        hostname = str(server.get("hostname") or "").strip()
        if not station or not hostname:
            continue

        # Location matching
        locations = server.get("locations", [])
        if not isinstance(locations, list):
            continue

        matched = True
        if normalized_country or normalized_city:
            loc_matched = False
            for loc in locations:
                if not isinstance(loc, dict):
                    continue
                loc_country = loc.get("country", {})
                if not isinstance(loc_country, dict):
                    continue
                loc_country_name = str(loc_country.get("name", "")).strip().lower()

                if normalized_country and loc_country_name != normalized_country:
                    continue

                if normalized_city:
                    loc_city = loc_country.get("city", {})
                    if not isinstance(loc_city, dict):
                        continue
                    loc_city_name = str(loc_city.get("name", "")).strip().lower()
                    if loc_city_name != normalized_city:
                        continue

                loc_matched = True
                break

            if not loc_matched:
                matched = False

        if matched:
            matching_servers.append(server)

    if not matching_servers:
        return None

    # Sort by lowest load
    matching_servers.sort(key=_server_load)
    best = matching_servers[0]
    return str(best["hostname"]), str(best["station"])


def resolve_nordvpn_endpoint(
    country: str | None = None,
    city: str | None = None,
    *,
    cache_path: Path | None = None,
    max_cache_age_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    force_refresh: bool = False,
) -> tuple[str, str] | None:
    """Resolve the optimal NordVPN server (hostname, IP) with caching."""
    country_clean = country.strip() if country else None
    city_clean = city.strip() if city else None

    # 1. Check cache if available and not forced
    if cache_path and cache_path.exists() and not force_refresh:
        try:
            cache_data = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_country = cache_data.get("country")
            cached_city = cache_data.get("city")
            cached_timestamp = float(cache_data.get("timestamp", 0.0))
            cached_hostname = cache_data.get("hostname")
            cached_ip = cache_data.get("ip")

            age = time.time() - cached_timestamp
            if (
                age < max_cache_age_seconds
                and cached_country == country_clean
                and cached_city == city_clean
                and cached_hostname
                and cached_ip
            ):
                return str(cached_hostname), str(cached_ip)
        except (json.JSONDecodeError, OSError, ValueError):
            pass

    # 2. Query live NordVPN API
    country_id = None
    if country_clean:
        country_id = NORDVPN_COUNTRY_IDS.get(country_clean.lower())

    try:
        servers = _fetch_nordvpn_recommendations(
            country_id=country_id, timeout_seconds=timeout_seconds
        )
        best = _find_best_server(servers, country=country_clean, city=city_clean)
        if best:
            hostname, ip = best
            if cache_path:
                try:
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_payload = {
                        "country": country_clean,
                        "city": city_clean,
                        "hostname": hostname,
                        "ip": ip,
                        "timestamp": time.time(),
                    }
                    cache_path.write_text(json.dumps(cache_payload, indent=2), encoding="utf-8")
                except OSError as write_err:
                    logger.debug(f"Failed to persist NordVPN endpoint cache: {write_err}")
            return hostname, ip
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as err:
        logger.warning(f"Could not fetch live NordVPN server recommendations: {err}")

    # 3. Fall back to stale cache if available
    if cache_path and cache_path.exists():
        try:
            cache_data = json.loads(cache_path.read_text(encoding="utf-8"))
            if (
                cache_data.get("country") == country_clean
                and cache_data.get("city") == city_clean
                and cache_data.get("hostname")
                and cache_data.get("ip")
            ):
                return str(cache_data["hostname"]), str(cache_data["ip"])
        except (json.JSONDecodeError, OSError):
            pass

    return None
