import time

try:
    import aiohttp  # type: ignore
except ImportError:
    aiohttp = None

try:
    from comet.core.logger import logger  # type: ignore
except ImportError:
    from loguru import logger  # type: ignore

try:
    from comet.core.models import database  # type: ignore
except ImportError:
    database = None

# Worker-safe in-memory cache
_EPISODE_COUNT_CACHE: dict[tuple[str, int], int] = {}


async def get_season_episode_count(series_id: str, season: int) -> int | None:
    """
    Get the total number of episodes in a given season of a TV show.
    Checks the in-memory cache first, falls back to Comet's local database index,
    and queries Cinemeta directly as a last resort.
    """
    if not isinstance(series_id, str) or not series_id.startswith("tt"):
        return None

    cache_key = (series_id, season)
    if cache_key in _EPISODE_COUNT_CACHE:
        return _EPISODE_COUNT_CACHE[cache_key]

    # Try local database (populated by Comet's EpisodeIndexService)
    try:
        if database is not None and database.is_connected:
            query = """
                SELECT MAX(episode)
                FROM series_episode_index
                WHERE series_id = :series_id
                  AND season = CAST(:season AS INTEGER)
            """
            db_max = await database.fetch_val(query, {"series_id": series_id, "season": season})
            if db_max is not None and db_max > 0:
                _EPISODE_COUNT_CACHE[cache_key] = db_max
                return db_max
    except Exception as exc:
        logger.warning(
            f"StremioGuard: Failed to query local episode index for {series_id} S{season}: {exc}"
        )

    # Fallback: Query Cinemeta directly via HTTP
    if aiohttp is None:
        logger.warning("StremioGuard: aiohttp is not installed; skipping Cinemeta fallback.")
        return None

    url = f"https://v3-cinemeta.strem.io/meta/series/{series_id}.json"
    headers = {"User-Agent": "stremio-guard/1"}

    start_time = time.monotonic()
    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(url, headers=headers, timeout=5) as response,
        ):
            if response.status == 200:
                payload = await response.json()
                videos = payload.get("meta", {}).get("videos") or []

                max_ep = 0
                for video in videos:
                    if not isinstance(video, dict):
                        continue
                    s = video.get("season")
                    ep = video.get("episode", video.get("number"))
                    if s is not None and ep is not None:
                        try:
                            if int(s) == season:
                                max_ep = max(max_ep, int(ep))
                        except (TypeError, ValueError):
                            continue

                latency = (time.monotonic() - start_time) * 1000
                logger.info(
                    f"StremioGuard: Cinemeta API fetched count {max_ep} "
                    f"for {series_id} S{season} in {latency:.1f}ms"
                )

                if max_ep > 0:
                    _EPISODE_COUNT_CACHE[cache_key] = max_ep
                    return max_ep
    except Exception as exc:
        logger.warning(
            f"StremioGuard: Failed to fetch Cinemeta fallback for {series_id} S{season}: {exc}"
        )

    return None
