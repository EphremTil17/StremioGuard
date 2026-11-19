import json
import re
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

# Coroutine-safe in-memory cache (per process event loop), bounded so arbitrary
# series/season lookups cannot grow memory without limit.
# Stores: (series_id, season) -> (episode_count | None, expiry_timestamp)
_EPISODE_COUNT_CACHE: dict[tuple[str, int], tuple[int | None, float]] = {}
_MAX_CACHE_ENTRIES = 1024
_MAX_CINEMETA_RESPONSE_BYTES = 2 * 1024 * 1024
_IMDB_ID_PATTERN = re.compile(r"\Att\d{1,12}\Z")


def _cache_get(cache_key: tuple[str, int], now: float) -> tuple[bool, int | None]:
    entry = _EPISODE_COUNT_CACHE.get(cache_key)
    if entry is None:
        return False, None
    val, expiry = entry
    if now >= expiry:
        _EPISODE_COUNT_CACHE.pop(cache_key, None)
        return False, None
    # Refresh insertion order so active series stay in the cache.
    _EPISODE_COUNT_CACHE[cache_key] = _EPISODE_COUNT_CACHE.pop(cache_key)
    return True, val


def _cache_set(cache_key: tuple[str, int], value: int | None, expiry: float, now: float) -> None:
    _EPISODE_COUNT_CACHE.pop(cache_key, None)
    _EPISODE_COUNT_CACHE[cache_key] = (value, expiry)
    if len(_EPISODE_COUNT_CACHE) <= _MAX_CACHE_ENTRIES:
        return
    expired = [k for k, (_, exp) in _EPISODE_COUNT_CACHE.items() if now >= exp]
    for k in expired:
        _EPISODE_COUNT_CACHE.pop(k, None)
    while len(_EPISODE_COUNT_CACHE) > _MAX_CACHE_ENTRIES:
        del _EPISODE_COUNT_CACHE[next(iter(_EPISODE_COUNT_CACHE))]


def _public_connector():
    try:
        from comet.stremioguard_stream_guard import PublicOnlyConnector  # type: ignore
    except ImportError:
        return None
    return PublicOnlyConnector()


async def get_season_episode_count(series_id: str, season: int) -> int | None:
    """
    Get the total number of episodes in a given season of a TV show.
    Checks the in-memory cache first, falls back to Comet's local database index,
    and queries Cinemeta directly as a last resort.
    """
    if (
        not isinstance(series_id, str)
        or not _IMDB_ID_PATTERN.fullmatch(series_id)
        or not isinstance(season, int)
        or isinstance(season, bool)
        or season < 0
    ):
        return None

    cache_key = (series_id, season)
    now = time.monotonic()
    hit, cached_val = _cache_get(cache_key, now)
    if hit:
        return cached_val

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
                # Cache positive result with 24 hours TTL
                _cache_set(cache_key, db_max, now + 86400.0, now)
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
        timeout = aiohttp.ClientTimeout(total=5)
        connector = _public_connector()
        session_kwargs = {"connector": connector} if connector is not None else {}
        async with (
            aiohttp.ClientSession(**session_kwargs) as session,
            session.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            ) as response,
        ):
            if response.status == 200:
                raw_body = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    raw_body.extend(chunk)
                    if len(raw_body) > _MAX_CINEMETA_RESPONSE_BYTES:
                        logger.warning(
                            "StremioGuard: Cinemeta response exceeded "
                            f"{_MAX_CINEMETA_RESPONSE_BYTES} bytes for {series_id} S{season}; "
                            "ignoring."
                        )
                        _cache_set(cache_key, None, now + 60.0, now)
                        return None
                payload = json.loads(bytes(raw_body).decode("utf-8"))
                meta = payload.get("meta") if isinstance(payload, dict) else None
                videos = meta.get("videos") if isinstance(meta, dict) else None
                videos = videos if isinstance(videos, list) else []

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
                    # Cache positive result with 24 hours TTL
                    _cache_set(cache_key, max_ep, now + 86400.0, now)
                    return max_ep
    except Exception as exc:
        logger.warning(
            f"StremioGuard: Failed to fetch Cinemeta fallback for {series_id} S{season}: {exc}"
        )

    # Cache negative result/miss with 60 seconds TTL
    _cache_set(cache_key, None, now + 60.0, now)
    return None
