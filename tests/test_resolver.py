"""Unit tests for dynamic NordVPN recommendation resolver and endpoint cache."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from stremioguard import resolver
from tests.conftest import (
    PUBLIC_IPV4_ALT,
    PUBLIC_IPV4_EGRESS,
    PUBLIC_IPV4_HOST,
    PUBLIC_IPV4_STATION,
)


class ResolverTests(unittest.TestCase):
    def test_find_best_server_selects_lowest_load_online_matching_city(self) -> None:
        servers = [
            {
                "hostname": "us-offline.nordvpn.com",
                "station": "1.1.1.1",
                "status": "offline",
                "load": 5,
                "locations": [{"country": {"name": "United States", "city": {"name": "Denver"}}}],
            },
            {
                "hostname": "us-highload.nordvpn.com",
                "station": "2.2.2.2",
                "status": "online",
                "load": 80,
                "locations": [{"country": {"name": "United States", "city": {"name": "Denver"}}}],
            },
            {
                "hostname": "us-best.nordvpn.com",
                "station": "3.3.3.3",
                "status": "online",
                "load": 12,
                "locations": [{"country": {"name": "United States", "city": {"name": "Denver"}}}],
            },
            {
                "hostname": "us-othercity.nordvpn.com",
                "station": "4.4.4.4",
                "status": "online",
                "load": 2,
                "locations": [{"country": {"name": "United States", "city": {"name": "Chicago"}}}],
            },
        ]
        result = resolver._find_best_server(servers, country="United States", city="Denver")
        self.assertEqual(result, ("us-best.nordvpn.com", "3.3.3.3"))

    def test_find_best_server_selects_matching_country_when_city_not_specified(self) -> None:
        servers = [
            {
                "hostname": "uk1.nordvpn.com",
                "station": "5.5.5.5",
                "status": "online",
                "load": 10,
                "locations": [{"country": {"name": "United Kingdom", "city": {"name": "London"}}}],
            },
            {
                "hostname": "us1.nordvpn.com",
                "station": "6.6.6.6",
                "status": "online",
                "load": 25,
                "locations": [{"country": {"name": "United States", "city": {"name": "New York"}}}],
            },
        ]
        result = resolver._find_best_server(servers, country="United States", city=None)
        self.assertEqual(result, ("us1.nordvpn.com", "6.6.6.6"))

    def test_resolve_nordvpn_endpoint_uses_valid_cache_without_network_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "cache.json"
            cache_payload = {
                "country": "United States",
                "city": "Denver",
                "hostname": "us-cached.nordvpn.com",
                "ip": PUBLIC_IPV4_STATION,
                "timestamp": time.time(),
            }
            cache_path.write_text(json.dumps(cache_payload), encoding="utf-8")

            with mock.patch("urllib.request.urlopen") as mock_urlopen:
                result = resolver.resolve_nordvpn_endpoint(
                    country="United States", city="Denver", cache_path=cache_path
                )

            self.assertEqual(result, ("us-cached.nordvpn.com", PUBLIC_IPV4_STATION))
            mock_urlopen.assert_not_called()

    def test_resolve_nordvpn_endpoint_fetches_and_updates_cache_on_miss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "cache.json"
            payload = [
                {
                    "hostname": "us1234.nordvpn.com",
                    "station": PUBLIC_IPV4_EGRESS,
                    "status": "online",
                    "load": 11,
                    "locations": [
                        {"country": {"name": "United States", "city": {"name": "Denver"}}}
                    ],
                }
            ]
            mock_response = mock.MagicMock()
            mock_response.read.return_value = json.dumps(payload).encode("utf-8")
            mock_response.__enter__.return_value = mock_response

            with mock.patch("urllib.request.urlopen", return_value=mock_response):
                result = resolver.resolve_nordvpn_endpoint(
                    country="United States", city="Denver", cache_path=cache_path
                )

            self.assertEqual(result, ("us1234.nordvpn.com", PUBLIC_IPV4_EGRESS))
            self.assertTrue(cache_path.exists())
            saved = json.loads(cache_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["hostname"], "us1234.nordvpn.com")
            self.assertEqual(saved["ip"], PUBLIC_IPV4_EGRESS)

    def test_resolve_nordvpn_endpoint_falls_back_to_stale_cache_on_network_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "cache.json"
            cache_payload = {
                "country": "United States",
                "city": "Denver",
                "hostname": "us-stale.nordvpn.com",
                "ip": PUBLIC_IPV4_ALT,
                "timestamp": time.time() - 7200,  # expired past 1h TTL, within 24h cap
            }
            cache_path.write_text(json.dumps(cache_payload), encoding="utf-8")

            with mock.patch(
                "urllib.request.urlopen", side_effect=urllib.error.URLError("No route")
            ):
                result = resolver.resolve_nordvpn_endpoint(
                    country="United States", city="Denver", cache_path=cache_path
                )

            self.assertEqual(result, ("us-stale.nordvpn.com", PUBLIC_IPV4_ALT))

    def test_resolve_nordvpn_endpoint_returns_none_when_no_match_and_no_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "cache.json"
            mock_response = mock.MagicMock()
            mock_response.read.return_value = json.dumps([]).encode("utf-8")
            mock_response.__enter__.return_value = mock_response

            with mock.patch("urllib.request.urlopen", return_value=mock_response):
                result = resolver.resolve_nordvpn_endpoint(
                    country="Nonexistent", city="Nowhere", cache_path=cache_path
                )

            self.assertIsNone(result)


class EndpointEnvTests(unittest.TestCase):
    def _env(self, directory: str, text: str) -> Path:
        path = Path(directory) / ".env"
        path.write_text(text, encoding="utf-8")
        return path

    def test_endpoint_env_pins_both_protocols_for_nordvpn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = self._env(directory, "VPN_SERVICE_PROVIDER=nordvpn\nSERVER_COUNTRIES=Canada\n")
            with mock.patch.object(
                resolver,
                "resolve_nordvpn_endpoint",
                return_value=("ca1.nordvpn.com", PUBLIC_IPV4_HOST),
            ) as resolve:
                result = resolver.nordvpn_endpoint_env(env, Path(directory) / "cache.json")
        self.assertEqual(
            result,
            {
                "OPENVPN_ENDPOINT_IP": PUBLIC_IPV4_HOST,
                "WIREGUARD_ENDPOINT_IP": PUBLIC_IPV4_HOST,
            },
        )
        self.assertEqual(resolve.call_args.kwargs["country"], "Canada")

    def test_endpoint_env_is_empty_for_other_providers_or_pinned_hostnames(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache.json"
            with mock.patch.object(resolver, "resolve_nordvpn_endpoint") as resolve:
                for text in (
                    "VPN_SERVICE_PROVIDER=mullvad\n",
                    "VPN_SERVICE_PROVIDER=nordvpn\nSERVER_HOSTNAMES=us1.nordvpn.com\n",
                ):
                    self.assertEqual(
                        resolver.nordvpn_endpoint_env(self._env(directory, text), cache), {}
                    )
                self.assertEqual(
                    resolver.nordvpn_endpoint_env(Path(directory) / "missing.env", cache), {}
                )
            resolve.assert_not_called()
