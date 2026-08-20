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


class ResolverTests(unittest.TestCase):
    def test_find_best_server_selects_lowest_load_online_matching_city(self) -> None:
        servers = [
            {
                "hostname": "us-offline.nordvpn.com",
                "station": "1.1.1.1",
                "status": "offline",
                "load": 5,
                "locations": [{"country": {"name": "United States", "city": {"name": "Seattle"}}}],
            },
            {
                "hostname": "us-highload.nordvpn.com",
                "station": "2.2.2.2",
                "status": "online",
                "load": 80,
                "locations": [{"country": {"name": "United States", "city": {"name": "Seattle"}}}],
            },
            {
                "hostname": "us-best.nordvpn.com",
                "station": "3.3.3.3",
                "status": "online",
                "load": 12,
                "locations": [{"country": {"name": "United States", "city": {"name": "Seattle"}}}],
            },
            {
                "hostname": "us-othercity.nordvpn.com",
                "station": "4.4.4.4",
                "status": "online",
                "load": 2,
                "locations": [{"country": {"name": "United States", "city": {"name": "Chicago"}}}],
            },
        ]
        result = resolver._find_best_server(servers, country="United States", city="Seattle")
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
                "city": "Seattle",
                "hostname": "us-cached.nordvpn.com",
                "ip": "10.0.0.1",
                "timestamp": time.time(),
            }
            cache_path.write_text(json.dumps(cache_payload), encoding="utf-8")

            with mock.patch("urllib.request.urlopen") as mock_urlopen:
                result = resolver.resolve_nordvpn_endpoint(
                    country="United States", city="Seattle", cache_path=cache_path
                )

            self.assertEqual(result, ("us-cached.nordvpn.com", "10.0.0.1"))
            mock_urlopen.assert_not_called()

    def test_resolve_nordvpn_endpoint_fetches_and_updates_cache_on_miss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "cache.json"
            payload = [
                {
                    "hostname": "us13590.nordvpn.com",
                    "station": "187.15.96.94",
                    "status": "online",
                    "load": 11,
                    "locations": [
                        {"country": {"name": "United States", "city": {"name": "Seattle"}}}
                    ],
                }
            ]
            mock_response = mock.MagicMock()
            mock_response.read.return_value = json.dumps(payload).encode("utf-8")
            mock_response.__enter__.return_value = mock_response

            with mock.patch("urllib.request.urlopen", return_value=mock_response):
                result = resolver.resolve_nordvpn_endpoint(
                    country="United States", city="Seattle", cache_path=cache_path
                )

            self.assertEqual(result, ("us13590.nordvpn.com", "187.15.96.94"))
            self.assertTrue(cache_path.exists())
            saved = json.loads(cache_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["hostname"], "us13590.nordvpn.com")
            self.assertEqual(saved["ip"], "187.15.96.94")

    def test_resolve_nordvpn_endpoint_falls_back_to_stale_cache_on_network_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "cache.json"
            cache_payload = {
                "country": "United States",
                "city": "Seattle",
                "hostname": "us-stale.nordvpn.com",
                "ip": "10.0.0.2",
                "timestamp": time.time() - 100000,  # expired
            }
            cache_path.write_text(json.dumps(cache_payload), encoding="utf-8")

            with mock.patch(
                "urllib.request.urlopen", side_effect=urllib.error.URLError("No route")
            ):
                result = resolver.resolve_nordvpn_endpoint(
                    country="United States", city="Seattle", cache_path=cache_path
                )

            self.assertEqual(result, ("us-stale.nordvpn.com", "10.0.0.2"))

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
