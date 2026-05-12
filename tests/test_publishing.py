"""Regression tests for compose-override rendering across different profiles."""

from __future__ import annotations

import unittest
from pathlib import Path

from stremioguard.publishing import render_stack_compose_override

from .conftest import make_comet_config, make_comet_gateway_config


class TestPublishingOverride(unittest.TestCase):
    def test_unified_profile_publishing(self) -> None:
        comet_cfg = make_comet_config(Path("/tmp"), enabled=True)
        gateway_cfg = make_comet_gateway_config(Path("/tmp"), enabled=True)
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            stremio_enabled=True,
            comet_config=comet_cfg,
            comet_gateway_config=gateway_cfg,
        )
        # Check both Stremio and Comet Gateway ports are published
        self.assertIn('"10.0.0.1:11470:11470"', content)
        self.assertIn('"10.0.0.1:18001:8090"', content)
        # Check raw Comet is localhost-only
        self.assertIn('"127.0.0.1:18000:8000"', content)
        self.assertIn("comet:", content)
        self.assertIn("comet-gateway:", content)

    def test_stremio_only_profile_publishing(self) -> None:
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            stremio_enabled=True,
            comet_config=None,
            comet_gateway_config=None,
        )
        self.assertIn('"10.0.0.1:11470:11470"', content)
        self.assertNotIn("comet:", content)
        self.assertNotIn("comet-gateway:", content)
        self.assertNotIn("18001", content)
        self.assertNotIn("18000", content)

    def test_comet_only_profile_publishing(self) -> None:
        comet_cfg = make_comet_config(Path("/tmp"), enabled=True)
        gateway_cfg = make_comet_gateway_config(Path("/tmp"), enabled=True)
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            stremio_enabled=False,
            comet_config=comet_cfg,
            comet_gateway_config=gateway_cfg,
        )
        self.assertNotIn('"10.0.0.1:11470:11470"', content)
        self.assertIn('"10.0.0.1:18001:8090"', content)
        self.assertIn('"127.0.0.1:18000:8000"', content)
        self.assertIn("comet:", content)
        self.assertIn("comet-gateway:", content)
