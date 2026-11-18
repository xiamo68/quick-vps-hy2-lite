import argparse
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from deploy import preflight
from deploy.preflight import hostname, port_conflicts, read_config, udp_port


class PreflightTests(unittest.TestCase):
    def test_absent_config_uses_detected_ip_and_defaults(self):
        with TemporaryDirectory() as folder:
            with (patch.object(preflight, "DEFAULT_CONFIG", Path(folder) / "install.env"),
                  patch.object(preflight, "detect_ipv4", return_value="8.8.8.8") as detect):
                settings = preflight.load_config(detect=True)
            detect.assert_called_once_with()
            self.assertEqual((settings.public_ipv4, settings.proxy_port), ("8.8.8.8", 24443))
            self.assertIsNone(settings.panel_host)

    def test_reads_ip_only_config_and_rejects_private_or_example_address(self):
        with TemporaryDirectory() as folder:
            config = Path(folder) / "install.env"
            config.write_text("PUBLIC_IPV4=8.8.8.8\nPANEL_HOST=\n", encoding="utf-8")
            result = read_config(config)
            self.assertEqual((result.public_ipv4, result.proxy_port), ("8.8.8.8", 24443))
            self.assertIsNone(result.panel_host)
            self.assertIsNone(result.proxy_host)
            for address in ("10.0.0.1", "203.0.113.10", "ff02::1", "224.0.0.1"):
                config.write_text(f"PUBLIC_IPV4={address}\n", encoding="utf-8")
                with self.subTest(address=address), self.assertRaisesRegex(ValueError, "PUBLIC_IPV4"):
                    read_config(config)

    def test_config_rejects_shell_syntax_and_duplicate_keys(self):
        with TemporaryDirectory() as folder:
            config = Path(folder) / "install.env"
            for line in ("export PUBLIC_IPV4=8.8.8.8", "PROXY_PORT=1234\nPROXY_PORT=5678"):
                config.write_text(line, encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_config(config)

    def test_distinguishes_tcp_and_udp_on_the_same_port(self):
        listeners = (
            "udp UNCONN 0 0 *:443 *:*\n"
            "udp UNCONN 0 0 0.0.0.0:24443 0.0.0.0:*\n"
            "tcp LISTEN 0 4096 [::]:443 [::]:*\n"
            "tcp LISTEN 0 4096 127.0.0.1:18771 0.0.0.0:*\n"
            "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
        )
        self.assertEqual(port_conflicts(listeners, 24443),
                         [("tcp", 443), ("tcp", 18771), ("udp", 24443)])

    def test_rejects_invalid_domain_and_port_arguments(self):
        self.assertEqual(hostname("Panel.Example.COM."), "panel.example.com")
        for value in ("https://example.com", "127.0.0.1", "example.com..", "example", "host:443"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                hostname(value)
        for value in ("0", "65536", "tcp"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                udp_port(value)
