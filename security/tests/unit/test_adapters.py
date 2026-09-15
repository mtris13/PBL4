import unittest
from datetime import timedelta
from unittest.mock import patch

from security.response.base import AddressPolicy
from security.response.dry_run import DryRunAdapter
from security.response.ufw import UfwAdapter
from security.response.iptables import IptablesAdapter
from security.response.aws_waf import AwsWafAdapter
from security.tests.helpers import START, block


class AdapterTests(unittest.TestCase):
    def test_protected_addresses(self):
        policy = AddressPolicy(allowlist=["192.0.2.0/24"], trusted_proxies=["10.0.0.0/24"],
                               alb_networks=["10.1.0.0/24"], admin_networks=["203.0.113.4/32"])
        for cls in (DryRunAdapter, UfwAdapter, IptablesAdapter):
            for address in ("127.1.2.3", "::1", "::ffff:127.0.0.1", "0.0.0.0", "ff02::1", "fe80::1",
                            "192.0.2.9", "10.0.0.5", "10.1.0.9", "203.0.113.4"):
                with self.subTest(adapter=cls.__name__, address=address):
                    result = cls(policy).respond(block(address))
                    self.assertEqual(result.outcome, "suppressed_protected_address")
                    self.assertEqual(result.commands, ())

    def test_command_injection_rejected(self):
        for cls in (DryRunAdapter, UfwAdapter, IptablesAdapter):
            for value in ("1.2.3.4; whoami", "$(whoami)", "1.2.3.4\n--help", "--help", "1.2.3.4/32", "fe80::1%eth0"):
                with self.subTest(adapter=cls.__name__, value=value), self.assertRaises(ValueError):
                    cls(AddressPolicy()).respond(block(value))

    def test_idempotence_and_expiry(self):
        for cls in (DryRunAdapter, UfwAdapter, IptablesAdapter):
            adapter = cls(AddressPolicy())
            self.assertEqual(adapter.respond(block()).outcome, "would_block")
            self.assertEqual(adapter.respond(block()).outcome, "already_planned")
            self.assertEqual(adapter.expire(START + timedelta(seconds=299)), [])
            records = adapter.expire(START + timedelta(seconds=300))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].outcome, "would_unblock")
            self.assertEqual(adapter.expire(START + timedelta(seconds=301)), [])
            self.assertEqual(adapter.respond(block(timestamp=START + timedelta(seconds=301))).outcome, "would_block")

    def test_host_firewalls_refuse_proxy(self):
        for cls in (UfwAdapter, IptablesAdapter):
            result = cls(AddressPolicy()).respond(block(via_trusted_proxy=True))
            self.assertEqual(result.outcome, "unsupported_proxy_topology_use_waf")
            self.assertFalse(result.commands)

    def test_command_arguments_and_ipv6(self):
        iptables = IptablesAdapter(AddressPolicy())
        self.assertEqual(iptables.commands("198.51.100.23")[0][:5], ("iptables", "-w", "-I", "INPUT", "1"))
        self.assertEqual(iptables.commands("2001:db8::1", True)[0][:4], ("ip6tables", "-w", "-D", "INPUT"))
        ufw = UfwAdapter(AddressPolicy())
        self.assertEqual(ufw.commands("198.51.100.23")[0],
                         ("ufw", "insert", "1", "deny", "from", "198.51.100.23", "to", "any"))
        self.assertEqual(ufw.commands("198.51.100.23", True)[0][:3], ("ufw", "--force", "delete"))

    def test_no_execution(self):
        with patch("subprocess.run", side_effect=AssertionError("Execution forbidden")), \
                patch("subprocess.Popen", side_effect=AssertionError("Execution forbidden")), \
                patch("os.system", side_effect=AssertionError("Execution forbidden")):
            for cls in (DryRunAdapter, UfwAdapter, IptablesAdapter):
                adapter = cls(AddressPolicy())
                self.assertFalse(adapter.respond(block()).executed)
                self.assertFalse(adapter.expire(START + timedelta(seconds=300))[0].executed)

    def test_invalid_duration_and_action(self):
        for changes in ({"block_duration_seconds": 0}, {"block_duration_seconds": -1}, {"action": "execute"}):
            with self.assertRaises(ValueError):
                DryRunAdapter(AddressPolicy()).respond(block(**changes))

    def test_lease_capacity_fails_closed(self):
        adapter = DryRunAdapter(AddressPolicy(), max_active_leases=1)
        self.assertEqual(adapter.respond(block("198.51.100.23")).outcome, "would_block")
        result = adapter.respond(block("203.0.113.9"))
        self.assertEqual(result.outcome, "lease_capacity_reached")
        self.assertEqual(result.commands, ())
        self.assertNotIn("203.0.113.9", adapter.leases)

    def test_waf_explicit_placeholder(self):
        self.assertEqual(AwsWafAdapter().respond(block()).outcome, "not_implemented")
        self.assertEqual(AwsWafAdapter().expire(START), [])
