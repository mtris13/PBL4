from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import Protocol

from security.analyzer.models import Decision


def validated_ip(value: str) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Expected a plain IPv4 or IPv6 address")
    return str(ip_address(value))


class AddressPolicy:
    def __init__(self, allowlist=(), trusted_proxies=(), alb_networks=(), admin_networks=()):
        groups = (allowlist, trusted_proxies, alb_networks, admin_networks)
        if any(not isinstance(group, (list, tuple)) for group in groups):
            raise ValueError("Address lists must be arrays of IPs or CIDRs")
        self.trusted = tuple(ip_network(n) for n in trusted_proxies)
        self.protected = tuple(ip_network(n) for group in groups for n in group)

    def is_trusted(self, address: str) -> bool:
        addr = ip_address(validated_ip(address))
        return any(addr in net for net in self.trusted)

    def is_protected(self, address: str) -> bool:
        addr = ip_address(validated_ip(address))
        return (addr.is_loopback or addr.is_unspecified or addr.is_multicast
                or addr.is_link_local or str(addr) == "255.255.255.255"
                or any(addr in net for net in self.protected)
                or (addr.version == 6 and addr.ipv4_mapped is not None
                    and self.is_protected(str(addr.ipv4_mapped))))


@dataclass(frozen=True)
class ResponseRecord:
    source_ip: str
    action: str
    outcome: str
    adapter: str
    timestamp: datetime
    expires_at: datetime | None = None
    commands: tuple[tuple[str, ...], ...] = ()
    reasons: tuple[str, ...] = ()
    executed: bool = False


class ResponseAdapter(Protocol):
    def respond(self, decision: Decision) -> ResponseRecord: ...
    def expire(self, now: datetime) -> list[ResponseRecord]: ...


class PreviewAdapter:
    """In-memory leases model plans only. No subprocess or firewall execution path."""
    name = "preview"
    host_firewall = False

    def __init__(self, policy: AddressPolicy):
        self.policy = policy
        self.leases: dict[str, datetime] = {}

    def commands(self, address: str, unblock: bool = False) -> tuple[tuple[str, ...], ...]:
        validated_ip(address)
        return ()

    def respond(self, decision: Decision) -> ResponseRecord:
        address = validated_ip(decision.source_ip)
        if decision.action not in ("observe", "alert", "temporary_block"):
            raise ValueError("Unknown response action")
        outcome, commands, expires = "recorded", (), None
        if decision.action == "temporary_block":
            if type(decision.block_duration_seconds) is not int or decision.block_duration_seconds <= 0:
                raise ValueError("Block duration must be a positive integer")
            if self.policy.is_protected(address):
                outcome = "suppressed_protected_address"
            elif self.host_firewall and decision.via_trusted_proxy:
                outcome = "unsupported_proxy_topology_use_waf"
            elif address in self.leases:
                # Caller must drain expire() first; never silently discard an unblock.
                outcome = "already_planned"
                expires = self.leases[address]
            else:
                expires = decision.timestamp + timedelta(seconds=decision.block_duration_seconds)
                self.leases[address] = expires
                outcome = "would_block"
                commands = self.commands(address)
        return ResponseRecord(address, decision.action, outcome, self.name,
                              decision.timestamp, expires, commands, decision.reasons)

    def expire(self, now: datetime) -> list[ResponseRecord]:
        records = []
        for address, expires in list(self.leases.items()):
            if expires <= now:
                records.append(ResponseRecord(address, "unblock", "would_unblock", self.name,
                                              now, expires, self.commands(address, unblock=True)))
                del self.leases[address]
        return records
