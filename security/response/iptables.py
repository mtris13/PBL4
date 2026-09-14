from ipaddress import ip_address

from security.response.base import PreviewAdapter, validated_ip


class IptablesAdapter(PreviewAdapter):
    name = "iptables_preview"
    host_firewall = True

    def commands(self, address, unblock=False):
        address = validated_ip(address)
        executable = "ip6tables" if ip_address(address).version == 6 else "iptables"
        position = ("-D", "INPUT") if unblock else ("-I", "INPUT", "1")
        return ((executable, "-w") + position + ("-s", address, "-m", "comment", "--comment",
                                                "pbl4-security-preview", "-j", "DROP"),)
