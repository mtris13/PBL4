from security.response.base import PreviewAdapter, validated_ip


class UfwAdapter(PreviewAdapter):
    name = "ufw_preview"
    host_firewall = True

    def commands(self, address, unblock=False):
        address = validated_ip(address)
        prefix = ("ufw", "--force", "delete") if unblock else ("ufw", "insert", "1")
        return (prefix + ("deny", "from", address, "to", "any"),)
