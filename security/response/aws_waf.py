from security.response.base import ResponseRecord, validated_ip


class AwsWafAdapter:
    """Integration placeholder, intentionally no AWS calls or simulated success.

    TODO: separate IPv4/IPv6 IP sets, WebACL/scope/region configuration, optimistic
    lock retries, IAM least privilege, durable expiry and reconciliation.
    """
    def respond(self, decision):
        return ResponseRecord(validated_ip(decision.source_ip), decision.action,
                              "not_implemented", "aws_waf", decision.timestamp,
                              reasons=decision.reasons)

    def expire(self, now):
        return []
