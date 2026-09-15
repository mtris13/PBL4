#!/usr/bin/env bash
# Controlled UFW INPUT test using an isolated network namespace. No external target.
set -Eeuo pipefail

export LC_ALL=C

readonly NETNS="pbl4-fw-client"
readonly HOST_IF="pbl4fw-host"
readonly PEER_IF="pbl4fw-peer"
readonly HOST_CIDR="198.18.0.1/30"
readonly HOST_IP="198.18.0.1"
readonly PEER_CIDR="198.18.0.2/30"
readonly PEER_IP="198.18.0.2"
readonly PORT="19080"
readonly COMMENT="PBL4 temporary firewall lab"

RULE_ADDED=0
SERVER_PID=""
TEMP_DIR=""

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

cleanup() {
    local original_status=$?
    local cleanup_failed=0
    trap - EXIT INT TERM
    set +e

    if [[ "$RULE_ADDED" == 1 ]]; then
        ufw --force delete allow in on "$HOST_IF" from "$PEER_IP" to "$HOST_IP" \
            port "$PORT" proto tcp >/dev/null || cleanup_failed=1
    fi
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    ip netns del "$NETNS" 2>/dev/null
    ip link del "$HOST_IF" 2>/dev/null
    if [[ -n "$TEMP_DIR" && "$TEMP_DIR" == /tmp/pbl4-firewall-lab.* ]]; then
        rm -f -- "$TEMP_DIR/healthz" "$TEMP_DIR/server.log"
        rmdir -- "$TEMP_DIR" 2>/dev/null
    fi

    if [[ "$cleanup_failed" == 1 ]]; then
        echo "FAIL: could not remove the temporary UFW rule; inspect 'ufw status numbered'." >&2
        exit 1
    fi
    exit "$original_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$EUID" == 0 ]] || fail "run with sudo: sudo bash deploy/arch/firewall_lab.sh"
[[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] || fail "run from the normal user account via sudo"

for command in ip curl ufw ss runuser python; do
    command -v "$command" >/dev/null || fail "missing command: $command"
done

UFW_STATUS=$(ufw status verbose)
grep -q '^Status: active$' <<<"$UFW_STATUS" || fail "UFW must already be active"
grep -q 'Default: deny (incoming)' <<<"$UFW_STATUS" || fail "UFW incoming default must be deny"
! ip netns list | awk '{print $1}' | grep -Fxq "$NETNS" || fail "namespace $NETNS already exists"
! ip link show "$HOST_IF" >/dev/null 2>&1 || fail "interface $HOST_IF already exists"
! ip -o address show | grep -Eq '198\.18\.0\.[12]/' || fail "test addresses are already in use"
! ss -H -ltn "sport = :$PORT" | grep -q . || fail "TCP port $PORT is already in use"

DOCKER_CHAIN_PRESENT=0
if iptables -S DOCKER-USER >/dev/null 2>&1; then
    DOCKER_CHAIN_PRESENT=1
fi

TEMP_DIR=$(mktemp -d /tmp/pbl4-firewall-lab.XXXXXX)
printf 'pbl4-firewall-lab-ok\n' >"$TEMP_DIR/healthz"
chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$TEMP_DIR"
chmod 700 "$TEMP_DIR"

ip netns add "$NETNS"
ip link add "$HOST_IF" type veth peer name "$PEER_IF"
ip link set "$PEER_IF" netns "$NETNS"
ip address add "$HOST_CIDR" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NETNS" ip link set lo up
ip netns exec "$NETNS" ip address add "$PEER_CIDR" dev "$PEER_IF"
ip netns exec "$NETNS" ip link set "$PEER_IF" up

runuser -u "$SUDO_USER" -- python -m http.server "$PORT" --bind "$HOST_IP" \
    --directory "$TEMP_DIR" >"$TEMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in {1..20}; do
    if curl --noproxy '*' -fsS --connect-timeout 1 --max-time 1 \
        "http://$HOST_IP:$PORT/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
kill -0 "$SERVER_PID" 2>/dev/null || fail "temporary HTTP server did not start"
curl --noproxy '*' -fsS --connect-timeout 1 --max-time 1 \
    "http://$HOST_IP:$PORT/healthz" >/dev/null || fail "host cannot reach temporary server"

echo "[1/3] Default deny from isolated peer"
if ip netns exec "$NETNS" curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 \
    "http://$HOST_IP:$PORT/healthz" >/dev/null 2>&1; then
    fail "connection succeeded before an allow rule was added"
fi
echo "PASS: UFW denied the new inbound connection"

echo "[2/3] Temporary allow rule"
ufw allow in on "$HOST_IF" from "$PEER_IP" to "$HOST_IP" port "$PORT" proto tcp \
    comment "$COMMENT" >/dev/null
RULE_ADDED=1
ip netns exec "$NETNS" curl --noproxy '*' -fsS --connect-timeout 1 --max-time 3 \
    "http://$HOST_IP:$PORT/healthz" | grep -Fxq 'pbl4-firewall-lab-ok' \
    || fail "connection did not succeed with the temporary allow rule"
echo "PASS: the reviewed allow rule admitted only the lab peer and port"

echo "[3/3] Remove allow rule and verify deny again"
ufw --force delete allow in on "$HOST_IF" from "$PEER_IP" to "$HOST_IP" \
    port "$PORT" proto tcp >/dev/null
RULE_ADDED=0
if ip netns exec "$NETNS" curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 \
    "http://$HOST_IP:$PORT/healthz" >/dev/null 2>&1; then
    fail "connection still succeeded after the allow rule was removed"
fi
echo "PASS: UFW denied the connection after rule removal"

if [[ "$DOCKER_CHAIN_PRESENT" == 1 ]]; then
    iptables -S DOCKER-USER >/dev/null 2>&1 || fail "Docker's DOCKER-USER chain disappeared"
fi
UFW_STATUS=$(ufw status)
grep -q '^Status: active$' <<<"$UFW_STATUS" || fail "UFW is no longer active"

echo "RESULT: PASS"
echo "Cleanup will remove the namespace, veth pair, server and temporary files."
