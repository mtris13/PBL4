#!/usr/bin/env bash
# Controlled Docker published-port test on an isolated veth. No external target or image pull.
set -Eeuo pipefail

export LC_ALL=C

readonly NETNS="pbl4-docker-client"
readonly HOST_IF="pbl4dk-host"
readonly PEER_IF="pbl4dk-peer"
readonly HOST_CIDR="198.18.0.5/30"
readonly HOST_IP="198.18.0.5"
readonly PEER_CIDR="198.18.0.6/30"
readonly PEER_IP="198.18.0.6"
readonly HOST_PORT="19081"
readonly CONTAINER_PORT="18080"
readonly CONTAINER_NAME="pbl4-firewall-lab-temporary"
readonly IMAGE_NAME="pbl4-firewall-lab:temporary"

RULE_ADDED=0
CONTAINER_CREATED=0
IMAGE_CREATED=0
TEMP_DIR=""
BASELINE_ALLOWED=0
RULE=(-i "$HOST_IF" -p tcp -m conntrack --ctorigdst "$HOST_IP" \
      --ctorigdstport "$HOST_PORT" -j DROP)

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
        if iptables -C DOCKER-USER "${RULE[@]}" >/dev/null 2>&1; then
            iptables -D DOCKER-USER "${RULE[@]}" >/dev/null 2>&1 || cleanup_failed=1
        fi
    fi
    if [[ "$CONTAINER_CREATED" == 1 ]] && docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
        docker container rm --force "$CONTAINER_NAME" >/dev/null 2>&1 || cleanup_failed=1
    fi
    if [[ "$IMAGE_CREATED" == 1 ]] && docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        docker image rm --force "$IMAGE_NAME" >/dev/null 2>&1 || cleanup_failed=1
    fi
    ip netns del "$NETNS" 2>/dev/null
    ip link del "$HOST_IF" 2>/dev/null
    if [[ -n "$TEMP_DIR" && "$TEMP_DIR" == /tmp/pbl4-docker-firewall-lab.* ]]; then
        find "$TEMP_DIR" -depth -delete 2>/dev/null
    fi

    iptables -C DOCKER-USER "${RULE[@]}" >/dev/null 2>&1 && cleanup_failed=1
    docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1 && cleanup_failed=1
    docker image inspect "$IMAGE_NAME" >/dev/null 2>&1 && cleanup_failed=1
    ip netns list | awk '{print $1}' | grep -Fxq "$NETNS" && cleanup_failed=1
    ip link show "$HOST_IF" >/dev/null 2>&1 && cleanup_failed=1

    if [[ "$cleanup_failed" == 1 ]]; then
        echo "FAIL: temporary Docker or DOCKER-USER state needs manual review." >&2
        exit 1
    fi
    if [[ "$original_status" == 0 ]]; then
        echo "RESULT: PASS (baseline_allowed=$BASELINE_ALLOWED, cleanup=pass)"
    fi
    exit "$original_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$EUID" == 0 ]] || fail "run with sudo: sudo bash deploy/arch/docker_firewall_lab.sh"
[[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] || fail "run from the normal user account via sudo"

for command in ip curl ufw ss runuser go docker iptables find systemctl; do
    command -v "$command" >/dev/null || fail "missing command: $command"
done

UFW_STATUS=$(ufw status verbose)
grep -q '^Status: active$' <<<"$UFW_STATUS" || fail "UFW must already be active"
grep -q 'Default: deny (incoming)' <<<"$UFW_STATUS" || fail "UFW incoming default must be deny"
systemctl is-enabled --quiet ufw.service || fail "ufw.service must be enabled for reboot persistence"
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"
iptables -S DOCKER-USER >/dev/null 2>&1 || fail "Docker DOCKER-USER chain is unavailable"
! iptables -C DOCKER-USER "${RULE[@]}" >/dev/null 2>&1 || fail "temporary rule already exists"
! ip netns list | awk '{print $1}' | grep -Fxq "$NETNS" || fail "namespace $NETNS already exists"
! ip link show "$HOST_IF" >/dev/null 2>&1 || fail "interface $HOST_IF already exists"
! ip -o address show | grep -Eq '198\.18\.0\.[56]/' || fail "test addresses are already in use"
! ss -H -ltn "sport = :$HOST_PORT" | grep -q . || fail "TCP port $HOST_PORT is already in use"
! docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1 || fail "container name already exists"
! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1 || fail "image name already exists"

TEMP_DIR=$(mktemp -d /tmp/pbl4-docker-firewall-lab.XXXXXX)
chown "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$TEMP_DIR"
chmod 700 "$TEMP_DIR"

cat >"$TEMP_DIR/server.go" <<'EOF'
package main

import (
    "io"
    "net/http"
    "time"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/healthz", func(response http.ResponseWriter, request *http.Request) {
        response.Header().Set("Content-Type", "text/plain")
        io.WriteString(response, "pbl4-docker-firewall-lab-ok\n")
    })
    server := &http.Server{Addr: ":18080", Handler: mux, ReadHeaderTimeout: 2 * time.Second,
        IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
    if err := server.ListenAndServe(); err != nil {
        panic(err)
    }
}
EOF
cat >"$TEMP_DIR/Dockerfile" <<'EOF'
FROM scratch
COPY pbl4-server /pbl4-server
USER 65534:65534
ENTRYPOINT ["/pbl4-server"]
EOF
chown "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$TEMP_DIR/server.go" "$TEMP_DIR/Dockerfile"
mkdir "$TEMP_DIR/go-cache"
chown "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$TEMP_DIR/go-cache"
runuser -u "$SUDO_USER" -- env CGO_ENABLED=0 GOCACHE="$TEMP_DIR/go-cache" \
    go build -trimpath -ldflags='-s -w' -o "$TEMP_DIR/pbl4-server" "$TEMP_DIR/server.go"
find "$TEMP_DIR/go-cache" -depth -delete

IMAGE_CREATED=1
docker build --network none --pull=false --tag "$IMAGE_NAME" "$TEMP_DIR" >/dev/null

ip netns add "$NETNS"
ip link add "$HOST_IF" type veth peer name "$PEER_IF"
ip link set "$PEER_IF" netns "$NETNS"
ip address add "$HOST_CIDR" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NETNS" ip link set lo up
ip netns exec "$NETNS" ip address add "$PEER_CIDR" dev "$PEER_IF"
ip netns exec "$NETNS" ip link set "$PEER_IF" up

CONTAINER_CREATED=1
docker run --detach --name "$CONTAINER_NAME" --network bridge --read-only \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 \
    --publish "$HOST_IP:$HOST_PORT:$CONTAINER_PORT/tcp" "$IMAGE_NAME" >/dev/null

for _ in {1..30}; do
    if curl --noproxy '*' -fsS --connect-timeout 1 --max-time 1 \
        "http://$HOST_IP:$HOST_PORT/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 \
    "http://$HOST_IP:$HOST_PORT/healthz" | grep -Fxq 'pbl4-docker-firewall-lab-ok' \
    || fail "host cannot reach the temporary published port"

echo "[1/3] Observe UFW default-deny behavior on a Docker published port"
if ip netns exec "$NETNS" curl --noproxy '*' -fsS --connect-timeout 1 --max-time 3 \
    "http://$HOST_IP:$HOST_PORT/healthz" >/dev/null 2>&1; then
    BASELINE_ALLOWED=1
    echo "OBSERVED: published port bypassed UFW INPUT default deny"
else
    echo "OBSERVED: current forwarding policy denied the published port"
fi

echo "[2/3] Add one exact temporary DOCKER-USER rule"
RULE_ADDED=1
iptables -I DOCKER-USER 1 "${RULE[@]}"
iptables -C DOCKER-USER "${RULE[@]}" >/dev/null || fail "temporary rule was not installed"
if ip netns exec "$NETNS" curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 \
    "http://$HOST_IP:$HOST_PORT/healthz" >/dev/null 2>&1; then
    fail "DOCKER-USER rule did not deny the isolated peer"
fi
echo "PASS: exact original destination and port were denied"

echo "[3/3] Remove the rule and verify the baseline behavior returns"
iptables -D DOCKER-USER "${RULE[@]}"
RULE_ADDED=0
if [[ "$BASELINE_ALLOWED" == 1 ]]; then
    ip netns exec "$NETNS" curl --noproxy '*' -fsS --connect-timeout 1 --max-time 3 \
        "http://$HOST_IP:$HOST_PORT/healthz" | grep -Fxq 'pbl4-docker-firewall-lab-ok' \
        || fail "baseline allowed behavior did not return"
else
    if ip netns exec "$NETNS" curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 \
        "http://$HOST_IP:$HOST_PORT/healthz" >/dev/null 2>&1; then
        fail "baseline denied behavior changed after rule removal"
    fi
fi
! iptables -C DOCKER-USER "${RULE[@]}" >/dev/null 2>&1 || fail "temporary rule remains"

echo "TEST: PASS (baseline_allowed=$BASELINE_ALLOWED)"
echo "Running cleanup for the container, image, namespace, veth pair and temporary files."
