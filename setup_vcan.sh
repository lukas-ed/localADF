#!/usr/bin/env bash
#
# setup_vcan.sh
# -------------
# Creates the two virtual CAN interfaces used by the test-bed:
#   vcan0 = production in-vehicle bus (ECUs + attacker)
#   vcan1 = forensic bus (read-only mirror observed by the component)
#
# Run once per boot.  Requires root (uses `sudo`).  Linux + SocketCAN only.
#
# Usage:
#   chmod +x setup_vcan.sh
#   ./setup_vcan.sh            # bring interfaces up
#   ./setup_vcan.sh down       # tear them down
#
set -euo pipefail

ACTION="${1:-up}"

bring_up() {
    # load the vcan kernel module (no-op if already loaded)
    sudo modprobe vcan

    for IF in vcan0 vcan1; do
        if ip link show "$IF" >/dev/null 2>&1; then
            echo "[setup] $IF already exists"
        else
            echo "[setup] creating $IF"
            sudo ip link add dev "$IF" type vcan
        fi
        sudo ip link set up "$IF"
        echo "[setup] $IF is up"
    done
    echo "[setup] done. vcan0 = production bus, vcan1 = forensic bus."
}

tear_down() {
    for IF in vcan0 vcan1; do
        if ip link show "$IF" >/dev/null 2>&1; then
            echo "[setup] removing $IF"
            sudo ip link set down "$IF" || true
            sudo ip link delete "$IF" type vcan || true
        fi
    done
    echo "[setup] interfaces removed."
}

case "$ACTION" in
    up)   bring_up ;;
    down) tear_down ;;
    *)    echo "usage: $0 [up|down]"; exit 1 ;;
esac
