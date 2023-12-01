#!/bin/ash

if ! [ -x "$(command -v ip)" ]; then
  echo 'Error: iproute2 is not installed.' >&2
  exit 1
fi

if [ -z "$REMOTE_IP" ] || [ -z "$IPV6_WITH_PREFIX" ]; then
  echo "REMOTE_IP and IPV6_WITH_PREFIX must be set"
  exit 1
fi

if ! lsmod | grep -q '^sit'; then
  echo "sit module is not loaded"
  exit 1
fi

if [ -z "$LOCAL_IP" ]; then
  LOCAL_IP=$(ip route get 1 | awk '{print $NF;exit}')
  if [ -z "$LOCAL_IP" ]; then
    echo "LOCAL_IP must be set"
    exit 1
  fi
  echo "LOCAL_IP not set, using $LOCAL_IP"
fi
TTL=${TTL:-255}

ip tunnel add he-ipv6 mode sit remote $REMOTE_IP local $LOCAL_IP ttl $TTL || {
  if [ $? -eq 1 ]; then
    echo "Permission error, trying to delete tunnel"
    ip tunnel del he-ipv6 || true
  else
    echo "Unknown error"
  fi
  exit 1
}
ip link set he-ipv6 up
ip addr add $IPV6_WITH_PREFIX dev he-ipv6
ip route replace ::/0 dev he-ipv6

if [ -n "$ADDITIONAL_RANGE" ]; then
    if ! sysctl -q -n net.ipv6.ip_nonlocal_bind | grep -q '^1$'; then
        echo "net.ipv6.ip_nonlocal_bind must be set to 1"
        exit 1
    fi
    ip -6 route replace local $ADDITIONAL_RANGE dev lo
fi

exec /v6rotator "$@"
