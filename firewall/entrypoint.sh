#!/bin/bash

APP_IP=$(getent hosts app | awk '{ print $1 }')

for i in {1..20}; do
  if [ -n "$APP_IP" ]; then
      break
  fi
  sleep 1
  APP_IP=$(getent hosts app | awk '{ print $1 }')
done

iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination $APP_IP:5000
iptables -t nat -A POSTROUTING -j MASQUERADE

# Esperar indefinidamente (para que el contenedor no se cierre)
tail -f /dev/null