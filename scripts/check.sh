#!/bin/bash

# Получаем переменные окружения
DHCP_INT="${DHCP_INT}"
DHCP_ALLOW_IP="${DHCP_ALLOW_IP}"

# Проверяем, что переменные установлены
if [ -z "$DHCP_INT" ] || [ -z "$DHCP_ALLOW_IP" ]; then
    echo "Ошибка: не установлены переменные окружения DHCP_INT и DHCP_ALLOW_IP" >> /app/dhcp.err
    exit 1
fi

RES="$(/usr/local/bin/python /app/dhcp4.py "$DHCP_INT" "$DHCP_ALLOW_IP")"

echo $RES > /app/dhcp4.out
echo $RES
