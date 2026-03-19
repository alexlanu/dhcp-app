#!/bin/bash

# Настраиваем cron задание с актуальными переменными окружения
echo "*/5 * * * * root DHCP_INT='$DHCP_INT' DHCP_ALLOW_IP='$DHCP_ALLOW_IP' /app/check.sh" > /etc/cron.d/dhcp-job

# Применяем задание
chmod 0644 /etc/cron.d/dhcp-job
crontab /etc/cron.d/dhcp-job
