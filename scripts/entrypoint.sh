#!/usr/bin/env bash

service cron start
/app/cron.sh
tail -f /var/log/lastlog & wait $!
