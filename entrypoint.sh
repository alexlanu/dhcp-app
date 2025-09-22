#!/usr/bin/env bash

service cron start
tail -f /var/log/lastlog & wait $!
