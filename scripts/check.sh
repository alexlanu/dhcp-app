#!/bin/sh

RES="$(/usr/local/bin/python /app/dhcp2.py eth0)"
echo $RES > /app/dhcp.out
echo $RES
