FROM anguslees/scapy

RUN rm /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian buster main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security buster/updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian buster-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' | tee /etc/apt/apt.conf.d/99no-check-valid-until && \
    apt update && apt -y upgrade && apt install -q -y cron nano

RUN echo "*/5 * * * * /app/check.sh 2>&1" >> dhcp.cron && crontab dhcp.cron && rm dhcp.cron

WORKDIR /app
COPY ./scripts .
COPY ./entrypoint.sh /

CMD [ "python", "./dhcp2.py", "eth0" ]
