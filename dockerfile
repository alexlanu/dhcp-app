
FROM anguslees/scapy

ENV TZ="Europe/Moscow"

RUN rm /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian buster main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security buster/updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian buster-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' | tee /etc/apt/apt.conf.d/99no-check-valid-until && \
    apt update && apt -y upgrade && apt install -q -y cron nano

WORKDIR /app
COPY ./scripts .

CMD [ "python", "./dhcp4.py", "eth0" ]
