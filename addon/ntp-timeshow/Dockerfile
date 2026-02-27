ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.13-alpine3.21
FROM ${BUILD_FROM}

WORKDIR /app
RUN apk add --no-cache python3 py3-paho-mqtt

COPY ntp_scan.py /app/ntp_scan.py
COPY addon_runner.py /app/addon_runner.py
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
