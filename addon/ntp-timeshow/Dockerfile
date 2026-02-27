ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.13-alpine3.21
FROM ${BUILD_FROM}

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

COPY ntp_scan.py /app/ntp_scan.py
COPY addon/ntp-timeshow/addon_runner.py /app/addon_runner.py
COPY addon/ntp-timeshow/run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
