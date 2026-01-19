FROM alpine:3.19

# Install dependencies
RUN apk add --no-cache wget unzip python3 py3-pip curl bash

# Install nuclei from official releases
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    unzip nuclei_3.3.7_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_3.3.7_linux_amd64.zip && \
    chmod +x /usr/local/bin/nuclei

# Install templates (run in background during build)
RUN nuclei -update-templates -silent || true

# Install Flask
RUN pip3 install flask gunicorn --break-system-packages

WORKDIR /app
COPY server.py .

EXPOSE 8080

# Explicit startup - NOT nuclei, run gunicorn
CMD ["/usr/bin/python3", "-m", "gunicorn", "-b", "0.0.0.0:8080", "-t", "300", "--access-logfile", "-", "server:app"]
