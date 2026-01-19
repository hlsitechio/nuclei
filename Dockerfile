FROM projectdiscovery/nuclei:latest

# Clear the entrypoint from base image
ENTRYPOINT []

# Install Python for API wrapper
USER root
RUN apk add --no-cache python3 py3-pip curl

# Install Flask
RUN pip3 install flask gunicorn --break-system-packages

# Update nuclei templates
RUN nuclei -update-templates

WORKDIR /app
COPY server.py .

EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "-t", "300", "server:app"]
