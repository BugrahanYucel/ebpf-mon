# Vulnerable demo target for the ebpf-mon enforcement demo. DO NOT DEPLOY.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY vulnapp.py /app/vulnapp.py
RUN printf 'app: demo\nenv: talk\n' > /app/config.txt
EXPOSE 8080
CMD ["python3", "/app/vulnapp.py"]
