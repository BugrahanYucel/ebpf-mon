# Dockerfile for isolated testing environment
FROM python:3.9-slim

# Install network tools for more comprehensive testing
RUN apt-get update && rm -rf /var/lib/apt/lists/*

WORKDIR /workload

# Copy test harness
COPY test_workload.py .

# Default command
CMD ["python3", "test_workload.py", "/output/ground_truth.json"]







