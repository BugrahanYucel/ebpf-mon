# Customer-records API for the data-exfil demo. DO NOT DEPLOY.
FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/app.py
COPY orders.json /data/orders.json
COPY db.env /secrets/db.env
RUN chmod 600 /secrets/db.env
EXPOSE 8081
CMD ["python3", "/app/app.py"]
