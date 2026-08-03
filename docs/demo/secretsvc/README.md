# secretsvc — data-exfiltration demo target

A tiny "customer records" API used for the stage demo of **containing data exfiltration**.

## Endpoints

| Path | Role | Behavior |
|------|------|----------|
| `GET /` | legit | liveness `ok` |
| `GET /orders` | legit | reads `/data/orders.json` |
| `GET /export?to=<ip>` | **attack** | reads `/secrets/db.env` and POSTs it to `http://<ip>/ingest` |

Profile only `/` and `/orders`. Under enforcement the secret read and/or the
egress to an un-profiled C2 IP are denied, while `/orders` keeps serving.

## Build & run

```bash
docker build -t secretsvc docs/demo/secretsvc
docker run -d --name secretsvc -p 8081:8081 --restart unless-stopped secretsvc
```

Or use `docs/demo/setup.sh`, which builds and keeps all three demo containers up.
