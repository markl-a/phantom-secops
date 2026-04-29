# Lab targets

Documentation for the intentionally vulnerable applications used in this
project's lab. All targets are legally distributed for security education
and research.

## OWASP Juice Shop

- **Image**: `bkimminich/juice-shop:latest`
- **License**: MIT
- **Source**: https://github.com/juice-shop/juice-shop
- **Default port (in lab)**: 3000
- **What's in it**: a modern JavaScript single-page application with the
  full OWASP Top 10 vulnerabilities woven in as challenges. Used worldwide
  for security training.

## DVWA (Damn Vulnerable Web Application)

- **Image**: `vulnerables/web-dvwa:latest`
- **License**: GPL-3.0
- **Source**: https://github.com/digininja/DVWA
- **Default port (in lab)**: 80
- **What's in it**: a classic PHP/MySQL deliberately vulnerable web app.
  Each vulnerability has Easy/Medium/Hard/Impossible difficulty levels.

## Metasploitable 3 *(optional)*

Not enabled by default in `docker-compose.yml` — Metasploitable is heavier
(~2GB image) and takes longer to spin up. Add the service block from
`metasploitable.yml.example` if you want to demo against it.

## Healthcheck troubleshooting

If `docker compose up -d` reports a target as unhealthy:

```bash
# Check container status
docker compose ps

# Tail logs of a specific service
docker compose logs juice-shop --tail=50

# Restart a single service
docker compose restart juice-shop
```

If Juice Shop hangs at startup on Apple Silicon, the image now ships
multi-arch — make sure you're on a recent `bkimminich/juice-shop:latest`
pull (`docker compose pull juice-shop`).

## Network exposure

By default, no host ports are published. Targets are reachable only from
inside the docker network `secops-lab`. The phantom agents use
`docker exec` into the `attacker` container to reach them.

If you need browser access for manual exploration (e.g., to view a finding),
uncomment the `ports:` block in `docker-compose.yml` for that specific service
and bind to `127.0.0.1` only.

**Never publish these ports on `0.0.0.0` or a public network.**
