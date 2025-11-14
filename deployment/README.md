# Production Deployment Runbook

This folder contains the operational scripts and guides for taking the Universal Bitcoin Identity Layer into production.  The instructions below describe the default single-node deployment path that ships with this repo; adapt naming, paths, and automation to match your infrastructure standards.

## Prerequisites

- Ubuntu 20.04+/Debian 11+ host (or equivalent) with root/sudo access
- Application code deployed under `/srv/app` (update the scripts if you relocate it)
- PostgreSQL and Redis reachable from the host
- Public DNS entries pointed at the host if you plan to terminate HTTPS locally
- Ports 22, 80, and 443 open in your firewall/security groups

## Quick Start (Automated)

The [`deploy-production.sh`](./deploy-production.sh) script provisions Nginx, obtains TLS certificates via Certbot, configures a locked-down systemd unit (`app.service`), and installs the backup automation used by the project.

```bash
cd /srv/app
# ensure you are on the branch/tag you intend to deploy
git pull --ff-only
cd deployment
sudo bash deploy-production.sh
```

> **Heads up:** The automation expects Gunicorn to run `wsgi:create_app()` under the `hodlxxi` user.  If you swap process managers or change service names, update the generated unit files before running the script.

## Manual Flow

If you need granular control or want to audit each step, execute the helpers individually:

1. **Security Hardening** – `sudo bash security-hardening.sh`
   - Configures UFW, Fail2ban, system users, and filesystem permissions.
2. **Reverse Proxy & TLS** – Install Nginx + Certbot and apply `nginx-hodlxxi.conf` (customise server names and upstreams to match your domain and port).
3. **App Service** – Install/enable your process manager unit.  The provided scripts expect `/etc/systemd/system/app.service` invoking `gunicorn --config /srv/app/scripts/gunicorn.conf.py wsgi:create_app()`.
4. **Backups** – `sudo bash setup-automated-backups.sh` installs `/usr/local/bin/hodlxxi-backup.sh` and related cron/systemd timers targeting `/backup/hodlxxi`.

Review and adapt the scripts before running them against production systems—especially if you run multiple services on the same machine.

## Operations Cheat Sheet

[`QUICK_REFERENCE.md`](./QUICK_REFERENCE.md) summarises the commands you are most likely to need during incident response or maintenance (service restarts, backup validation, certificate renewal, etc.).

## Related Documentation

- [`app/PRODUCTION_DEPLOYMENT.md`](../app/PRODUCTION_DEPLOYMENT.md) – Expanded environment checklist, scaling strategies, and troubleshooting matrix.
- [`README.md`](../README.md) – Overview of configuration knobs, authentication flows, and observability endpoints.
- [`TESTING.md`](../TESTING.md) – How to exercise smoke and regression suites prior to rollout.

Keep scripts idempotent and re-runnable where possible. If you change ports, user names, or directories, document the divergence in your fork so future operators have accurate runbooks.
