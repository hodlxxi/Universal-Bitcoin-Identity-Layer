# Production Quick Reference

Use this card during on-call rotations or maintenance windows.  Commands assume the application lives under `/srv/app`, runs as the `hodlxxi` user, and is managed by the `app.service` systemd unit.  Tweak names or paths if your deployment differs.

## Pre-Deployment Checks

- [ ] DNS records resolve to the host you are deploying
- [ ] App passes the local health check (`curl http://127.0.0.1:5000/health`)
- [ ] PostgreSQL and Redis are reachable
- [ ] Port 80 is reachable for ACME/Let’s Encrypt issuance

## Service Management

```bash
# Status
sudo systemctl status app nginx postgresql redis-server

# Restart
sudo systemctl restart app nginx

# Logs
sudo journalctl -u app -f
sudo tail -f /var/log/nginx/hodlxxi-error.log
```

## Backup & Restore

```bash
# Manual backup
sudo /usr/local/bin/hodlxxi-backup.sh

# List backups
ls -lh /backup/hodlxxi/

# Restore latest backup
sudo /usr/local/bin/hodlxxi-restore.sh /backup/hodlxxi/hodlxxi_db_YYYYMMDD_HHMMSS.sql.gz
```

## TLS Certificates

```bash
# Inspect certs
sudo certbot certificates

# Force renewal
sudo certbot renew --force-renewal

# Dry run renewal
sudo certbot renew --dry-run
```

## Firewall + Fail2ban

```bash
# UFW status
sudo ufw status verbose

# Allow an additional port
sudo ufw allow 8333/tcp

# Fail2ban status
sudo fail2ban-client status
sudo fail2ban-client status sshd

# Unban an IP
sudo fail2ban-client set sshd unbanip 203.0.113.10
```

## Monitoring & Diagnostics

```bash
# Resource utilisation
htop

# Disk usage
df -h

du -sh /backup/hodlxxi/

# Database size
sudo -u postgres psql -c "\\l+ hodlxxi"
```

## HTTP Smoke Tests

```bash
# Health
curl https://<your-domain>/health

# OIDC configuration
curl https://<your-domain>/.well-known/openid-configuration | jq

# OAuth client registration (example)
curl -X POST https://<your-domain>/oauth/register \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["https://example.com/callback"]}' | jq
```

## Emergency Actions

- **App unhealthy (502 from Nginx):** Verify `systemctl status app` then inspect `journalctl -u app` for stack traces.
- **TLS renewal failing:** Check DNS entries and that port 80 is reachable; rerun Certbot with `--force-renewal`.
- **Locked out by firewall:** Use the VPS console/serial access to `sudo ufw disable`, then reapply desired rules.
- **Database corruption:** Stop the app, restore the latest backup, and restart services once restored.

Keep this document in sync with any changes to service names, ports, or automation scripts so on-call responders have accurate directions.
