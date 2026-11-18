# Wazuh integration

Every Wazuh alert above a chosen level is sent to TIScan. TIScan checks the source IP, URL or
file hash and writes an enrichment event back to Wazuh. The rules in `tiscan_rules.xml` then
raise a new alert, level 7 for medium, 12 for high and 14 for critical, with a link to the
full TIScan report.

```
Wazuh alert (e.g. SSH brute force from 185.x.x.x)
      │  custom-tiscan
      ▼
TIScan /api/scan  ──►  VirusTotal, AbuseIPDB, ThreatFox, GreyNoise, Spamhaus …
      │  risk 87 / critical
      ▼
Wazuh queue  ──►  rule 100904  "TIScan: 185.x.x.x is CRITICAL threat"
```

## 1. Make TIScan reachable from the Wazuh manager

Set these in TIScan's `.env` and restart it:

```ini
TISCAN_HOST=0.0.0.0
TISCAN_API_TOKEN=<long random string>
```

Requests from other machines must then send the token. The script sends it automatically.

## 2. Install the script on the Wazuh manager

```bash
sudo cp custom-tiscan /var/ossec/integrations/custom-tiscan
sudo chmod 750 /var/ossec/integrations/custom-tiscan
sudo chown root:wazuh /var/ossec/integrations/custom-tiscan
sudo cp tiscan_rules.xml /var/ossec/etc/rules/tiscan_rules.xml
```

## 3. Enable it in `/var/ossec/etc/ossec.conf`

```xml
<integration>
  <name>custom-tiscan</name>
  <hook_url>http://TISCAN_HOST:8787</hook_url>
  <api_key>YOUR_TISCAN_API_TOKEN</api_key>
  <level>6</level>
  <alert_format>json</alert_format>
</integration>
```

Use `<group>` or `<rule_id>` instead of `<level>` to limit which alerts get enriched, for example
`<group>sshd,web,syscheck,</group>`. This saves API quota.

```bash
sudo systemctl restart wazuh-manager
tail -f /var/ossec/logs/integrations.log
```
