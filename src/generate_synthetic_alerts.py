"""
generate_synthetic_alerts.py — Creates a realistic synthetic alert dataset.

This script generates ~250 security alerts that simulate what a defence
analyst would see in a real SOC (Security Operations Centre). The alerts
come from multiple "sources" (SIEM, IDS, firewall, email gateway, threat
intel feed) and contain a mix of:

  GENUINE THREATS (should be correlated into incidents):
  1. SSH Brute Force → Successful Login on WEB-SERVER-01
  2. Port Scan → Exploitation Attempt on WEB-SERVER-01
  3. Phishing Email → Credential Harvesting → Unusual Login on DC-01
  4. Lateral Movement Chain (internal) → Data Exfiltration
  5. C2 Beacon Activity from compromised WORKSTATION-042

  FALSE POSITIVES (noise that should be filtered out):
  6. Routine vulnerability scanner traffic
  7. DNS query spikes from automated software updates
  8. Single failed logins (no follow-up, just typos)
  9. Firewall blocks of known-benign traffic
  10. Informational/low-severity log noise

Run this script to regenerate the dataset:
    python generate_synthetic_alerts.py

The output is written to data/synthetic_alerts.json.
"""

import json
import random
import os
from datetime import datetime, timedelta

# Seed for reproducibility — same data every time you run it
random.seed(42)

# Base timestamp: alerts span a 6-hour window
BASE_TIME = datetime(2025, 9, 12, 8, 0, 0)

# Counters
alert_counter = 0


def make_alert(
    minutes_offset, source, source_ip, dest_ip, dest_port,
    alert_type, severity, asset_name, raw_message
):
    """Helper to create one alert dict with auto-incrementing ID."""
    global alert_counter
    alert_counter += 1
    # Add a small random jitter (0-120 seconds) so timestamps aren't
    # perfectly aligned — more realistic.
    jitter = random.randint(0, 120)
    timestamp = BASE_TIME + timedelta(minutes=minutes_offset, seconds=jitter)
    return {
        "alert_id": f"ALERT-{alert_counter:04d}",
        "timestamp": timestamp.isoformat(),
        "source": source,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "alert_type": alert_type,
        "severity_reported": severity,
        "asset_name": asset_name,
        "raw_message": raw_message
    }


alerts = []

# =========================================================================
# INCIDENT 1: SSH Brute Force → Successful Login on WEB-SERVER-01
# Attacker: 203.0.113.45 → Target: 10.0.1.50 (WEB-SERVER-01)
# Timeline: 08:05 - 08:35 (30 min window)
# This is a GENUINE THREAT — many failed SSH logins from same IP,
# followed by a successful one. Classic brute-force pattern.
# =========================================================================
attacker_ip_1 = "203.0.113.45"
target_1 = "10.0.1.50"

# 15 failed SSH login attempts over ~20 minutes
for i in range(15):
    alerts.append(make_alert(
        minutes_offset=5 + i * 1.5,
        source="IDS",
        source_ip=attacker_ip_1,
        dest_ip=target_1,
        dest_port=22,
        alert_type="ssh_failed_login",
        severity="medium",
        asset_name="WEB-SERVER-01",
        raw_message=f"Failed SSH login attempt from {attacker_ip_1} to {target_1}:22 "
                    f"- user 'admin' - attempt {i+1} - password authentication failed"
    ))

# The successful login (this is the dangerous one)
alerts.append(make_alert(
    minutes_offset=28,
    source="IDS",
    source_ip=attacker_ip_1,
    dest_ip=target_1,
    dest_port=22,
    alert_type="ssh_successful_login",
    severity="high",
    asset_name="WEB-SERVER-01",
    raw_message=f"Successful SSH login from {attacker_ip_1} to {target_1}:22 "
                f"- user 'admin' - after 15 failed attempts - SUSPICIOUS"
))

# SIEM correlation alert
alerts.append(make_alert(
    minutes_offset=29,
    source="SIEM",
    source_ip=attacker_ip_1,
    dest_ip=target_1,
    dest_port=22,
    alert_type="brute_force_detected",
    severity="critical",
    asset_name="WEB-SERVER-01",
    raw_message=f"SIEM CORRELATION: Brute force attack detected. {attacker_ip_1} made "
                f"15 failed SSH attempts followed by successful login on {target_1} "
                f"(WEB-SERVER-01). Account 'admin' potentially compromised."
))

# Threat intel feed match on the attacker IP
alerts.append(make_alert(
    minutes_offset=30,
    source="ThreatIntel",
    source_ip=attacker_ip_1,
    dest_ip=target_1,
    dest_port=22,
    alert_type="known_malicious_ip",
    severity="high",
    asset_name="WEB-SERVER-01",
    raw_message=f"Threat Intelligence match: IP {attacker_ip_1} is listed in "
                f"abuse.ch blocklist as SSH brute-force botnet node. "
                f"Last seen: 2025-09-10. Country: CN. ASN: AS4134."
))


# =========================================================================
# INCIDENT 2: Port Scan → Web Exploitation Attempt
# Attacker: 198.51.100.23 → Target: 10.0.1.50 (WEB-SERVER-01)
# Timeline: 09:00 - 09:45
# GENUINE THREAT — network recon followed by exploitation attempt
# =========================================================================
attacker_ip_2 = "198.51.100.23"

# Port scan alerts
for port in [21, 22, 80, 443, 3306, 5432, 8080, 8443]:
    alerts.append(make_alert(
        minutes_offset=60 + random.randint(0, 10),
        source="Firewall",
        source_ip=attacker_ip_2,
        dest_ip=target_1,
        dest_port=port,
        alert_type="port_scan",
        severity="low",
        asset_name="WEB-SERVER-01",
        raw_message=f"Firewall: Connection attempt from {attacker_ip_2} to "
                    f"{target_1}:{port} - SYN packet - possible port scan"
    ))

# IDS detects the scan pattern
alerts.append(make_alert(
    minutes_offset=72,
    source="IDS",
    source_ip=attacker_ip_2,
    dest_ip=target_1,
    dest_port=0,
    alert_type="network_scan_detected",
    severity="medium",
    asset_name="WEB-SERVER-01",
    raw_message=f"IDS: Network scan detected from {attacker_ip_2} targeting "
                f"{target_1}. 8 ports probed in 10 minutes. Pattern: sequential SYN scan."
))

# SQL injection attempt on the web server
alerts.append(make_alert(
    minutes_offset=80,
    source="IDS",
    source_ip=attacker_ip_2,
    dest_ip=target_1,
    dest_port=443,
    alert_type="sql_injection_attempt",
    severity="high",
    asset_name="WEB-SERVER-01",
    raw_message=f"IDS: SQL injection attempt detected from {attacker_ip_2} to "
                f"{target_1}:443 - URI: /api/users?id=1' OR '1'='1 - "
                f"WAF signature match: SQLi-001"
))

# Command injection attempt
alerts.append(make_alert(
    minutes_offset=82,
    source="IDS",
    source_ip=attacker_ip_2,
    dest_ip=target_1,
    dest_port=443,
    alert_type="command_injection_attempt",
    severity="critical",
    asset_name="WEB-SERVER-01",
    raw_message=f"IDS: Possible RCE attempt from {attacker_ip_2} to {target_1}:443 - "
                f"URI: /api/export?file=;cat /etc/passwd - "
                f"Signature: CMD-INJECT-002 - CVE-2024-XXXX"
))

# SIEM alert
alerts.append(make_alert(
    minutes_offset=85,
    source="SIEM",
    source_ip=attacker_ip_2,
    dest_ip=target_1,
    dest_port=443,
    alert_type="exploitation_attempt",
    severity="critical",
    asset_name="WEB-SERVER-01",
    raw_message=f"SIEM: Multi-stage attack detected. {attacker_ip_2} performed "
                f"port scan followed by SQLi and command injection attempts on "
                f"WEB-SERVER-01 ({target_1}). Possible exploitation in progress."
))


# =========================================================================
# INCIDENT 3: Phishing → Credential Harvest → Unusual Login on DC-01
# Attacker: 192.0.2.100 (phishing infra) → multiple internal targets
# Timeline: 10:00 - 11:00
# GENUINE THREAT — spearphishing with credential compromise
# =========================================================================
phishing_ip = "192.0.2.100"

# Phishing emails detected by email gateway
for i, target_ws in enumerate(["WORKSTATION-042", "WORKSTATION-087", "WORKSTATION-015"]):
    target_ip_map = {
        "WORKSTATION-042": "10.0.3.42",
        "WORKSTATION-087": "10.0.3.87",
        "WORKSTATION-015": "10.0.3.15"
    }
    alerts.append(make_alert(
        minutes_offset=120 + i * 2,
        source="EmailGateway",
        source_ip=phishing_ip,
        dest_ip=target_ip_map[target_ws],
        dest_port=25,
        alert_type="phishing_email_detected",
        severity="medium",
        asset_name=target_ws,
        raw_message=f"Email Gateway: Suspicious email from external sender "
                    f"security-update@micros0ft-verify.com to user on {target_ws}. "
                    f"Subject: 'Urgent: Verify your account credentials'. "
                    f"Contains link to {phishing_ip}/login.html. "
                    f"SPF: FAIL, DKIM: NONE."
    ))

# One user clicks the link (WORKSTATION-042, finance dept)
alerts.append(make_alert(
    minutes_offset=135,
    source="Proxy",
    source_ip="10.0.3.42",
    dest_ip=phishing_ip,
    dest_port=443,
    alert_type="suspicious_url_access",
    severity="high",
    asset_name="WORKSTATION-042",
    raw_message=f"Web Proxy: User on WORKSTATION-042 (10.0.3.42) accessed "
                f"https://{phishing_ip}/login.html - Category: PHISHING - "
                f"URL reputation: MALICIOUS - User submitted form data."
))

# Credential used from unusual location (the attacker now has the creds)
alerts.append(make_alert(
    minutes_offset=150,
    source="SIEM",
    source_ip="45.33.32.156",
    dest_ip="10.0.2.10",
    dest_port=389,
    alert_type="unusual_login_location",
    severity="critical",
    asset_name="DC-01",
    raw_message=f"SIEM: Unusual login detected on DC-01 (10.0.2.10). "
                f"User 'j.martinez' (Finance) logged in from IP 45.33.32.156 "
                f"(GeoIP: Russia) via LDAP. Normal login location: 10.0.3.42. "
                f"This account was targeted by phishing 30 minutes ago."
))

# AD anomaly - privilege escalation attempt
alerts.append(make_alert(
    minutes_offset=155,
    source="SIEM",
    source_ip="45.33.32.156",
    dest_ip="10.0.2.10",
    dest_port=389,
    alert_type="privilege_escalation_attempt",
    severity="critical",
    asset_name="DC-01",
    raw_message=f"SIEM: Privilege escalation attempt on DC-01. User 'j.martinez' "
                f"(normally a standard user) attempted to add self to "
                f"'Domain Admins' group. Source IP: 45.33.32.156 (Russia). "
                f"Action: BLOCKED by AD policy."
))

# Threat intel on the phishing infrastructure
alerts.append(make_alert(
    minutes_offset=140,
    source="ThreatIntel",
    source_ip=phishing_ip,
    dest_ip="10.0.3.42",
    dest_port=443,
    alert_type="known_phishing_infrastructure",
    severity="high",
    asset_name="WORKSTATION-042",
    raw_message=f"Threat Intel: Domain micros0ft-verify.com (hosted on {phishing_ip}) "
                f"registered 48 hours ago. Registrar: Namecheap. "
                f"SSL cert: Let's Encrypt (free). Matches known phishing kit pattern. "
                f"Related campaigns: APT-PHISH-2025-0912."
))


# =========================================================================
# INCIDENT 4: Lateral Movement + Data Exfiltration
# Compromised internal host 10.0.3.42 → internal servers
# Timeline: 11:30 - 12:30
# GENUINE THREAT — attacker moves internally after phishing compromise
# =========================================================================

# Unusual SMB connections from the compromised workstation
for target, port, asset in [
    ("10.0.2.50", 445, "FILE-SERVER-01"),
    ("10.0.2.100", 5432, "DB-SERVER-01"),
    ("10.0.2.200", 445, "BACKUP-SERVER-01")
]:
    alerts.append(make_alert(
        minutes_offset=210 + random.randint(0, 15),
        source="IDS",
        source_ip="10.0.3.42",
        dest_ip=target,
        dest_port=port,
        alert_type="unusual_internal_connection",
        severity="medium",
        asset_name=asset,
        raw_message=f"IDS: Unusual connection from WORKSTATION-042 (10.0.3.42) to "
                    f"{asset} ({target}:{port}). This workstation has no historical "
                    f"baseline for accessing this server. First-time connection."
    ))

# Large data transfer detected
alerts.append(make_alert(
    minutes_offset=240,
    source="IDS",
    source_ip="10.0.3.42",
    dest_ip="10.0.2.50",
    dest_port=445,
    alert_type="large_data_transfer",
    severity="high",
    asset_name="FILE-SERVER-01",
    raw_message=f"IDS: Anomalous data volume from FILE-SERVER-01 (10.0.2.50) to "
                f"WORKSTATION-042 (10.0.3.42). Transfer size: 2.3 GB in 15 minutes. "
                f"Normal baseline for this workstation: < 50 MB/day."
))

# Outbound exfiltration attempt
alerts.append(make_alert(
    minutes_offset=250,
    source="Firewall",
    source_ip="10.0.3.42",
    dest_ip="104.21.45.67",
    dest_port=443,
    alert_type="suspicious_outbound_transfer",
    severity="critical",
    asset_name="WORKSTATION-042",
    raw_message=f"Firewall: Large outbound HTTPS transfer from WORKSTATION-042 "
                f"(10.0.3.42) to external IP 104.21.45.67 (Cloudflare, unknown "
                f"domain). Transfer size: 1.8 GB. Destination not in approved "
                f"cloud storage list. Potential data exfiltration."
))

# SIEM correlates the lateral movement chain
alerts.append(make_alert(
    minutes_offset=252,
    source="SIEM",
    source_ip="10.0.3.42",
    dest_ip="104.21.45.67",
    dest_port=443,
    alert_type="data_exfiltration_detected",
    severity="critical",
    asset_name="WORKSTATION-042",
    raw_message=f"SIEM CORRELATION: Possible data breach in progress. "
                f"WORKSTATION-042 (compromised via phishing) accessed FILE-SERVER-01, "
                f"DB-SERVER-01, and BACKUP-SERVER-01, then transferred 1.8 GB "
                f"to external IP 104.21.45.67. Kill chain: Initial Access → "
                f"Credential Access → Lateral Movement → Collection → Exfiltration."
))


# =========================================================================
# INCIDENT 5: C2 Beacon Activity
# Compromised WORKSTATION-042 beaconing to C2 server
# Timeline: 12:00 - 14:00 (periodic beacons)
# GENUINE THREAT — regular callbacks to command and control
# =========================================================================
c2_ip = "185.220.101.34"

# Periodic beacons every ~15 minutes
for i in range(8):
    alerts.append(make_alert(
        minutes_offset=240 + i * 15,
        source="IDS",
        source_ip="10.0.3.42",
        dest_ip=c2_ip,
        dest_port=443,
        alert_type="suspicious_beacon",
        severity="medium",
        asset_name="WORKSTATION-042",
        raw_message=f"IDS: Periodic HTTPS connection from WORKSTATION-042 (10.0.3.42) "
                    f"to {c2_ip}:443. Beacon interval: ~15 min ±30s. "
                    f"Packet size: 256 bytes (consistent). JA3 hash: "
                    f"e7d705a3286e19ea42f587b344ee6865. Beacon #{i+1}."
    ))

# Threat intel on C2 IP
alerts.append(make_alert(
    minutes_offset=270,
    source="ThreatIntel",
    source_ip=c2_ip,
    dest_ip="10.0.3.42",
    dest_port=443,
    alert_type="known_c2_server",
    severity="critical",
    asset_name="WORKSTATION-042",
    raw_message=f"Threat Intel: IP {c2_ip} identified as Cobalt Strike C2 server. "
                f"Listed by: AlienVault OTX, Abuse.ch. Associated malware family: "
                f"CobaltStrike 4.9. First seen: 2025-08-15. "
                f"Related threat group: FIN7."
))

# DNS anomaly for C2
alerts.append(make_alert(
    minutes_offset=275,
    source="IDS",
    source_ip="10.0.3.42",
    dest_ip="10.0.2.5",
    dest_port=53,
    alert_type="suspicious_dns_query",
    severity="medium",
    asset_name="DNS-SERVER-01",
    raw_message=f"IDS: Suspicious DNS queries from WORKSTATION-042 (10.0.3.42). "
                f"Querying: c2-relay.darkops.xyz (resolves to {c2_ip}). "
                f"Domain registered 3 days ago. DGA-like subdomain patterns detected."
))


# =========================================================================
# FALSE POSITIVE 1: Vulnerability Scanner Traffic
# Internal scanner 10.0.4.100 → various targets
# Timeline: scattered throughout the day
# FALSE POSITIVE — this is a legitimate Nessus/Qualys scan
# =========================================================================
scanner_ip = "10.0.4.100"

for i, (target, port, asset) in enumerate([
    ("10.0.1.50", 80, "WEB-SERVER-01"),
    ("10.0.1.50", 443, "WEB-SERVER-01"),
    ("10.0.1.50", 22, "WEB-SERVER-01"),
    ("10.0.2.100", 5432, "DB-SERVER-01"),
    ("10.0.2.100", 22, "DB-SERVER-01"),
    ("10.0.2.10", 389, "DC-01"),
    ("10.0.2.10", 636, "DC-01"),
    ("10.0.2.10", 88, "DC-01"),
    ("10.0.1.25", 25, "MAIL-SERVER-01"),
    ("10.0.1.25", 587, "MAIL-SERVER-01"),
    ("10.0.1.25", 143, "MAIL-SERVER-01"),
    ("10.0.2.50", 445, "FILE-SERVER-01"),
    ("10.0.2.50", 139, "FILE-SERVER-01"),
    ("10.0.1.5", 443, "VPN-GATEWAY-01"),
    ("10.0.1.5", 1194, "VPN-GATEWAY-01"),
]):
    alerts.append(make_alert(
        minutes_offset=30 + i * 8 + random.randint(0, 5),
        source="IDS",
        source_ip=scanner_ip,
        dest_ip=target,
        dest_port=port,
        alert_type="vulnerability_scan",
        severity="low",
        asset_name=asset,
        raw_message=f"IDS: Vulnerability scan traffic from {scanner_ip} "
                    f"(authorised scanner) to {asset} ({target}:{port}). "
                    f"Scanner: Nessus Professional. Scan ID: SCHED-WEEKLY-2025-09-12. "
                    f"This is a scheduled scan — likely benign."
    ))

# =========================================================================
# FALSE POSITIVE 2: DNS Query Spikes (Software Updates)
# Various workstations → DNS server
# Timeline: 09:00 - 09:30
# FALSE POSITIVE — Windows Update and antivirus signature downloads
# =========================================================================
for i in range(12):
    ws_ip = f"10.0.3.{random.randint(10, 99)}"
    alerts.append(make_alert(
        minutes_offset=60 + random.randint(0, 30),
        source="IDS",
        source_ip=ws_ip,
        dest_ip="10.0.2.5",
        dest_port=53,
        alert_type="high_dns_query_volume",
        severity="low",
        asset_name="DNS-SERVER-01",
        raw_message=f"IDS: High DNS query volume from {ws_ip}. "
                    f"Queries: windowsupdate.microsoft.com, "
                    f"download.windowsupdate.com, ctldl.windowsupdate.com. "
                    f"Query count: {random.randint(150, 400)} in 5 minutes. "
                    f"Pattern consistent with Windows Update cycle."
    ))


# =========================================================================
# FALSE POSITIVE 3: Single Failed Logins (No Follow-up)
# Various external IPs → various services
# Timeline: scattered
# FALSE POSITIVE — one-off typos, automated scans that don't persist
# =========================================================================
random_external_ips = [
    "91.189.88.142",   # Ubuntu mirrors
    "151.101.1.140",   # Fastly CDN
    "172.217.14.99",   # Google
    "13.107.42.14",    # Microsoft
    "31.13.71.36",     # Facebook
]

for i, ext_ip in enumerate(random_external_ips):
    target_choices = [
        ("10.0.1.50", 22, "WEB-SERVER-01"),
        ("10.0.1.5", 443, "VPN-GATEWAY-01"),
        ("10.0.1.25", 993, "MAIL-SERVER-01"),
    ]
    target, port, asset = random.choice(target_choices)
    alerts.append(make_alert(
        minutes_offset=random.randint(10, 350),
        source="Firewall",
        source_ip=ext_ip,
        dest_ip=target,
        dest_port=port,
        alert_type="single_failed_login",
        severity="low",
        asset_name=asset,
        raw_message=f"Firewall: Single failed authentication from {ext_ip} "
                    f"to {asset} ({target}:{port}). No subsequent attempts. "
                    f"Likely automated probe or misconfigured client."
    ))

# =========================================================================
# FALSE POSITIVE 4: Firewall Blocks of Benign Traffic
# Various sources → various destinations
# Timeline: scattered
# FALSE POSITIVE — normal firewall noise
# =========================================================================
for i in range(20):
    src = f"{random.choice(['10.0.3', '10.0.4'])}.{random.randint(1, 254)}"
    dst_choices = [
        ("10.0.1.10", 3128, "PROXY-01"),
        ("10.0.1.10", 8080, "PROXY-01"),
        ("10.0.2.5", 53, "DNS-SERVER-01"),
    ]
    dst, port, asset = random.choice(dst_choices)
    alerts.append(make_alert(
        minutes_offset=random.randint(0, 360),
        source="Firewall",
        source_ip=src,
        dest_ip=dst,
        dest_port=port,
        alert_type="connection_blocked",
        severity="low",
        asset_name=asset,
        raw_message=f"Firewall: Blocked connection from {src} to {dst}:{port}. "
                    f"Rule: DEFAULT-DENY. Reason: Source not in allowed subnet "
                    f"for this service. Action: DROP. This is routine traffic."
    ))


# =========================================================================
# FALSE POSITIVE 5: Informational Log Noise
# Various internal sources
# Timeline: scattered
# FALSE POSITIVE — normal operational alerts
# =========================================================================
info_messages = [
    ("10.0.2.100", "DB-SERVER-01", "database_backup_completed",
     "DB-SERVER-01: Scheduled PostgreSQL backup completed successfully. "
     "Backup size: 45 GB. Duration: 12 minutes. Next scheduled: 2025-09-13 02:00."),
    ("10.0.2.10", "DC-01", "group_policy_update",
     "DC-01: Group Policy update applied to OU=Workstations. "
     "Policy: Security-Baseline-v2.3. Affected objects: 150. Errors: 0."),
    ("10.0.1.5", "VPN-GATEWAY-01", "vpn_session_expired",
     "VPN-GATEWAY-01: VPN session expired for user 'r.chen'. "
     "Duration: 8 hours. Bytes transferred: 1.2 GB. Reason: timeout."),
    ("10.0.1.25", "MAIL-SERVER-01", "spam_filter_update",
     "MAIL-SERVER-01: Spam filter rules updated. New rules: 342. "
     "Removed: 18. Source: SpamAssassin 4.0. Status: active."),
    ("10.0.2.200", "BACKUP-SERVER-01", "storage_threshold_warning",
     "BACKUP-SERVER-01: Storage utilisation at 78%. Threshold: 80%. "
     "Available: 4.4 TB of 20 TB. Consider archiving old backups."),
    ("10.0.1.50", "WEB-SERVER-01", "ssl_certificate_renewal",
     "WEB-SERVER-01: SSL certificate for app.company.com renewed "
     "successfully via Let's Encrypt. Expires: 2025-12-11."),
    ("10.0.2.5", "DNS-SERVER-01", "dns_zone_transfer",
     "DNS-SERVER-01: Zone transfer completed for company.local. "
     "Records: 2,847. Secondary: 10.0.2.6. Status: SUCCESS."),
    ("10.0.1.10", "PROXY-01", "cache_cleared",
     "PROXY-01: Web proxy cache cleared automatically. "
     "Cache was at 95% capacity. Freed: 12 GB. Performance nominal."),
]

for ip, asset, alert_type, msg in info_messages:
    alerts.append(make_alert(
        minutes_offset=random.randint(0, 360),
        source="SIEM",
        source_ip=ip,
        dest_ip=ip,
        dest_port=0,
        alert_type=alert_type,
        severity="low",
        asset_name=asset,
        raw_message=msg
    ))

# Additional scattered medium-severity alerts that are false positives
# (antivirus detections on test files, etc.)
fp_medium = [
    ("10.0.3.87", "WORKSTATION-087", "antivirus_detection",
     "Antivirus: Detected EICAR test file on WORKSTATION-087. "
     "File: C:\\Users\\test\\Downloads\\eicar.com. Action: quarantined. "
     "This is a test file, not actual malware."),
    ("10.0.3.15", "WORKSTATION-015", "usb_device_connected",
     "Endpoint Agent: USB mass storage device connected on WORKSTATION-015. "
     "Device: SanDisk Ultra 64GB. User: p.johnson (HR). "
     "Policy: ALERT-ONLY (not blocked)."),
    ("10.0.3.42", "WORKSTATION-042", "software_installation",
     "Endpoint Agent: New software installed on WORKSTATION-042. "
     "Software: 7-Zip 23.01. Installer hash: a4b3c2d1... (clean). "
     "User: j.martinez (Finance). Source: approved repository."),
]

for ip, asset, alert_type, msg in fp_medium:
    alerts.append(make_alert(
        minutes_offset=random.randint(30, 300),
        source="SIEM",
        source_ip=ip,
        dest_ip=ip,
        dest_port=0,
        alert_type=alert_type,
        severity="medium",
        asset_name=asset,
        raw_message=msg
    ))


# =========================================================================
# Extra noise: more scattered low-severity alerts to bulk up the dataset
# =========================================================================
noise_types = [
    ("connection_timeout", "low", "Firewall: Connection timeout"),
    ("icmp_echo_request", "low", "IDS: ICMP echo request"),
    ("service_restart", "low", "SIEM: Service automatically restarted"),
    ("certificate_warning", "low", "IDS: Weak cipher suite negotiated"),
    ("config_change", "low", "SIEM: Configuration change detected"),
]

for i in range(30):
    alert_type, sev, base_msg = random.choice(noise_types)
    src = f"10.0.{random.randint(1,4)}.{random.randint(1,254)}"
    dst = f"10.0.{random.randint(1,4)}.{random.randint(1,254)}"
    asset_names = [
        "WEB-SERVER-01", "DB-SERVER-01", "MAIL-SERVER-01", "DC-01",
        "FILE-SERVER-01", "VPN-GATEWAY-01", "DNS-SERVER-01", "PROXY-01",
        "WORKSTATION-042", "WORKSTATION-087", "WORKSTATION-015",
        "BACKUP-SERVER-01"
    ]
    asset = random.choice(asset_names)
    alerts.append(make_alert(
        minutes_offset=random.randint(0, 360),
        source=random.choice(["Firewall", "IDS", "SIEM"]),
        source_ip=src,
        dest_ip=dst,
        dest_port=random.choice([0, 22, 80, 443, 53, 445, 3389]),
        alert_type=alert_type,
        severity=sev,
        asset_name=asset,
        raw_message=f"{base_msg} - src: {src} dst: {dst} - asset: {asset} - "
                    f"event #{i+1} - routine operational alert"
    ))


# Sort all alerts by timestamp (chronological order)
alerts.sort(key=lambda a: a["timestamp"])

# Re-assign sequential alert IDs after sorting
for i, alert in enumerate(alerts):
    alert["alert_id"] = f"ALERT-{i+1:04d}"

# Write to JSON file
output_path = os.path.join(os.path.dirname(__file__), "data", "synthetic_alerts.json")
os.makedirs(os.path.dirname(output_path), exist_ok=True)

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(alerts, f, indent=2, ensure_ascii=False)

print(f"Generated {len(alerts)} synthetic alerts -> {output_path}")
print(f"\nBreakdown:")
print(f"  Incident 1 (SSH Brute Force):    18 alerts")
print(f"  Incident 2 (Port Scan + Exploit): 12 alerts")
print(f"  Incident 3 (Phishing Chain):      7 alerts")
print(f"  Incident 4 (Lateral + Exfil):     6 alerts")
print(f"  Incident 5 (C2 Beacons):         10 alerts")
print(f"  False Positives + Noise:         {len(alerts) - 53} alerts")
print(f"  TOTAL:                           {len(alerts)} alerts")
