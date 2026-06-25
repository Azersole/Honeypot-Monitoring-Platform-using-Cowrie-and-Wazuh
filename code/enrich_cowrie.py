#!/usr/bin/env python3
import json
import sys
import requests
import os
from datetime import datetime
import ipaddress

ABUSEIPDB_KEY = "ABUSEIPDB_KEY"
VIRUSTOTAL_KEY = "VIRUSTOTAL_KEY"
DISCORD_WEBHOOK = "DISCORD_WEBHOOK_URL"

def query_abuseipdb(ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        d = r.json().get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode", "unknown"),
            "isp": d.get("isp", "unknown"),
            "total_reports": d.get("totalReports", 0)
        }
    except:
        return {}

def query_virustotal(ip):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10
        )
        stats = r.json().get("data", {}).get(
            "attributes", {}).get(
            "last_analysis_stats", {})
        return {
            "vt_malicious": stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_harmless": stats.get("harmless", 0)
        }
    except:
        return {}

def send_discord(alert, abuse, vt):

    ip = str(alert.get("src_ip", "unknown")) or "unknown"
    event = str(alert.get("eventid", "unknown")) or "unknown"
    username = str(alert.get("username", "unknown")) or "unknown"
    password = str(alert.get("password", "unknown")) or "unknown"

    country = abuse.get("country")
    isp = abuse.get("isp")

    score = int(abuse.get("abuse_score", 0))
    reports = int(abuse.get("total_reports", 0))
    vt_bad = int(vt.get("vt_malicious", 0))

# Handle private IP addresses

    try:
        if ipaddress.ip_address(ip).is_private:
            country = "Internal/Lab Network"
            isp = "Private Address"
            score = 0
            reports = 0
            vt_bad = 0
    except:
        pass

# Fallback values
    country = country or "Unknown"
    isp = isp or "Unknown"

    if score > 50 or vt_bad > 3:
        color = 16711680
        risk = "HIGH RISK"
    elif score > 20:
        color = 16744272
        risk = "MEDIUM RISK"
    else:
        color = 3066993
        risk = "LOW RISK"

    payload = {
        "username": "Honeypot Alert",
        "embeds": [{
            "title": f"Honeypot Hit — {risk}",
            "color": color,
            "fields": [
                {"name": "Event", "value": event or "unknown", "inline": True},
                {"name": "Source IP", "value": ip or "unknown", "inline": True},
                {"name": "Country", "value": country or "unknown", "inline": True},
                {"name": "ISP", "value": isp or "unknown", "inline": True},
                {"name": "Username Tried", "value": username or "unknown", "inline": True},
                {"name": "Password Tried", "value": password or "unknown", "inline": True},
                {"name": "Abuse Score", "value": str(score), "inline": True},
                {"name": "Total Reports", "value": str(reports), "inline": True},
                {"name": "VT Malicious", "value": str(vt_bad), "inline": True}
            ],
            "footer": {
                "text": f"Wazuh Honeypot Monitor — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
            }
        }]
    }

    try:
        r = requests.post(DISCORD_WEBHOOK,
                          json=payload,
                          timeout=10)

        with open("/tmp/discord_debug.log", "a") as f:
            f.write(f"Discord status: {r.status_code}\n")
            f.write(f"Discord response: {r.text}\n")

    except Exception as e:
        with open("/tmp/discord_debug.log", "a") as f:
            f.write(str(e) + "\n")

def main():
    alert_file = sys.argv[1]
    with open(alert_file) as f:
        alert = json.load(f)

    data = alert.get("data", {})
    src_ip = data.get("src_ip", "")

    if not src_ip:
        sys.exit(0)

    private = ["10.", "192.168.", "172.16.", "127."]
    if any(src_ip.startswith(p) for p in private):
        sys.exit(0)

    abuse = query_abuseipdb(src_ip)
    vt = query_virustotal(src_ip)
    send_discord(data, abuse, vt)

    enriched = {**alert, "abuse_intel": abuse, "virustotal": vt}
    with open("/var/ossec/logs/cowrie_enriched.json", "a") as f:
        f.write(json.dumps(enriched) + "\n")

if __name__ == "__main__":
    main()