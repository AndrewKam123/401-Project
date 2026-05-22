import json

def load_alerts():
    with open("data/alerts.json", "r") as f:
        return json.load(f)

def load_nessus():
    return {
        "10.0.0.5": {"cvss": 9.8},
        "10.0.0.8": {"cvss": 5.0}
    }

def extract_features(alert, nessus):
    return {
        "severity": alert["severity"],
        "cvss": nessus.get(alert["dest_ip"], {}).get("cvss", 0),
        "is_ssh": 1 if alert["port"] == 22 else 0
    }

def prioritize(features):
    score = features["severity"] + (features["cvss"] / 3)

    if score > 8:
        return "CRITICAL"
    elif score > 5:
        return "HIGH"
    elif score > 3:
        return "MEDIUM"
    return "LOW"

def root_cause(alert):
    alert_type = alert["alert_type"]
    if "Brute Force" in alert_type:
        return "Repeated login attempts"
    if "Port Scan" in alert_type:
        return "Recon activity"
    if "SQL Injection" in alert_type:
        return "Malicious SQL query detected"
    if "SSL Certificate" in alert_type:
        return "Invalid or expired SSL certificate"
    if "Unauthorized Access" in alert_type:
        return "Credentials or permissions violation"
    if "Suspicious Activity" in alert_type:
        return "Anomalous behavior detected"
    if "Spam Detection" in alert_type:
        return "Unsolicited bulk email"
    if "DNS Tunneling" in alert_type:
        return "Potential data exfiltration via DNS"
    if "SMB Exploit" in alert_type:
        return "Vulnerability exploitation attempt"
    if "Elasticsearch" in alert_type:
        return "Exposed database service"
    if "Redis" in alert_type:
        return "Exposed cache service"
    if "Command Injection" in alert_type:
        return "Arbitrary command execution attempt"
    if "MongoDB" in alert_type:
        return "Exposed NoSQL database"
    return "Unknown"

def recommend(alert):
    alert_type = alert["alert_type"]
    if "Brute Force" in alert_type:
        return ["Check logs", "Block IP", "Enable lockout"]
    if "Port Scan" in alert_type:
        return ["Check firewall", "Block IP"]
    if "SQL Injection" in alert_type:
        return ["Patch application", "Review input validation", "Block IP"]
    if "SSL Certificate" in alert_type:
        return ["Renew certificate", "Update servers", "Alert users"]
    if "Unauthorized Access" in alert_type:
        return ["Revoke credentials", "Reset password", "Block IP"]
    if "Suspicious Activity" in alert_type:
        return ["Review logs", "Isolate system", "Investigate"]
    if "Spam Detection" in alert_type:
        return ["Block sender", "Review email gateway"]
    if "DNS Tunneling" in alert_type:
        return ["Block IP", "Review DNS logs", "Isolate host"]
    if "SMB Exploit" in alert_type:
        return ["Patch system", "Block IP", "Isolate network"]
    if "Elasticsearch" in alert_type:
        return ["Restrict access", "Enable authentication", "Move behind firewall"]
    if "Redis" in alert_type:
        return ["Restrict access", "Enable password", "Move behind firewall"]
    if "Command Injection" in alert_type:
        return ["Patch application", "Block IP", "Review parameters"]
    if "MongoDB" in alert_type:
        return ["Restrict access", "Enable authentication", "Move behind firewall"]
    return ["Investigate"]

def main():
    alerts = load_alerts()
    nessus = load_nessus()

    for alert in alerts:
        features = extract_features(alert, nessus)
        priority = prioritize(features)
        cause = root_cause(alert)
        actions = recommend(alert)

        print("\n--- ALERT ---")
        print("Priority:", priority)
        print("Cause:", cause)
        print("Actions:", actions)

if __name__ == "__main__":
    main()