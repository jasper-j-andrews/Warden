from warden.models import SecurityEvent, RiskAssessement

def get_severity(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"

def analyze_event(event: SecurityEvent) -> RiskAssessement:
    score = 0
    reasons = []
    rule_ids = []
    actions = []

    # Rule 1: Brute force detection

    if event.event_type == "failed_login":
        score += (2.5 * event.event_count)
        reasons.append(f"{event.event_count} failed login attempts detected.")
        rule_ids.append("AUTH-001")
        actions.append("Investigate the source IP and authentication history.")
    
    # Rule 2: Privileged account targeting

    if event.username in {"admin", "root", "administrator"}:
        score += 15
        reasons.append(f"Privileged account targeted: {event.username}")
        rule_ids.append("AUTH-003")
        actions.append("Review the targeted account's recent activity.")

    # Rule 3: Potential port scanning
    if event.event_type == "port_scan":
        score += 35
        reasons.append("Multiple connection attempts suggest possible port scanning.")
        rule_ids.append("NET-001")
        actions.append("Inspect network traffic and determine which ports were targeted.")
    
    severity = get_severity(score)
    if not reasons:
        reasons.append("No suspicious behavior matched the configured detection rules.")
    return RiskAssessement(event_id=event.event_id, risk_score=score, severity=severity,reasons=reasons, rule_ids=rule_ids, recommended_actions=actions)
