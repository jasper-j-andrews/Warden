import argparse
from warden.ingestion import load_events
from warden.rules import analyze_event

def main():
    parser = argparse.ArgumentParser(description="WardenAI security event analyzer")
    parser.add_argument("--input", default="data/sample_alerts.jsonl", help="Path to JSONL security event file")
    args = parser.parse_args()

    # Ingest events
    events = load_events(args.input)
    print(f"Loaded {len(events)} security events.\n")

    # Analyze events
    assessements = [analyze_event(event) for event in events]

    # Display results
    assessements.sort(key=lambda x: x.risk_score, reverse=True)

    for assessement in assessements:
        print("=" * 50)
        print(f"Event ID: {assessement.event_id}")
        print(f"Risk Score: {assessement.risk_score}")
        print(f"Severity: {assessement.severity}")
        print("\nReasons:")
        for reason in assessement.reasons:
            print(f" - {reason}")
        print("\nTriggered Rules")
        for rule in assessement.rule_ids:
            print(f" - {rule}")
        for action in assessement.recommended_actions:
            print(f" - {action}")

if __name__ == "__main__":
    main()