import json

def format_alert_json(alert_data):
    """Format alert data as JSON"""
    return json.dumps(alert_data, indent=2) 