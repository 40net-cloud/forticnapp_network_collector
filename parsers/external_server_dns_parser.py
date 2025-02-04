import json

def parse_alert(alert_data):
    """Parse NewExternalServerDns and NewExternalServerDNSConn alerts (DNS-based outbound)"""
    
    # Initialize connection info
    connection_info = {
        "source": {
            "hosts": set(),
            "applications": set(),
            "pods": set(),
            "ips": set(),
            "users": set(),
            "containers": {}
        },
        "destination": {
            "hosts": set(),
            "applications": set(),
            "pods": set(),
            "ips": set(),
            "users": set(),
            "ports": set(),
            "containers": {},
            "dns_names": set()
        }
    }

    # Parse description for additional context
    description = alert_data.get("alertInfo", {}).get("description", "")
    
    # Extract application and user from description
    if "Application" in description:
        parts = description.split("running on host")
        if len(parts) > 0:
            app_part = parts[0].split("Application")[1].strip()
            connection_info["source"]["applications"].add(app_part.strip())
            
        # Extract user
        if "as user" in description:
            user = description.split("as user")[1].split("made")[0].strip()
            connection_info["source"]["users"].add(user)
            
        # Extract DNS name
        if "connection to" in description:
            dns_part = description.split("connection to")[1].split("at TCP port")[0].strip()
            connection_info["destination"]["dns_names"].add(dns_part)
            
        # Extract port
        if "TCP port" in description:
            port_part = description.split("TCP port")[1].split(".")[0].strip()
            # Handle format "HTTPS(443)"
            if "(" in port_part:
                port = port_part.split("(")[1].split(")")[0].strip()
                connection_info["destination"]["ports"].add(port)
            # Handle named ports
            elif "HTTP" in port_part:
                connection_info["destination"]["ports"].add("80")
            elif "HTTPS" in port_part:
                connection_info["destination"]["ports"].add("443")
            # Handle plain port numbers
            else:
                port = port_part.strip()
                connection_info["destination"]["ports"].add(port)

    # Get machine information
    for machine in alert_data.get("entityMap", {}).get("Machine", []):
        if "PROPS" in machine:
            hostname = machine["PROPS"].get("hostname")
            internal_ip = machine["PROPS"].get("internal_ip_addr")
            
            if hostname and internal_ip:
                connection_info["source"]["hosts"].add(hostname)
                connection_info["source"]["ips"].add(internal_ip)

    return {
        "alert_id": alert_data.get("alertId"),
        "alert_type": alert_data.get("alertType"),
        "severity": alert_data.get("severity"),
        "time": alert_data.get("startTime"),
        "connection": {
            "source": {
                "hosts": sorted(list(connection_info["source"]["hosts"])),
                "applications": sorted(list(connection_info["source"]["applications"])),
                "pods": sorted(list(connection_info["source"]["pods"])),
                "ips": sorted(list(connection_info["source"]["ips"])),
                "users": sorted(list(connection_info["source"]["users"])),
                "containers": connection_info["source"]["containers"]
            },
            "destination": {
                "hosts": sorted(list(connection_info["destination"]["hosts"])),
                "applications": sorted(list(connection_info["destination"]["applications"])),
                "pods": sorted(list(connection_info["destination"]["pods"])),
                "ips": sorted(list(connection_info["destination"]["ips"])),
                "users": sorted(list(connection_info["destination"]["users"])),
                "ports": sorted(list(connection_info["destination"]["ports"])),
                "containers": connection_info["destination"]["containers"],
                "dns_names": sorted(list(connection_info["destination"]["dns_names"]))
            }
        }
    } 