import json

def parse_alert(alert_data):
    """Parse NewExternalClientConn alert details (outbound connections)"""
    
    connection_info = {
        "source": {
            "hosts": set(),      # Internal hosts making connections
            "applications": set(),
            "pods": set(),
            "ips": set(),        # Internal source IPs
            "users": set()
        },
        "destination": {
            "hosts": set(),      # External destination hosts
            "applications": set(),
            "pods": set(),
            "ips": set(),        # External destination IPs
            "users": set(),
            "ports": set()       # Destination ports
        }
    }
    
    # Get all Machine entities (source machines)
    for machine in alert_data.get("entityMap", {}).get("Machine", []):
        if "PROPS" in machine:
            hostname = machine["PROPS"].get("hostname")
            internal_ip = machine["PROPS"].get("internal_ip_addr")
            user = machine["PROPS"].get("user")
            
            if hostname and internal_ip:
                connection_info["source"]["hosts"].add(hostname)
                connection_info["source"]["ips"].add(internal_ip)
                if user:
                    connection_info["source"]["users"].add(user)

    # Get all Container/Pod information (source containers)
    for container in alert_data.get("entityMap", {}).get("Container", []):
        if "PROPS" in container:
            pod_name = container["PROPS"].get("pod_name")
            image_name = container["PROPS"].get("image_name")
            ip_addr = container["PROPS"].get("ip_addr")
            
            if pod_name:
                connection_info["source"]["pods"].add(pod_name)
            if image_name:
                connection_info["source"]["applications"].add(image_name)
            if ip_addr:
                connection_info["source"]["ips"].add(ip_addr)

    # Get external destination IPs and ports
    for ip_entry in alert_data.get("entityMap", {}).get("IpAddress", []):
        if "PROPS" in ip_entry:
            ip = ip_entry["KEY"].get("ip_addr")
            ports = ip_entry["PROPS"].get("port_list", [])
            location = ip_entry["PROPS"].get("location", {})
            
            # If IP is not in our source IPs, it's external
            if ip not in connection_info["source"]["ips"]:
                connection_info["destination"]["ips"].add(ip)
                connection_info["destination"]["ports"].update(map(str, ports))

    return {
        "alert_id": alert_data.get("alertId"),
        "alert_type": "NewExternalClientConn",
        "severity": alert_data.get("severity"),
        "time": alert_data.get("startTime"),
        "connection": {
            "source": {
                "hosts": sorted(list(connection_info["source"]["hosts"])),
                "applications": sorted(list(connection_info["source"]["applications"])),
                "pods": sorted(list(connection_info["source"]["pods"])),
                "ips": sorted(list(connection_info["source"]["ips"])),
                "users": sorted(list(connection_info["source"]["users"]))
            },
            "destination": {
                "hosts": sorted(list(connection_info["destination"]["hosts"])),
                "applications": sorted(list(connection_info["destination"]["applications"])),
                "pods": sorted(list(connection_info["destination"]["pods"])),
                "ips": sorted(list(connection_info["destination"]["ips"])),
                "users": sorted(list(connection_info["destination"]["users"])),
                "ports": sorted(list(connection_info["destination"]["ports"]))
            }
        }
    } 