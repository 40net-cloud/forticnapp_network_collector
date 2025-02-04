import json

def parse_alert(alert_data):
    """Parse NewInternalConnection alert details for complete policy information"""
    
    # First build IP to container/pod mapping
    ip_mapping = {}
    for container in alert_data.get("entityMap", {}).get("Container", []):
        if "PROPS" in container:
            ip = container["PROPS"].get("ip_addr")
            if ip:
                ip_mapping[ip] = {
                    "pod_name": container["PROPS"].get("pod_name"),
                    "container_name": container["PROPS"].get("container_name"),
                    "image_name": container["PROPS"].get("image_name"),
                    "namespace": container["PROPS"].get("namespace")
                }

    connection_info = {
        "source": {
            "hosts": set(),
            "applications": set(),
            "pods": set(),
            "ips": set(),
            "users": set(),
            "containers": {}  # IP -> container details mapping
        },
        "destination": {
            "hosts": set(),
            "applications": set(),
            "pods": set(),
            "ips": set(),
            "users": set(),
            "ports": set(),
            "containers": {}  # IP -> container details mapping
        }
    }
    
    description = alert_data.get("alertInfo", {}).get("description", "")
    
    # First identify source and destination applications from description
    source_app = None
    dest_app = None
    if "Application" in description:
        parts = description.split("connected to")
        if len(parts) == 2:
            source_part = parts[0]
            dest_part = parts[1]
            if "Application" in source_part:
                source_app = source_part.split("Application")[1].split("running")[0].strip()
            if "application" in dest_part:
                dest_app = dest_part.split("application")[1].split("listening")[0].strip()
    
    # Get all Machine entities
    for machine in alert_data.get("entityMap", {}).get("Machine", []):
        if "PROPS" in machine:
            hostname = machine["PROPS"].get("hostname")
            internal_ip = machine["PROPS"].get("internal_ip_addr")
            user = machine["PROPS"].get("user")
            
            if hostname and internal_ip:
                # Match against source/dest apps to determine direction
                if any(app in machine.get("PROPS", {}).get("cmdline", "") for app in [source_app] if app):
                    connection_info["source"]["hosts"].add(hostname)
                    connection_info["source"]["ips"].add(internal_ip)
                    if user:
                        connection_info["source"]["users"].add(user)
                else:
                    connection_info["destination"]["hosts"].add(hostname)
                    connection_info["destination"]["ips"].add(internal_ip)
                    if user:
                        connection_info["destination"]["users"].add(user)
    
    # Get all Container/Pod information
    for container in alert_data.get("entityMap", {}).get("Container", []):
        if "PROPS" in container:
            pod_name = container["PROPS"].get("pod_name")
            image_name = container["PROPS"].get("image_name")
            ip_addr = container["PROPS"].get("ip_addr")
            
            if image_name == source_app:
                if pod_name:
                    connection_info["source"]["pods"].add(pod_name)
                if image_name:
                    connection_info["source"]["applications"].add(image_name)
                if ip_addr:
                    connection_info["source"]["ips"].add(ip_addr)
            else:
                if pod_name:
                    connection_info["destination"]["pods"].add(pod_name)
                if image_name:
                    connection_info["destination"]["applications"].add(image_name)
                if ip_addr:
                    connection_info["destination"]["ips"].add(ip_addr)
    
    # Parse description for ports
    if "TCP port" in description:
        port_part = description.split("TCP port")[1].split("running")[0].strip()
        # Handle format "High Ports (5000)"
        if "(" in port_part:
            port = port_part.split("(")[1].split(")")[0].strip()
            connection_info["destination"]["ports"].add(port)
        # Handle format "HTTPS(443)"
        elif "HTTPS" in port_part:
            port = port_part.split("(")[1].split(")")[0].strip()
            connection_info["destination"]["ports"].add(port)
        # Handle plain port numbers
        else:
            port = port_part.strip()
            connection_info["destination"]["ports"].add(port)

    # Get all IP addresses and ports
    for ip_entry in alert_data.get("entityMap", {}).get("IpAddress", []):
        if "PROPS" in ip_entry:
            ip = ip_entry["KEY"].get("ip_addr")
            ports = ip_entry["PROPS"].get("port_list", [])
            
            # If this IP belongs to a container, get its details
            container_info = ip_mapping.get(ip)
            
            if ip in connection_info["source"]["ips"]:
                if container_info:
                    connection_info["source"]["containers"][ip] = container_info
                    connection_info["source"]["pods"].add(container_info["pod_name"])
                    connection_info["source"]["applications"].add(container_info["image_name"])
            else:
                if container_info:
                    connection_info["destination"]["containers"][ip] = container_info
                    connection_info["destination"]["pods"].add(container_info["pod_name"])
                    connection_info["destination"]["applications"].add(container_info["image_name"])
                connection_info["destination"]["ports"].update(map(str, ports))

    return {
        "alert_id": alert_data.get("alertId"),
        "alert_type": "NewInternalConnection",
        "severity": alert_data.get("severity"),
        "time": alert_data.get("startTime"),
        "connection": {
            "source": {
                "hosts": sorted(list(connection_info["source"]["hosts"])),
                "applications": sorted(list(connection_info["source"]["applications"])),
                "pods": sorted(list(connection_info["source"]["pods"])),
                "ips": sorted(list(connection_info["source"]["ips"])),
                "users": sorted(list(connection_info["source"]["users"])),
                "containers": connection_info["source"]["containers"]  # IP -> container details
            },
            "destination": {
                "hosts": sorted(list(connection_info["destination"]["hosts"])),
                "applications": sorted(list(connection_info["destination"]["applications"])),
                "pods": sorted(list(connection_info["destination"]["pods"])),
                "ips": sorted(list(connection_info["destination"]["ips"])),
                "users": sorted(list(connection_info["destination"]["users"])),
                "ports": sorted(list(connection_info["destination"]["ports"])),
                "containers": connection_info["destination"]["containers"]  # IP -> container details
            }
        }
    } 