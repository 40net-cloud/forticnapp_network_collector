import json

def parse_alert(alert_data):
    """Parse NewExternalClientIp alert details (outbound connections from specific IPs)"""
    
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
            "hosts": set(),      # Internal hosts making connections
            "applications": set(),
            "pods": set(),
            "ips": set(),        # Internal source IPs
            "users": set(),
            "containers": {}     # IP -> container details mapping
        },
        "destination": {
            "hosts": set(),      # External destination hosts
            "applications": set(),
            "pods": set(),
            "ips": set(),        # External destination IPs
            "users": set(),
            "ports": set(),      # Destination ports
            "location": {},      # Geographical location info
            "domain": set(),     # Domain names if available
            "cloud_provider": set()  # Cloud provider info if available
        }
    }
    
    # Get source information from Machine entities
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

    # Get container/pod information
    for container in alert_data.get("entityMap", {}).get("Container", []):
        if "PROPS" in container:
            pod_name = container["PROPS"].get("pod_name")
            image_name = container["PROPS"].get("image_name")
            ip_addr = container["PROPS"].get("ip_addr")
            
            if ip_addr:
                connection_info["source"]["ips"].add(ip_addr)
                if ip_addr in ip_mapping:
                    connection_info["source"]["containers"][ip_addr] = ip_mapping[ip_addr]
                    if pod_name:
                        connection_info["source"]["pods"].add(pod_name)
                    if image_name:
                        connection_info["source"]["applications"].add(image_name)

    # Get destination information from IpAddress entities
    for ip_entry in alert_data.get("entityMap", {}).get("IpAddress", []):
        if "PROPS" in ip_entry:
            ip = ip_entry["KEY"].get("ip_addr")
            ports = ip_entry["PROPS"].get("port_list", [])
            location = ip_entry["PROPS"].get("location", {})
            domain = ip_entry["PROPS"].get("domain_name")
            cloud_provider = ip_entry["PROPS"].get("cloud_provider")
            
            # If IP is not in our source IPs, it's external
            if ip not in connection_info["source"]["ips"]:
                connection_info["destination"]["ips"].add(ip)
                connection_info["destination"]["ports"].update(map(str, ports))
                if location:
                    connection_info["destination"]["location"][ip] = location
                if domain:
                    connection_info["destination"]["domain"].add(domain)
                if cloud_provider:
                    connection_info["destination"]["cloud_provider"].add(cloud_provider)

    return {
        "alert_id": alert_data.get("alertId"),
        "alert_type": "NewExternalClientIp",
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
                "location": connection_info["destination"]["location"],
                "domain": sorted(list(connection_info["destination"]["domain"])),
                "cloud_provider": sorted(list(connection_info["destination"]["cloud_provider"]))
            }
        }
    } 