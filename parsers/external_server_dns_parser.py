import json

def parse_alert(alert_data):
    """Parse NewExternalServerDns and NewExternalServerDNSConn alerts (DNS-based inbound)"""
    
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
            "containers": {},
            "dns_names": set()  # DNS names for source
        },
        "destination": {
            "hosts": set(),
            "applications": set(),
            "pods": set(),
            "ips": set(),
            "users": set(),
            "ports": set(),
            "containers": {},
            "dns_names": set()  # DNS names for destination
        }
    }

    # Process DNS information
    for dns_entry in alert_data.get("entityMap", {}).get("DnsName", []):
        if "PROPS" in dns_entry:
            dns_name = dns_entry["PROPS"].get("dns_name")
            resolved_ips = dns_entry["PROPS"].get("resolved_ips", [])
            
            if dns_name:
                connection_info["source"]["dns_names"].add(dns_name)
                connection_info["source"]["ips"].update(resolved_ips)

    # Get source information from Machine entities
    for machine in alert_data.get("entityMap", {}).get("Machine", []):
        if "PROPS" in machine:
            hostname = machine["PROPS"].get("hostname")
            internal_ip = machine["PROPS"].get("internal_ip_addr")
            user = machine["PROPS"].get("user")
            
            if hostname and internal_ip:
                connection_info["destination"]["hosts"].add(hostname)
                connection_info["destination"]["ips"].add(internal_ip)
                if user:
                    connection_info["destination"]["users"].add(user)

    # Get container/pod information
    for container in alert_data.get("entityMap", {}).get("Container", []):
        if "PROPS" in container:
            pod_name = container["PROPS"].get("pod_name")
            image_name = container["PROPS"].get("image_name")
            ip_addr = container["PROPS"].get("ip_addr")
            
            if ip_addr:
                connection_info["destination"]["ips"].add(ip_addr)
                if ip_addr in ip_mapping:
                    connection_info["destination"]["containers"][ip_addr] = ip_mapping[ip_addr]
                    if pod_name:
                        connection_info["destination"]["pods"].add(pod_name)
                    if image_name:
                        connection_info["destination"]["applications"].add(image_name)

    # Get destination ports from IpAddress entities
    for ip_entry in alert_data.get("entityMap", {}).get("IpAddress", []):
        if "PROPS" in ip_entry:
            ip = ip_entry["KEY"].get("ip_addr")
            ports = ip_entry["PROPS"].get("port_list", [])
            
            if ip in connection_info["destination"]["ips"]:
                connection_info["destination"]["ports"].update(map(str, ports))

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
                "containers": connection_info["source"]["containers"],
                "dns_names": sorted(list(connection_info["source"]["dns_names"]))
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