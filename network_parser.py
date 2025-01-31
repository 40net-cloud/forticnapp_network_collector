import requests
import json
from datetime import datetime, timedelta, UTC
import os
import logging
from pprint import pprint, pformat
import time
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from parsers import external_server_ip_parser, external_client_conn_parser, internal_connection_parser, utils

# Enhanced logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global configuration
CONFIG = {
    'DEFAULT_LOOKBACK_HOURS': 24,     # Default hours to look back
    'REQUESTS_PER_SECOND': 2,        # API rate limit
    'MAX_RETRIES': 3,                # Maximum retry attempts
    'TOKEN_EXPIRY_BUFFER': 300,      # Buffer time in seconds before token expiry
    'DEFAULT_ALERT_TYPES': [
        "NewExternalServerIp",       # Inbound connections
        "NewExternalClientConn",     # Outbound connections
        "NewInternalConnection"      # Internal connections
    ]
}

class LaceworkAPI:
    def __init__(self, config_file=None, lookback_hours=None):
        """
        Initialize with either a config file or environment variables
        
        Args:
            config_file (str): Path to config file
            lookback_hours (int): Override default lookback period
        """
        # Set lookback period
        self.lookback_hours = lookback_hours or CONFIG['DEFAULT_LOOKBACK_HOURS']
        
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                self.account = config['account']  # Remove the .split('.')[0]
                self.access_key_id = config['keyId']
                self.secret_key = config['secret']
                logger.info(f"Successfully loaded config from {config_file}")
            except Exception as e:
                logger.error(f"Error reading config file: {str(e)}")
                raise
        else:
            # Fallback to environment variables
            self.account = os.environ.get('LW_ACCOUNT')
            self.access_key_id = os.environ.get('LW_ACCESS_KEY_ID')
            self.secret_key = os.environ.get('LW_SECRET_KEY')
        
        if not all([self.account, self.access_key_id, self.secret_key]):
            raise ValueError("Missing required Lacework credentials")
            
        self.base_url = f"https://{self.account}/api/v2"
        self.token = None
        self.token_expiry = None
        logger.info(f"Initialized Lacework API client for account: {self.account}")
        
        # Configure retry strategy
        self.retry_strategy = Retry(
            total=CONFIG['MAX_RETRIES'],  # number of retries
            backoff_factor=1,  # wait 1, 2, 4 seconds between retries
            status_forcelist=[429, 500, 502, 503, 504]  # HTTP status codes to retry on
        )
        self.adapter = HTTPAdapter(max_retries=self.retry_strategy)
        self.session = requests.Session()
        self.session.mount("https://", self.adapter)
        
        # Rate limiting
        self.requests_per_second = CONFIG['REQUESTS_PER_SECOND']
        self.last_request_time = 0

    def _log_response(self, method, url, response, params=None):
        """Log API response details only for errors"""
        if response is None:
            logger.error(f"API Error - {method} {url} - No response received")
            return
            
        if response.status_code >= 400:
            logger.error(f"API Error - {method} {url}")
            logger.error(f"Status Code: {response.status_code}")
            logger.error(f"Response: {response.text}")

    def _get_token(self):
        """Get a new access token from Lacework"""
        try:
            auth_url = f"https://{self.account}/api/v2/access/tokens"
            auth_data = {
                "keyId": self.access_key_id,
                "expiryTime": 3600
            }
            headers = {
                "X-LW-UAKS": self.secret_key,
                "Content-Type": "application/json"
            }
            
            # Debug logging
            logger.info("Token request details:")
            logger.info(f"URL: {auth_url}")
            logger.info(f"Headers: {headers}")
            logger.info(f"Data: {auth_data}")
            
            response = requests.post(
                auth_url,
                json=auth_data,
                headers=headers
            )
            
            if response.status_code != 200:
                logger.error(f"Token request failed: {response.text}")
                logger.error(f"Response headers: {dict(response.headers)}")
            
            response.raise_for_status()
            
            token_data = response.json()
            self.token = token_data["token"]
            # Set token expiry 5 minutes before actual expiry
            self.token_expiry = datetime.now(UTC) + timedelta(seconds=CONFIG['TOKEN_EXPIRY_BUFFER'])
            logger.info("Successfully obtained new access token")
            return self.token
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting token: {str(e)}")
            raise

    def _ensure_token(self):
        """Ensure we have a valid token"""
        if not self.token or not self.token_expiry or datetime.now(UTC) >= self.token_expiry:
            return self._get_token()
        return self.token

    def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < (1.0 / self.requests_per_second):
            sleep_time = (1.0 / self.requests_per_second) - time_since_last_request
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def _make_request(self, method, endpoint, params=None, data=None):
        """Make an API request with rate limiting and retries"""
        headers = {
            "Authorization": f"Bearer {self._ensure_token()}",
            "Content-Type": "application/json"
        }
        
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        max_retries = CONFIG['MAX_RETRIES']
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                self._rate_limit()  # Apply rate limiting
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=data
                )
                
                if response.status_code == 429:  # Too Many Requests
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limit hit. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    retry_count += 1
                    continue
                    
                response.raise_for_status()
                return response.json()
                
            except requests.exceptions.RequestException as e:
                self._log_response(method, url, e.response if hasattr(e, 'response') else None)
                retry_count += 1
                if retry_count == max_retries:
                    logger.error(f"Failed after {max_retries} retries: {str(e)}")
                    return {"data": []}
                logger.warning(f"Retry {retry_count} of {max_retries}")
                time.sleep(retry_count * 2)  # Exponential backoff
                
            except Exception as e:
                logger.error(f"Unexpected error in request: {str(e)}")
                return {"data": []}

    def get_alerts(self, start_time=None, end_time=None, alert_types=None):
        """
        Get all alerts from Lacework with pagination
        
        Args:
            start_time (str): ISO format start time
            end_time (str): ISO format end time
            alert_types (list): List of alert types to filter for
        """
        if not start_time:
            start_time = (datetime.now(UTC) - timedelta(hours=self.lookback_hours)).isoformat()
        if not end_time:
            end_time = datetime.now(UTC).isoformat()

        all_alerts = []
        next_page = None
        page_number = 1

        while True:
            params = {
                "startTime": start_time,
                "endTime": end_time,
                "limit": 100  # Maximum allowed per page
            }
            
            if next_page:
                params["nextPage"] = next_page

            # Get alerts for current page
            response = self._make_request("GET", "Alerts", params=params)
            
            if not response or 'data' not in response:
                break

            current_alerts = response.get('data', [])
            
            # Filter by alert type if specified
            if alert_types:
                current_alerts = [
                    alert for alert in current_alerts
                    if alert.get('alertType') in alert_types
                ]
            
            all_alerts.extend(current_alerts)
            
            # Check if there's a next page
            next_page = response.get('paging', {}).get('urls', {}).get('nextPage')
            logger.info(f"Retrieved page {page_number} with {len(current_alerts)} alerts")
            
            if not next_page:
                break
                
            page_number += 1

        return {
            'data': all_alerts,
            'paging': {
                'rows': len(all_alerts),
                'totalRows': len(all_alerts)
            }
        }

    def get_alert_details(self, alert_id, scope="Details"):
        """
        Get details for a specific alert
        
        Args:
            alert_id (str): The alert ID to get details for
            scope (str): One of "Details", "Investigation", "Events", "RelatedAlerts", 
                        "Integrations", "Timeline", "ObservationTimeline"
        """
        params = {"scope": scope}
        try:
            return self._make_request("GET", f"Alerts/{alert_id}", params=params)
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to get details for alert {alert_id} with scope {scope}: {str(e)}")
            return {"data": {}}

    def get_alert_types(self):
        """Get available alert types"""
        return self._make_request("GET", "AlertRules/Types")

    def get_internal_connections(self, start_time=None, end_time=None):
        """
        Get internal connection alerts specifically
        """
        alerts = self.get_alerts(start_time, end_time)
        return [
            alert for alert in alerts.get("data", [])
            if "Internal Connection" in alert.get("eventCategory", "")
        ]

    def get_all_alerts_detailed(self, start_time=None, end_time=None, alert_types=None):
        """
        Get all alerts with detailed information for the specified time period
        """
        alerts = self.get_alerts(start_time, end_time, alert_types)
        detailed_alerts = []

        for alert in alerts.get("data", []):
            alert_id = alert.get("alertId")
            if not alert_id:
                continue

            try:
                time.sleep(2)  # Rate limiting
                
                # Get alert details
                details = self.get_alert_details(alert_id, "Details")
                alert_data = details.get("data", {})
                
                # Parse specific alert types
                if alert_data.get("alertType") == "NewExternalServerIp":
                    parsed_alert = parse_external_server_ip_alert(alert_data)
                    logger.info(format_external_server_ip_summary(parsed_alert))
                    alert_data["parsed_summary"] = parsed_alert
                
                detailed_alerts.append(alert_data)
                logger.info(f"Successfully processed alert {alert_id}")

            except Exception as e:
                logger.error(f"Error processing alert {alert_id}: {str(e)}")
                continue

        return detailed_alerts

    def get_process_details(self, start_time=None, end_time=None, filters=None):
        """
        Get process details from Lacework with flexible filtering
        
        Args:
            start_time (str): ISO format start time
            end_time (str): ISO format end time
            filters (list): List of filter dicts to apply
        """
        params = {
            "startTime": start_time,
            "endTime": end_time,
            "limit": 100
        }
        
        if filters:
            params["filters"] = filters
            
        return self._make_request("GET", "Processes", params=params)

    def search_connections(self, start_time=None, end_time=None, filters=None, returns=None):
        """
        Search for connections in the Lacework environment
        
        Args:
            start_time (str): ISO format start time
            end_time (str): ISO format end time
            filters (list): List of filter dicts to apply
            returns (list): List of fields to return
        """
        if not start_time:
            start_time = (datetime.now(UTC) - timedelta(hours=self.lookback_hours)).isoformat()
            
        payload = {
            "timeFilter": {
                "startTime": start_time
            }
        }
        
        if end_time:
            payload["timeFilter"]["endTime"] = end_time
            
        if filters:
            payload["filters"] = filters
            
        if returns:
            payload["returns"] = returns
            
        return self._make_request("POST", "Activities/Connections/search", data=payload)

def extract_network_details(alert):
    """Extract IP addresses, ports, and related information from alert data"""
    network_info = {
        'source_ips': set(),
        'destination_ips': set(),
        'ports': set(),
        'connections': [],
        'aws_instances': set(),
        'aws_accounts': set(),
        'domains': set()
    }
    
    description = alert.get('alertInfo', {}).get('description', '')
    if not description:
        return network_info
        
    import re
    
    # IP address pattern (both IPv4 and IPv6)
    ip_pattern = r'(?:External IP |IP address |IP |)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    
    # Port patterns
    port_patterns = [
        r'port (?:HTTPS|HTTP|SSH|High Ports)?\(?(\d+)\)?',  # Standard port notation
        r'port\s+(\d+)',                                    # Simple port number
        r'port\s+[A-Za-z\s]+\((\d+)\)'                     # Named ports with numbers
    ]
    
    # Extract IPs
    ips = re.findall(ip_pattern, description)
    if "connected to" in description.lower():
        network_info['source_ips'].update(ips)
    else:
        network_info['destination_ips'].update(ips)
    
    # Extract ports
    for pattern in port_patterns:
        ports = re.findall(pattern, description)
        network_info['ports'].update(ports)
    
    # If we have both IP and port, create a connection entry
    if ips and ports:
        network_info['connections'].append({
            'source': ips[0] if "connected to" in description.lower() else 'internal',
            'destination': 'internal' if "connected to" in description.lower() else ips[0],
            'port': ports[0],
            'protocol': 'TCP' if 'TCP' in description else 'unknown',
            'alert_type': alert.get('alertType'),
            'severity': alert.get('severity'),
            'timestamp': alert.get('startTime')
        })

    return network_info

def format_alert_network_summary(alert):
    """Format network-focused alert information for display"""
    network_info = extract_network_details(alert)
    
    summary = f"""
{'='*80}
Alert ID: {alert['alert_id']}
Category: {alert['event_category']}
Type: {alert['event_type']}
Severity: {alert['severity']}
Status: {alert['status']}

Network Information:
Source IPs: {', '.join(sorted(network_info['source_ips'])) if network_info['source_ips'] else 'None'}
Destination IPs: {', '.join(sorted(network_info['destination_ips'])) if network_info['destination_ips'] else 'None'}
Ports: {', '.join(sorted(network_info['ports'])) if network_info['ports'] else 'None'}

Connections:"""
    
    if network_info['connections']:
        for conn in network_info['connections']:
            summary += f"\n  {conn['source']} -> {conn['destination']}:{conn['port']}"
    else:
        summary += "\n  No specific connections found"
    
    if 'error' in alert:
        summary += f"\nERROR: {alert['error']}"
    
    summary += f"\n{'='*80}"
    return summary

def save_results_to_file(alerts, filename="lacework_alerts.json"):
    """Save results to a JSON file"""
    with open(filename, 'w') as f:
        json.dump(alerts, f, indent=2)
    logger.info(f"Results saved to {filename}")

def save_network_summary(alerts, api_client=None, filename="network_summary.json"):
    """
    Save network summary to a JSON file
    """
    network_summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "alert_types": {}
    }
    
    # Handle both list and dict inputs
    alert_list = alerts if isinstance(alerts, list) else alerts.get('data', [])
    
    for alert in alert_list:
        alert_type = alert.get('alertType')
        
        if alert_type not in network_summary["alert_types"]:
            network_summary["alert_types"][alert_type] = {
                "alert_count": 0,
                "unique_sources": set(),
                "unique_destinations": set(),
                "unique_ports": set(),
                "aws_instances": set(),
                "aws_accounts": set(),
                "domains": set(),
                "alerts": [],
                "additional_details": []
            }
        
        type_summary = network_summary["alert_types"][alert_type]
        type_summary["alert_count"] += 1
        
        try:
            # Get additional details if needed
            if "(and" in alert.get('alertInfo', {}).get('description', '') and api_client:
                events = api_client.get_alert_details(alert.get('alertId'), "Events")
                if events and 'data' in events:
                    type_summary["additional_details"].extend(events['data'])
            
            # Extract and add network details
            network_info = extract_network_details(alert)
            type_summary["unique_sources"].update(network_info['source_ips'])
            type_summary["unique_destinations"].update(network_info['destination_ips'])
            type_summary["unique_ports"].update(network_info['ports'])
            type_summary["aws_instances"].update(network_info['aws_instances'])
            type_summary["aws_accounts"].update(network_info['aws_accounts'])
            type_summary["domains"].update(network_info['domains'])
            
            # Add individual alert details
            alert_details = {
                "alert_id": alert.get('alertId'),
                "severity": alert.get('severity'),
                "start_time": alert.get('startTime'),
                "end_time": alert.get('endTime'),
                "source": alert.get('derivedFields', {}).get('source'),
                "category": alert.get('derivedFields', {}).get('category'),
                "sub_category": alert.get('derivedFields', {}).get('sub_category'),
                "description": alert.get('alertInfo', {}).get('description'),
                "network_info": {
                    "source_ips": list(network_info['source_ips']),
                    "destination_ips": list(network_info['destination_ips']),
                    "ports": list(network_info['ports']),
                    "connections": network_info['connections'],
                    "aws_instances": list(network_info['aws_instances']),
                    "aws_accounts": list(network_info['aws_accounts']),
                    "domains": list(network_info['domains'])
                }
            }
            type_summary["alerts"].append(alert_details)
            
            # Log successful extraction
            if any([network_info['source_ips'], network_info['destination_ips'], 
                   network_info['ports'], network_info['aws_instances']]):
                logger.info(f"Extracted network info from alert {alert.get('alertId')}: {network_info}")
                
        except Exception as e:
            logger.error(f"Error processing alert {alert.get('alertId', 'unknown')}: {str(e)}")
            continue
    
    try:
        # Convert sets to lists for JSON serialization
        for alert_type in network_summary["alert_types"].values():
            alert_type["unique_sources"] = sorted(list(alert_type["unique_sources"]))
            alert_type["unique_destinations"] = sorted(list(alert_type["unique_destinations"]))
            alert_type["unique_ports"] = sorted(list(alert_type["unique_ports"]))
            alert_type["aws_instances"] = sorted(list(alert_type["aws_instances"]))
            alert_type["aws_accounts"] = sorted(list(alert_type["aws_accounts"]))
            alert_type["domains"] = sorted(list(alert_type["domains"]))
        
        # Save to file
        with open(filename, 'w') as f:
            json.dump(network_summary, f, indent=2)
        
        return network_summary
    except Exception as e:
        logger.error(f"Error saving network summary: {str(e)}")
        raise

def save_raw_response(response_data, filename="raw_lacework_response.json"):
    """Save raw API response to a JSON file"""
    with open(filename, 'w') as f:
        json.dump(response_data, f, indent=2)
    logger.info(f"Raw response saved to {filename}")

def main():
    """Example usage"""
    try:
        # Initialize with custom lookback period (optional)
        lw = LaceworkAPI(
            config_file='lwintforticnappeu.json',
            lookback_hours=CONFIG['DEFAULT_LOOKBACK_HOURS']
        )
        
        # Get time range based on lookback period
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(hours=lw.lookback_hours)
        
        # Get network alerts using default alert types from CONFIG
        alerts = lw.get_alerts(
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            alert_types=CONFIG['DEFAULT_ALERT_TYPES']
        )
        
        # Map alert types to their parsers
        parsers = {
            "NewExternalServerIp": external_server_ip_parser,
            "NewExternalClientConn": external_client_conn_parser,
            "NewInternalConnection": internal_connection_parser
        }
        
        for alert in alerts.get('data', []):
            try:
                details = lw.get_alert_details(alert.get('alertId'), "Details")
                alert_data = details.get("data", {})
                
                # Get parser for this alert type
                alert_type = alert_data.get("alertType")
                parser = parsers.get(alert_type)
                
                if parser:
                    parsed_alert = parser.parse_alert(alert_data)
                    print(utils.format_alert_json(parsed_alert))
                    print("-" * 80)
                
            except Exception as e:
                logger.error(f"Error processing alert {alert.get('alertId')}: {str(e)}")
                continue
        
        # Save raw alerts to file
        save_raw_response(alerts, "network_alerts.json")
        logger.info(f"Raw alerts saved to network_alerts.json")

    except Exception as e:
        logger.error(f"Error in main: {str(e)}")
        raise

if __name__ == "__main__":
    main() 