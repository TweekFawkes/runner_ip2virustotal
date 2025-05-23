import argparse
import sys
import os
import json
from ipaddress import ip_address, AddressValueError

try:
    import vt
except ImportError:
    print("[!] Error: vt-py package not found. Please install it with: pip install vt-py", file=sys.stderr)
    sys.exit(1)

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

def validate_ip_address(ip_str):
    """Validate if the provided string is a valid IP address."""
    try:
        ip_obj = ip_address(ip_str)
        return ip_obj
    except (AddressValueError, ValueError):
        return None

def format_vt_response(data, ip_str):
    """Format the VirusTotal response data for readable output."""
    print(f"\n=== VirusTotal Threat Intelligence Report for {ip_str} ===\n")
    
    if not data:
        print("[*] No threat intelligence data found for this IP address.")
        return
    
    # General information
    print("[*] GENERAL INFORMATION:")
    print(f"    IP Address: {ip_str}")
    print(f"    Type: {data.get('type', 'N/A')}")
    print(f"    Country: {data.get('country', 'N/A')}")
    print(f"    ASN: {data.get('asn', 'N/A')}")
    print(f"    AS Owner: {data.get('as_owner', 'N/A')}")
    
    # Network information
    if 'network' in data:
        print(f"    Network: {data.get('network', 'N/A')}")
    
    # Reputation information
    reputation = data.get('reputation', 0)
    print(f"    Reputation Score: {reputation}")
    
    # Analysis stats
    if 'last_analysis_stats' in data:
        stats = data['last_analysis_stats']
        print(f"    Analysis Results:")
        print(f"        Harmless: {stats.get('harmless', 0)}")
        print(f"        Malicious: {stats.get('malicious', 0)}")
        print(f"        Suspicious: {stats.get('suspicious', 0)}")
        print(f"        Undetected: {stats.get('undetected', 0)}")
        print(f"        Timeout: {stats.get('timeout', 0)}")
        
        total_engines = sum(stats.values()) if stats.values() else 0
        malicious_count = stats.get('malicious', 0)
        if total_engines > 0:
            print(f"    Detection Ratio: {malicious_count}/{total_engines}")
        print()
    
    # Malware classifications
    if malicious_count > 0 and 'last_analysis_results' in data:
        print("[!] MALICIOUS DETECTIONS:")
        analysis_results = data['last_analysis_results']
        malicious_engines = []
        
        for engine, result in analysis_results.items():
            if result.get('category') == 'malicious':
                engine_result = result.get('result', 'Detected')
                malicious_engines.append(f"{engine}: {engine_result}")
        
        if malicious_engines:
            for detection in malicious_engines[:10]:  # Show first 10 detections
                print(f"    - {detection}")
            if len(malicious_engines) > 10:
                print(f"    ... and {len(malicious_engines) - 10} more detections")
        print()
    
    # Community votes
    if 'total_votes' in data:
        votes = data['total_votes']
        print("[*] COMMUNITY VOTES:")
        print(f"    Harmless: {votes.get('harmless', 0)}")
        print(f"    Malicious: {votes.get('malicious', 0)}")
        print()
    
    # Additional context
    if 'last_analysis_date' in data:
        print(f"[*] Last Analysis Date: {data.get('last_analysis_date', 'N/A')}")
    
    # Regional Internet Registry
    if 'regional_internet_registry' in data:
        print(f"[*] Regional Internet Registry: {data.get('regional_internet_registry', 'N/A')}")
    
    print()

def main():
    parser = argparse.ArgumentParser(description="Lookup IP Address threat intelligence using VirusTotal API.")
    parser.add_argument('ip_address', help='IP Address to Get Threat Intelligence For')
    parser.add_argument('--api-key', help='VirusTotal API Key (or set VT_API_KEY environment variable)')
    parser.add_argument('--raw', action='store_true', help='Output raw JSON response')
    args = parser.parse_args()

    ip_str = args.ip_address

    # Validate IP address format
    ip_obj = validate_ip_address(ip_str)
    if ip_obj is None:
        print(f"[!] Error: '{ip_str}' is not a valid IPv4 or IPv6 address.", file=sys.stderr)
        return 1

    # Get API key from argument or environment variable
    api_key = args.api_key or os.getenv('VT_API_KEY')
    if not api_key:
        print("[!] Error: VirusTotal API Key required. Set VT_API_KEY environment variable or use --api-key argument.", file=sys.stderr)
        print("[*] You can get an API key by registering at https://www.virustotal.com", file=sys.stderr)
        return 1

    print(f"[*] Querying VirusTotal for IP: {ip_str}")
    print(f"[*] IP Version: IPv{ip_obj.version}")

    try:
        # Initialize VirusTotal client
        with vt.Client(api_key) as client:
            print("[*] Fetching threat intelligence data...")
            
            # Get IP information from VirusTotal
            ip_object = client.get_object(f"/ip_addresses/{ip_str}")
            
            # Convert to dictionary for easier handling
            response_data = ip_object.to_dict()
            
            if args.raw:
                # Output raw JSON
                print(json.dumps(response_data, indent=2, default=str))
            else:
                # Format and display the response
                format_vt_response(response_data, ip_str)
        
        return 0

    except vt.APIError as e:
        print(f"[!] VirusTotal API Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[!] Error querying VirusTotal API: {e}", file=sys.stderr)
        return 1

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

if __name__ == "__main__":
    sys.exit(main())