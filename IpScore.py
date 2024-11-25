import requests
import json
import csv
import re
import ipaddress
import folium
import geoip2.database

# Constants
ABUSE_IPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
API_KEY = ''  # Replace with your actual API key
GEOIP_DB_PATH = 'GeoLite2-City.mmdb'  # Path to GeoIP database
OUTPUT_CSV = 'abuse_ip_results.csv'
OUTPUT_MAP = 'ip_map.html'

# Headers for AbuseIPDB API
HEADERS = {
    'Accept': 'application/json',
    'Key': API_KEY
}

# Deduplicate IPs
def deduplicate(ips):
    return list(set(ips))

# Extract public IPs from file
def extract_public_ips(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    # Extract IPv4 addresses
    all_ips = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', content)
    # Filter public IPs
    public_ips = [ip for ip in deduplicate(all_ips) if not ipaddress.ip_address(ip).is_private]
    return public_ips

# Query AbuseIPDB and save results to CSV
def query_abuse_ipdb(ips):
    results = []
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['ipAddress', 'abuseConfidenceScore', 'domain', 'countryCode', 'usageType'])
        for ip in ips:
            try:
                response = requests.get(
                    ABUSE_IPDB_URL,
                    headers=HEADERS,
                    params={'ipAddress': ip, 'maxAgeInDays': '90'},
                    verify=False
                )
                data = response.json().get('data', {})
                results.append(data)
                writer.writerow([
                    data.get('ipAddress', ''),
                    data.get('abuseConfidenceScore', ''),
                    data.get('domain', ''),
                    data.get('countryCode', ''),
                    data.get('usageType', '')
                ])
            except Exception as e:
                print(f"Error querying AbuseIPDB for IP {ip}: {e}")
    return results

# Generate map from AbuseIPDB results
def generate_map(results):
    # Initialize map
    m = folium.Map(location=[0, 0], zoom_start=2)
    # Load GeoIP database
    reader = geoip2.database.Reader(GEOIP_DB_PATH)
    for result in results:
        ip = result.get('ipAddress', '')
        score = int(result.get('abuseConfidenceScore', 0))
        domain = result.get('domain', 'N/A')
        color = 'green' if score == 0 else \
                'beige' if 0 < score < 10 else \
                'lightblue' if 10 <= score < 50 else \
                'purple' if 50 <= score < 75 else 'red'
        try:
            response = reader.city(ip)
            lat, lon = response.location.latitude, response.location.longitude
            popup_text = f"IP: {ip}<br>Domain: {domain}<br>Score: {score}<br>Location: {response.city.name}, {response.country.name}"
            folium.Marker(
                location=[lat, lon],
                tooltip=ip,
                popup=popup_text,
                icon=folium.Icon(color=color)
            ).add_to(m)
        except Exception as e:
            print(f"Error resolving IP {ip} to location: {e}")
    # Save map to file
    m.save(OUTPUT_MAP)
    print(f"Map saved to {OUTPUT_MAP}")

# Main function
def main(input_file):
    # Step 1: Extract public IPs
    print("Extracting public IPs...")
    public_ips = extract_public_ips(input_file)
    print(f"Found {len(public_ips)} public IPs.")

    # Step 2: Query AbuseIPDB
    print("Querying AbuseIPDB...")
    abuse_results = query_abuse_ipdb(public_ips)
    print(f"Results saved to {OUTPUT_CSV}.")

    # Step 3: Generate map
    print("Generating map...")
    generate_map(abuse_results)
    print("Process completed.")

# Run the script
if __name__ == "__main__":
    input_file = 'SampleIpRaw.csv'  # Replace with your input file (CSV or text)
    main(input_file)
