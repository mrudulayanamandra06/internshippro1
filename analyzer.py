import re
import csv
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

# --- Configuration ---
APACHE_LOG = 'apache.log'
AUTH_LOG = 'auth.csv'
REPORT_FILE = 'incident_report.csv'
GRAPH_FILE = 'attack_graph.png'

# Simulated Public IP Blacklist (Threat Intelligence)
KNOWN_THREAT_IPS = {'222.110.193.108', '8.197.178.154', '192.168.1.100'}

def analyze_apache(file_path):
    print(f"[*] Scanning {file_path} for suspicious web activity...")
    ip_counter = Counter()
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}'
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if ' 401 ' in line or ' 403 ' in line:
                    match = re.search(ip_pattern, line)
                    if match:
                        ip_counter[match.group()] += 1
        return ip_counter
    except FileNotFoundError:
        print(f"[-] Error: Could not find '{file_path}'.")
        return Counter()

def analyze_auth(file_path):
    print(f"[*] Scanning {file_path} for SSH brute-force attempts...")
    failed_logins = Counter()
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if 'Failed password' in line or 'failure' in line.lower():
                    match = re.search(ip_pattern, line)
                    if match:
                        failed_logins[match.group()] += 1
        return failed_logins
    except FileNotFoundError:
        print(f"[-] Error: Could not find '{file_path}'.")
        return Counter()

def generate_incident_report(apache_data, auth_data, output_file):
    print(f"\n[*] Generating automated incident report: {output_file}")
    flagged_events = []
    
    # Process Web Attacks
    for ip, count in apache_data.items():
        if count >= 10:
            threat_level = "High (Blacklisted)" if ip in KNOWN_THREAT_IPS else "Medium"
            flagged_events.append({
                'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'IP Address': ip,
                'Attack Type': 'Web Brute Force / Scanning',
                'Attempt Count': count,
                'Threat Intel': threat_level
            })
            
    # Process SSH Attacks
    for ip, count in auth_data.items():
        if count >= 5:
            threat_level = "Critical (Blacklisted)" if ip in KNOWN_THREAT_IPS else "High"
            flagged_events.append({
                'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'IP Address': ip,
                'Attack Type': 'SSH Brute Force',
                'Attempt Count': count,
                'Threat Intel': threat_level
            })

    # Write to CSV
    try:
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['Timestamp', 'IP Address', 'Attack Type', 'Attempt Count', 'Threat Intel']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for event in flagged_events:
                writer.writerow(event)
        print(f"[+] Success! Wrote {len(flagged_events)} alerts to {output_file}")
    except Exception as e:
        print(f"[-] Error writing report: {e}")

def visualize_attacks(csv_file, graph_file):
    print(f"[*] Generating visual attack graph: {graph_file}")
    try:
        # Load the newly created incident report into a pandas DataFrame
        df = pd.read_csv(csv_file)
        
        if df.empty:
            print("[-] No data available to graph.")
            return

        # Sort the data to get the top 10 most aggressive IPs
        top_attackers = df.sort_values(by='Attempt Count', ascending=False).head(10)

        # Plotting with matplotlib
        plt.figure(figsize=(10, 6))
        bars = plt.bar(top_attackers['IP Address'], top_attackers['Attempt Count'], color='darkred')
        
        # Formatting the graph
        plt.title('Top Malicious IP Addresses by Attempt Volume', fontsize=14, fontweight='bold')
        plt.xlabel('IP Address', fontsize=12)
        plt.ylabel('Number of Access Attempts', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout() # Ensures labels don't get cut off
        
        # Save the graph as a PNG
        plt.savefig(graph_file)
        print(f"[+] Success! Attack graph saved as '{graph_file}'")
        
    except Exception as e:
        print(f"[-] Error generating graph: {e}")

if __name__ == "__main__":
    print("--- SOC Log Analyzer Initialized ---\n")
    
    # 1. Parse Logs
    apache_results = analyze_apache(APACHE_LOG)
    auth_results = analyze_auth(AUTH_LOG)
    
    # 2. Cross-reference Blacklist & Export CSV
    generate_incident_report(apache_results, auth_results, REPORT_FILE)
    
    # 3. Visualize the Data
    visualize_attacks(REPORT_FILE, GRAPH_FILE)
    
    print("\n--- Analysis Complete ---")