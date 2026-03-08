import re
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

# ==========================================
# 1. PARSING REAL WORLD LOGS (MEMORY OPTIMIZED)
# ==========================================
def parse_apache_log(filepath):
    print(f"Reading massive {filepath}... (This might take a minute or two, please wait!)")
    pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] ".*?" (?P<status>\d+)')
    
    # Using Counters saves your computer's RAM from crashing on a 2.4GB file!
    ip_counts = Counter()
    scanner_counts = Counter()
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    ip = match.group('ip')
                    status = match.group('status')
                    ip_counts[ip] += 1
                    if status == '404':
                        scanner_counts[ip] += 1
    except FileNotFoundError:
        print(f"Warning: Could not find {filepath}. Check your folder to make sure it is there!")
        
    return ip_counts, scanner_counts

def parse_ssh_data(auth_file, sessions_file):
    try:
        auth_df = pd.read_csv(auth_file)
        sessions_df = pd.read_csv(sessions_file)
    except FileNotFoundError:
        print("Warning: Could not find the CSV files. Check your folder.")
        return pd.DataFrame({'ip': []})

    # FIX: Rename the 'id' column in sessions_df to 'session' so they match perfectly
    if 'id' in sessions_df.columns:
        sessions_df = sessions_df.rename(columns={'id': 'session'})

    # Standardize the IP column name
    if 'peerIP' in sessions_df.columns:
        sessions_df = sessions_df.rename(columns={'peerIP': 'ip'})
    elif 'source_ip' in sessions_df.columns:
        sessions_df = sessions_df.rename(columns={'source_ip': 'ip'})

    # MERGE databases together using the shared 'session' ID
    merged_df = pd.merge(auth_df, sessions_df, on='session')
    
    # Filter for failed logins
    failed_logins = merged_df[merged_df['success'].astype(int) == 0]
    return failed_logins

# ==========================================
# 2. THREAT DETECTION ENGINE
# ==========================================
def detect_threats(ip_counts, scanner_counts, failed_ssh_df):
    alerts = []

    # Detect DoS (Threshold raised for a massive file)
    for ip, count in ip_counts.items():
        if count > 500:
            alerts.append({'IP': ip, 'Threat': 'Potential DoS', 'Count': count})

    # Detect Scanning (Threshold raised for a massive file)
    for ip, count in scanner_counts.items():
        if count >= 100:
            alerts.append({'IP': ip, 'Threat': 'Directory Scanning (404s)', 'Count': count})

    if not failed_ssh_df.empty:
        brute_ips = failed_ssh_df['ip'].value_counts()
        for ip in brute_ips[brute_ips >= 50].index:
            alerts.append({'IP': ip, 'Threat': 'SSH Brute Force', 'Count': brute_ips[ip]})

    return pd.DataFrame(alerts)

# ==========================================
# 3. EXPORT & VISUALIZE
# ==========================================
def run_analyzer():
    print("Initializing Log File Analyzer...")
    
    # 1. Parse Apache
    ip_counts, scanner_counts = parse_apache_log('apache.log')
    
    # 2. Parse SSH
    print("Merging SSH Databases...")
    failed_ssh_df = parse_ssh_data('auth.csv', 'sessions.csv')
    
    # 3. Detect Threats
    print("Hunting for threats...")
    alerts_df = detect_threats(ip_counts, scanner_counts, failed_ssh_df)

    if alerts_df.empty:
        print("\nNo threats detected! The data might be clean, or thresholds need adjusting.")
        return

    # Export CSV
    alerts_df.to_csv('incident_report.csv', index=False)
    print("\n--- ENTERPRISE INTRUSION REPORT ---")
    # Using .to_string() prevents Pandas from hiding rows if there are a lot of threats
    print(alerts_df.to_string())
    print("\nReport saved to 'incident_report.csv'")

    # Generate Graph
    # Combine counts if the same IP did multiple types of attacks
    graph_data = alerts_df.groupby('IP')['Count'].sum().reset_index()
    top_10 = graph_data.sort_values(by='Count', ascending=False).head(10)
    
    top_10.plot(x='IP', y='Count', kind='bar', color='darkred', legend=False)
    plt.title('Top 10 Detected Attacks by IP Address')
    plt.ylabel('Event Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('attack_graph.png')
    print("Graph saved to 'attack_graph.png'")

if __name__ == "__main__":
    run_analyzer()