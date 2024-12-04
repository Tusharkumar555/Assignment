import re
import csv
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = 'sample.log'  
OUTPUT_CSV = 'results.csv'

def parse_log_file(log_file):
    ip_requests = defaultdict(int)
    endpoint_access = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_requests[ip_address] += 1
            
            endpoint_match = re.search(r'\"(GET|POST|PUT|DELETE) (.+?) ', line)
            if endpoint_match:
                endpoint = endpoint_match.group(2)
                endpoint_access[endpoint] += 1
            if '401' in line or 'Invalid credentials' in line:
                failed_logins[ip_address] += 1

    return ip_requests, endpoint_access, failed_logins

def analyze_logs():
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)

    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1], default=("None", 0))
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    print("IP Address Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(sorted_ip_requests)

        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

if __name__ == "__main__":
    analyze_logs()