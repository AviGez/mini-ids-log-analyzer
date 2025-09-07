import re
from collections import Counter

def parse_auth_log(filename):
    failed_ips = []
    regex = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
    with open(filename, "r") as f:
        for line in f:
            match = regex.search(line)
            if match:
                failed_ips.append(match.group(1))
    return Counter(failed_ips)

if __name__ == "__main__":
    counts = parse_auth_log("data/auth.log")
    print("Suspicious IPs:")
    for ip, c in counts.items():
        print(f"{ip} → {c} failed attempts")
