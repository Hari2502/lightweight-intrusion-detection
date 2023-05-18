import re
import datetime

class IDS:
    def __init__(self):
        self.rules = []
    
    def add_rule(self, rule):
        self.rules.append(rule)
    
    def detect(self, packet):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alerts = []
        for rule in self.rules:
            if re.search(rule, packet):
                alerts.append(f"{timestamp} - Alert: Suspicious pattern '{rule}' detected in packet: '{packet}'")
        return alerts

# Example usage
ids = IDS()

# Add rules
ids.add_rule(r"\bSELECT.*FROM")
ids.add_rule(r"\b(\\x[\dA-Fa-f]{2})+")

# Simulated network traffic packets
packets = [
    "This is a normal packet.",
    "SELECT * FROM users;",
    "This packet contains SQL injection attempt: ' OR '1'='1';",
    "Packet with hexadecimal encoding: \\x48\\x65\\x6c\\x6c\\x6f\\x21",
    "Another normal packet."
]

# Detect suspicious patterns in network traffic
for packet in packets:
    alerts = ids.detect(packet)
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No alerts detected.")
