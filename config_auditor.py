# ==============================================================================
# PROJECT: PYTHON AUTOMATED NETWORK CONFIGURATION COMPLIANCE AUDITOR
# AUTHOR: MATUTUZELA JABULANI NDLOVU
# PURPOSE: Automatically parses device backup configurations to audit security vectors
# ==============================================================================

import re
import json

# Simulating raw text configuration files pulled from a Cisco edge router backup
mock_cisco_config = """
hostname Core-Vaal-Router-01
!
no ip domain-lookup
!
username admin privilege 15 secret 0 default_password123
!
interface Ethernet0/1
 description Local Area Network Interface
 ip address 192.168.1.1 255.255.255.0
!
interface Ethernet0/2
 description Public Facing Interface
 ip address 45.22.11.4 255.255.255.248
!
line vty 0 4
 transport input telnet
 login local
!
end
"""

def run_security_compliance_audit(config_text):
    print("=== STARTING INFRASTRUCTURE COMPLIANCE SCAN ===")
    
    # Define compliance check patterns using Regular Expressions (Regex)
    security_checks = {
        "Unencrypted Default Passwords": r"secret 0 .*password",
        "Insecure Plaintext Telnet Protocol Enabled": r"transport input telnet",
        "Missing Global Domain Lookup Disable Baseline": r"no ip domain-lookup"
    }
    
    audit_report = {
        "device_hostname": "Unknown",
        "vulnerabilities_detected": [],
        "passed_compliance_checks": []
    }
    
    # Extract Hostname dynamically from the config string
    hostname_match = re.search(r"hostname\s+(\S+)", config_text)
    if hostname_match:
        audit_report["device_hostname"] = hostname_match.group(1)
        
    # Run structural compliance comparisons
    for check_name, pattern in security_checks.items():
        match = re.search(pattern, config_text, re.IGNORECASE)
        
        if check_name == "Missing Global Domain Lookup Disable Baseline":
            # If the "no ip domain-lookup" baseline is present, it PASSES
            if match:
                audit_report["passed_compliance_checks"].append(check_name)
            else:
                audit_report["vulnerabilities_detected"].append(check_name)
        else:
            # For password and telnet, if the pattern MATCHES, it's a VULNERABILITY
            if match:
                audit_report["vulnerabilities_detected"].append(check_name)
            else:
                audit_report["passed_compliance_checks"].append(check_name)
                
    return audit_report

# Execute the auditing automation sequence
audit_results = run_security_compliance_audit(mock_cisco_config)

# Output results as a clean, standardized JSON string (ideal for data pipelines)
print(json.dumps(audit_results, indent=4))
