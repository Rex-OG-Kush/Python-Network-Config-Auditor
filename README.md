# Python Network Config Auditor 🐍🛡️

An automated infrastructure compliance tracking utility written in Python designed to parse raw Cisco/Mikrotik text configuration backups and programmatically isolate architectural security vulnerabilities.

## 📋 Project Overview
Manually verifying security compliance policies across hundreds of enterprise router deployment files is highly prone to human oversight. This automation script introduces an automated audit model. By leveraging regular expressions (Regex) and text parsing arrays, the script treats text-based configuration states as data inputs, scans for common security vulnerabilities (such as plaintext passwords or insecure management protocols), and structuralizes the audit log into a standardized JSON format.

## 🛠️ Technical Capabilities Demonstrated
*   **Infrastructure Automation (Python):** Processing unstructured router configuration text data using native data-handling tools.
*   **Pattern-Matching Logic (Regex):** Crafting exact regular expression blocks to scan file layers for security compliance breaches.
*   **Standardized Data Structuring:** Mapping flat text evaluation arrays into multi-level JSON string blocks ready to be streamed into enterprise database monitoring tools.

## 🚀 How the Automation System Operates
1.  **Ingestion:** The Python script loads an exported device text configuration block baseline.
2.  **Regex Auditing:** Searches for core architectural vulnerabilities, including unencrypted password tokens and unsecure Telnet access configuration parameters.
3.  **JSON Structuring:** Generates a machine-readable compliance tracking payload identifying the specific device hostname, failed compliance vectors, and passed configurations.

## 📈 Intended Business Impact
Replacing manual configuration checklists with automated text auditing pipelines ensures that enterprise infrastructure teams can instantly run regular bulk network safety compliance sweeps across multi-vendor nodes, mitigating deployment human error risks entirely.
