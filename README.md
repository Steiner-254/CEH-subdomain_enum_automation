# Subdomain Enumeration Automation

## Overview

This project provides an automated Python script for subdomain enumeration and live subdomain verification targeting a given domain. The script, `sub_enum_automation.py`, leverages [Subfinder](https://github.com/projectdiscovery/subfinder) to gather subdomains and checks which of them are responsive by testing both HTTP and HTTPS connections.

The script outputs two files:
- **All discovered subdomains:** Saved as `all_subs_<domain>.txt`
- **Live subdomains:** Saved as `live_subs_<domain>.txt`

Additionally, the script is fully monitored via Python's `logging` module, ensuring each step is logged for easy troubleshooting. It also includes an installation feature: it automatically installs required Python modules (e.g. `requests`) and downloads Subfinder if it's not present on your system.

## Installation

### Prerequisites

- **Python 3.x** is required.
- An **active internet connection** to download dependencies and the Subfinder tool if needed.

### Steps

1. **Clone the Repository**

   Open your terminal and run:
   ```bash
   git clone https://github.com/Steiner-254/CEH-subdomain_enum_automation.git
   cd CEH-subdomain_enum_automation
   ```
2. **(Optional) Create a Virtual Environment.** It is recommended to use a virtual environment to manage dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Run the Script.**
The script automatically checks for required dependencies and installs them if needed. To execute the script, run:
   ```bash
   python3 sub_enum_automation.py --target domain.com
   ```
   - Replace domain.com with the target domain you wish to enumerate.
   - The script will:
   
   >> Check and install the Python requests module if it is missing.
   
   >> Verify if Subfinder is in your system PATH; if not, it will download and extract the appropriate version for your system.
   
   >> Enumerate and save all subdomains to `all_subs_domain_com.txt` (dots replaced by underscores).
   
   >> Filter and save live subdomains to `live_subs_domain_com.txt`.

## License
- This project is provided as-is with no warranty. You are free to modify it as needed for your own use.
