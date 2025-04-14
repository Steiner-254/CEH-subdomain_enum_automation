#!/usr/bin/env python3
"""
Automated Fingerprinting & Recon Script
This script uses Subfinder to enumerate subdomains for a given target domain,
checks which subdomains are live, and saves:
    - All discovered subdomains in a file named all_subs_<domain>.txt
    - Only live subdomains in a file named live_subs_<domain>.txt

It also checks for required dependencies:
    - Python module 'requests' (installs if missing)
    - The Subfinder tool (downloads and sets up if not found in PATH)

Usage:
    python3 sub_enum_automation.py --target domain.com
"""

import argparse
import logging
import os
import platform
import shutil
import subprocess
import sys
import zipfile

# Check for the 'requests' module and install if not present.
try:
    import requests
except ImportError:
    # Log information about installing the module.
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    logging.info("The 'requests' module was not found; installing it using pip.")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Disable warnings for unverified HTTPS requests (used in live subdomain check).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging for the script.
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)


def check_and_install_subfinder():
    """
    Checks if subfinder exists in the system PATH.
    If not present, downloads, extracts, and sets up the subfinder binary.
    Returns:
        The absolute path to the subfinder executable.
    """
    # Check if subfinder is available in PATH.
    subfinder_path = shutil.which("subfinder")
    if subfinder_path:
        logging.info(f"Subfinder found in PATH at: {subfinder_path}")
        return subfinder_path

    logging.info("Subfinder not found. Attempting to download and set up subfinder...")

    # Determine system details to download the appropriate release.
    system = platform.system().lower()  # e.g., "linux", "darwin", "windows"
    machine = platform.machine().lower()
    # Set the desired version. Adjust if needed.
    version = "2.4.5"
    base_url = f"https://github.com/projectdiscovery/subfinder/releases/download/v{version}/"

    # Determine the correct filename for the platform.
    if system == "linux":
        if machine in ("x86_64", "amd64"):
            filename = f"subfinder_{version}_linux_amd64.zip"
        elif "arm" in machine:
            filename = f"subfinder_{version}_linux_arm64.zip"
        else:
            logging.error("Unsupported Linux architecture detected.")
            sys.exit(1)
    elif system == "darwin":
        if machine in ("x86_64", "amd64"):
            filename = f"subfinder_{version}_darwin_amd64.zip"
        elif "arm" in machine:
            filename = f"subfinder_{version}_darwin_arm64.zip"
        else:
            logging.error("Unsupported macOS architecture detected.")
            sys.exit(1)
    elif system == "windows":
        if machine in ("x86_64", "amd64"):
            filename = f"subfinder_{version}_windows_amd64.zip"
        else:
            logging.error("Unsupported Windows architecture detected.")
            sys.exit(1)
    else:
        logging.error("Unsupported operating system.")
        sys.exit(1)

    download_url = base_url + filename
    logging.info(f"Downloading subfinder from {download_url}")

    # Download the zip archive.
    local_zip = filename
    try:
        with requests.get(download_url, stream=True) as r:
            r.raise_for_status()
            with open(local_zip, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        logging.info("Subfinder download completed.")
    except Exception as e:
        logging.error(f"Failed to download subfinder: {e}")
        sys.exit(1)

    # Extract the downloaded zip file.
    try:
        with zipfile.ZipFile(local_zip, "r") as zip_ref:
            zip_ref.extractall(".")
        logging.info("Subfinder extraction completed.")
    except Exception as e:
        logging.error(f"Failed to extract subfinder: {e}")
        sys.exit(1)
    finally:
        # Clean up: remove the downloaded zip file.
        if os.path.exists(local_zip):
            os.remove(local_zip)

    # Determine the binary name depending on the operating system.
    binary_name = "subfinder.exe" if system == "windows" else "subfinder"

    if not os.path.exists(binary_name):
        logging.error("Subfinder binary not found after extraction.")
        sys.exit(1)

    # On Unix systems, ensure the binary is executable.
    if system != "windows":
        os.chmod(binary_name, 0o755)

    subfinder_full_path = os.path.abspath(binary_name)
    logging.info(f"Subfinder set up successfully at: {subfinder_full_path}")
    return subfinder_full_path


def run_subfinder(domain: str, subfinder_exe: str) -> list:
    """
    Runs the subfinder tool for the provided domain using the subfinder executable.
    Args:
        domain: The target domain to enumerate subdomains for.
        subfinder_exe: The path to the subfinder executable.
    Returns:
        A list of discovered subdomains (one per line from subfinder output).
    """
    try:
        cmd = [subfinder_exe, "-d", domain, "-silent"]
        logging.info(f"Executing command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        subdomains = result.stdout.strip().splitlines()
        logging.info(f"Subfinder discovered {len(subdomains)} subdomains for {domain}.")
        return subdomains
    except subprocess.CalledProcessError as e:
        logging.error(f"Subfinder execution failed: {e.stderr}")
        return []


def is_live(url: str, timeout: float = 5.0) -> bool:
    """
    Checks if a given URL is live by making an HTTP GET request.
    Args:
        url: The URL (with scheme) to check.
        timeout: Timeout for the HTTP request.
    Returns:
        True if the URL responds with a status code less than 400, otherwise False.
    """
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        return response.status_code < 400
    except requests.RequestException:
        return False


def filter_live_subdomains(subdomains: list) -> list:
    """
    Filters the list of subdomains by checking which ones are live.
    It tests with both HTTPS and HTTP for each subdomain.
    Args:
        subdomains: List of subdomains to check.
    Returns:
        A list of live subdomains.
    """
    live_subdomains = []

    def check_subdomain(subd):
        # Attempt to connect using HTTPS first, then HTTP.
        for scheme in ("https://", "http://"):
            target = scheme + subd.strip()
            if is_live(target):
                logging.info(f"[LIVE] {target}")
                return subd
        logging.info(f"[DEAD] {subd}")
        return None

    # Use a thread pool to concurrently check each subdomain.
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                live_subdomains.append(result)

    logging.info(f"{len(live_subdomains)} out of {len(subdomains)} subdomains are live.")
    return live_subdomains


def parse_args():
    """
    Parses command-line arguments.
    Returns:
        The parsed arguments containing the target domain.
    """
    parser = argparse.ArgumentParser(
        description="Automated fingerprinting & recon script using Subfinder and live subdomain filtering."
    )
    parser.add_argument("--target", required=True, help="Target domain (e.g., domain.com)")
    return parser.parse_args()


def main():
    # Parse command-line arguments.
    args = parse_args()
    target_domain = args.target.strip()
    logging.info(f"Starting recon for target domain: {target_domain}")

    # Check for and install subfinder if necessary.
    subfinder_exe = check_and_install_subfinder()

    # Run subfinder to enumerate all subdomains.
    subdomains = run_subfinder(target_domain, subfinder_exe)
    if not subdomains:
        logging.error("No subdomains discovered or subfinder encountered an error. Exiting...")
        sys.exit(1)

    # Save all discovered subdomains to the output file.
    # Replace dots with underscores in the filename for compatibility.
    output_all_file = f"all_subs_{target_domain.replace('.', '_')}.txt"
    try:
        with open(output_all_file, "w") as f_all:
            for sub in subdomains:
                f_all.write(sub + "\n")
        logging.info(f"All subdomains saved to: {output_all_file}")
    except Exception as e:
        logging.error(f"Error writing all subdomains to file: {e}")
        sys.exit(1)

    # Filter subdomains to get the live ones.
    live_subdomains = filter_live_subdomains(subdomains)

    # Save live subdomains to their designated output file.
    output_live_file = f"live_subs_{target_domain.replace('.', '_')}.txt"
    try:
        with open(output_live_file, "w") as f_live:
            for sub in live_subdomains:
                f_live.write(sub + "\n")
        logging.info(f"Live subdomains saved to: {output_live_file}")
    except Exception as e:
        logging.error(f"Error writing live subdomains to file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
