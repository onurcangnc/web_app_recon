import requests
import subprocess
import argparse
import socket
from urllib.parse import urlparse
from colorama import Fore, Style, init
import whois

# Initialize colorama
init(autoreset=True)

SECURITY_HTTP_HEADERS = [
    "Set-Cookie",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options"
]

def nslookup(domain):
    """
    Perform NSLOOKUP for a domain and return the result.
    """
    try:
        ip = socket.gethostbyname(domain)
        return f"{Fore.GREEN}[+] NSLOOKUP: {domain} resolves to {ip}{Style.RESET_ALL}"
    except socket.gaierror:
        return f"{Fore.RED}[-] NSLOOKUP failed: Unable to resolve {domain}{Style.RESET_ALL}"

def whois_lookup(domain):
    """
    Perform WHOIS lookup for a domain and return the result.
    """
    try:
        domain_info = whois.whois(domain)
        owner = domain_info.get("org", domain_info.get("name", "Unknown"))
        owner_type = "Company" if "org" in domain_info else "Individual"
        result = [
            f"{Fore.GREEN}[+] WHOIS Information:{Style.RESET_ALL}",
            f"    Owner Type: {owner_type}",
            f"    Owner: {owner}",
            f"    Domain Name: {domain}",
            f"    Creation Date: {domain_info.get('creation_date', 'Unknown')}",
            f"    Expiration Date: {domain_info.get('expiration_date', 'Unknown')}",
        ]
        return "\n".join(result)
    except Exception as e:
        return f"{Fore.RED}[-] WHOIS lookup failed for {domain}: {e}{Style.RESET_ALL}"

def analyze_http_headers(url):
    """
    Analyze HTTP/HTTPS headers for vulnerabilities and return the result.
    """
    output = []
    try:
        response = requests.get(url, timeout=5)
        
        # Check HTTP status code (2XX, 3XX are considered valid)
        if not (200 <= response.status_code < 400):
            return f"{Fore.RED}[-] {url} is not live. Status code: {response.status_code}{Style.RESET_ALL}"

        output.append(f"{Fore.GREEN}[+] HTTP Header Analysis ({url}):{Style.RESET_ALL}")
        for header in SECURITY_HTTP_HEADERS:
            if header in response.headers:
                value = response.headers[header]
                is_vulnerable, recommendation = evaluate_header(header, value)
                if is_vulnerable:
                    output.append(f"    {Fore.RED}{header}: {value} - Vulnerable{Style.RESET_ALL}")
                    output.append(f"        {Fore.GREEN}Best Practice: {recommendation}{Style.RESET_ALL}")
                else:
                    output.append(f"    {Fore.GREEN}{header}: {value} - Secure{Style.RESET_ALL}")
            else:
                output.append(f"    {Fore.RED}{header}: Not Present - Vulnerable{Style.RESET_ALL}")
                output.append(f"        {Fore.GREEN}Best Practice: {best_practice_for_header(header)}{Style.RESET_ALL}")
    except requests.exceptions.RequestException:
        output.append(f"{Fore.RED}[-] Failed to fetch headers for {url}{Style.RESET_ALL}")
    return "\n".join(output)

def evaluate_header(header, value):
    """
    Evaluate a specific HTTP header and return its status and best practice recommendation.
    """
    if header == "Set-Cookie":
        if "Secure" not in value or "HttpOnly" not in value or "SameSite" not in value:
            return True, "Set Secure, HttpOnly, and SameSite attributes on cookies."
        return False, "Cookies are secure with recommended attributes."

    if header == "Content-Security-Policy":
        return True, "Use a strong CSP to mitigate XSS and other code injection attacks."
    if header == "Strict-Transport-Security":
        return True, "Set HSTS to enforce HTTPS connections with a long max-age and includeSubDomains."
    if header == "X-Content-Type-Options" and value != "nosniff":
        return True, "Set X-Content-Type-Options to 'nosniff' to prevent MIME-type sniffing."
    if header == "X-Frame-Options" and value not in ["DENY", "SAMEORIGIN"]:
        return True, "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent clickjacking."
    
    return False, "Header is configured as per best practices."

def best_practice_for_header(header):
    """
    Return the best practice recommendation for a specific HTTP header.
    """
    recommendations = {
        "Set-Cookie": "Set Secure, HttpOnly, and SameSite attributes on cookies.",
        "Content-Security-Policy": "Use a strong CSP to mitigate XSS and other code injection attacks.",
        "Strict-Transport-Security": "Set HSTS to enforce HTTPS connections with a long max-age and includeSubDomains.",
        "X-Content-Type-Options": "Set X-Content-Type-Options to 'nosniff' to prevent MIME-type sniffing.",
        "X-Frame-Options": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent clickjacking."
    }
    return recommendations.get(header, "No best practice available.")

def run_whatweb(url):
    """
    Runs WhatWeb on the given URL and returns the result.
    """
    try:
        result = subprocess.run(["whatweb", url], capture_output=True, text=True, check=True)
        return f"[i] WhatWeb Results for {url}:\n{result.stdout.strip()}"
    except FileNotFoundError:
        return f"{Fore.RED}[-] WhatWeb is not installed. Please install it to use this feature.{Style.RESET_ALL}"
    except subprocess.CalledProcessError as e:
        return f"{Fore.RED}[-] WhatWeb execution failed: {e.stderr}{Style.RESET_ALL}"
    except Exception as e:
        return f"{Fore.RED}[-] An error occurred while running WhatWeb: {e}{Style.RESET_ALL}"

def process_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    output = [f"============================================================",
              f"[i] Processing: {domain}",
              f"============================================================"]

    # WHOIS
    output.append(whois_lookup(domain))

    # NSLOOKUP
    output.append(nslookup(domain))

    # WhatWeb
    output.append(run_whatweb(f"http://{domain}"))
    output.append(run_whatweb(f"https://{domain}"))

    # HTTP Header Analysis
    output.append(analyze_http_headers(f"http://{domain}"))
    output.append(analyze_http_headers(f"https://{domain}"))

    return "\n".join(output)

def main():
    parser = argparse.ArgumentParser(description="Web Recon Tool with WhatWeb, WHOIS, and HTTP Headers Analysis")
    parser.add_argument("file", help="Path to the .txt file containing URLs or domains")
    args = parser.parse_args()

    try:
        with open(args.file, "r") as file:
            targets = [line.strip() for line in file.readlines()]
        for target in targets:
            print(process_url(target))
    except FileNotFoundError:
        print(f"{Fore.RED}File not found: {args.file}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
