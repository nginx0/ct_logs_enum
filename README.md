This script fetches certificates from crt.sh to identify associated subdomains, extracts and verifies these subdomains, performs SSL/TLS configuration checks, and tests for various web vulnerabilities using common payloads


git clone https://github.com/nginx0/ct_logs_enum.git
cd ct_logs_enum
python ct_logs_enum.py

A report will be generated in a file named vulnerability_report.txt.

