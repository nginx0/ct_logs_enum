## Overview

This script fetches certificates from crt.sh to identify associated subdomains, extracts and verifies these subdomains, performs SSL/TLS configuration checks, and tests for various web vulnerabilities using common payloads.

## Installation 

1. Clone the repository:

    ```bash
    git clone https://github.com/nginx0/ct_logs_enum.git
    ```

2. Navigate into the directory:

    ```bash
    cd ct_logs_enum
    ```

3. Run the script:

    ```bash
    python ct_logs_enum.py
    ```

A report will be generated in a file named `vulnerability_report.txt`.
