<h1 align="center">「🐦‍🔥」 MapVuln - Advanced security tool for uncovering hidden vulnerabilities through sitemap analysis</h1>

<p align="center"><img src="assets/Screenshot_2025.png"></p>

## Connect

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/zabed-ullah-poyel/)
[![Medium](https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white)](https://medium.com/@zabedullahpoyel)
[![YouTube](https://img.shields.io/badge/YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://www.youtube.com/@XploitPoy-777)
[![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://x.com/zabedullahpoyel)
[![Website](https://img.shields.io/badge/Website-000000?style=for-the-badge&logo=About.me&logoColor=white)](https://zabedullahpoyel.com)
[![Gmail](https://img.shields.io/badge/Gmail-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:zabedullahpoyelcontact@gmail.com)

---

## Description
A powerful Python tool that systematically analyzes website sitemaps to identify security weaknesses, including exposed admin panels, API endpoints, debug interfaces, and sensitive files. Perfect for penetration testers and security researchers.

## Features
- Multi-threaded scanning for rapid results
- Smart sitemap discovery (`50+ common locations`)
- Comprehensive vulnerability detection:
  - Sensitive directories (`admin panels, config files . etc`)
  - Backup/compressed files (`.zip, .bak, .tar.gz . etc`)
  - Version control exposures (`.git/, .svn/ . etc`)
  - API endpoints (`REST, GraphQL, Swagger . etc`)
  - Debug interfaces and health checks
  - Open redirect vulnerabilities
  - Credential leaks in `JS/JSON` files
- JSON output for easy integration
- Proxy support (Burp/OWASP ZAP compatible)

![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Installation Instructions
```bash
# Clone the repository:
git clone https://github.com/XploitPoy-777/MapVuln.git
cd MapVuln

# Install 
pip install -r requirements.txt --break-system-packages

# Make the script executable:
chmod +x mapvuln.py
```

## Usage Instructions
```bash
# One-Line Advanced Usage
python mapvuln.py -u https://example.com -o vulns.json -p http://127.0.0.1:8080 -t 15 --timeout 30

# Basic Scan
python mapvuln.py -u https://example.com
# Scan Multiple Sites from File
python mapvuln.py -i urls.txt -o results.json
```

## Options
| Option	              | Description  | 
|-----------------------|--------------|
| -u                    | URL Scan single URL
| -i                    | INPUT_FILE	File containing list of URLs
| -o                    | OUTPUT_FILE	Save results to JSON file
| -p                    | PROXY	Use proxy (e.g., http://127.0.0.1:8080)
| -t                    | THREADS	Number of threads (default: 5)
| -h	                  | Show help message

## Output 

The tool generates a JSON report containing:

- Target URL
- List of tested sitemaps
- Found vulnerabilities (categorized)
- HTTP status codes for each finding
- Timestamp of the scan
Example structure:
```json
{
  "target": "https://example.com",
  "sitemaps_tested": ["https://example.com/sitemap.xml"],
  "vulnerabilities": {
    "sensitive_directories": ["https://example.com/admin (HTTP 200)"],
    "api_endpoints": ["https://example.com/api/v1/users (HTTP 200)"]
  },
  "timestamp": "2023-11-15T12:34:56.789Z"
}
```

```plaintext
[!] Found sensitive directory (HTTP 200) https://example.com/admin
[!] Found API endpoint (HTTP 200) https://example.com/api/v1/users
[!] Found potential credential leak (HTTP 200) https://example.com/config.json
[+] Scan completed. 3 vulnerabilities found.
```

## 🔔 Reminder
- **⚠ Use responsibly** - Only scan websites you have permission to test
- **⚠ Not a stealthy tool** - May generate noticeable traffic
- **⚠ Verify findings manually** - Some results may be false positives


