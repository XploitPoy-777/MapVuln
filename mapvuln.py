#!/usr/bin/env python3
import argparse
import requests
import re
import json
import os
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import sys
from datetime import datetime

# Colors for console output
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Sensitive patterns to check
SENSITIVE_DIRS = [
    # Admin and Management
    '/admin', '/administrator', '/admin_panel', '/admin-console', '/manager', '/controlpanel',    
    # Configuration and Setup
    '/config', '/configuration', '/settings', '/setup', '/install', '/init',    
    # Development and Testing
    '/dev', '/development', '/debug', '/test', '/testing', '/staging', '/qa',    
    # Internal and Private Areas
    '/internal', '/private', '/restricted', '/secure', '/hidden', '/vault',    
    # Backup and Old Content
    '/backup', '/backups', '/bkp', '/archive', '/old', '/previous', '/tmp', '/dump',    
    # API and Frameworks
    '/graphql', '/api', '/api/v1/', '/api/v2/', '/v1/', '/v2/', '/v0/', '/rest', '/webapi',    
    # Health and Monitoring
    '/health', '/healthz', '/status', '/metrics', '/monitor', '/uptime', '/debug/status',    
    # Information and Logs
    '/info', '/systeminfo', '/version', '/changelog', '/readme', '/logs', '/logviewer',    
    # Misc
    '/console', '/shell', '/cli', '/cmd', '/scripts', '/actuator', '/ws', '/adminapi'
]

SENSITIVE_PARAMS = [
    # Authentication and Tokens
    'token=', 'access_token=', 'auth=', 'auth_token=', 'apikey=', 'api_key=', 'key=', 'secret=',   
    # Login and Credentials
    'username=', 'user=', 'password=', 'pass=', 'credential=', 'login=', 'email=', 'pwd=', 'session=',    
    # Debug and Testing
    'debug=', 'test=', 'env=', 'dev=', 'stage=', 'mock=', 'example=', 'sandbox=', 'preview=',    
    # Internal/Custom Parameters
    'internal=', 'admin=', 'config=', 'file=', 'path=', 'url=', 'next=', 'redirect=',    
    # Tokens and Sessions
    'sid=', 'sessionid=', 'sessid=', 'jwt=', 'bearer=', 'token_type=', 'refresh_token=',    
    # Payment / Financial
    'card_number=', 'credit_card=', 'ccn=', 'ssn=', 'billing=', 'payment_id=', 'iban=', 'routing='
]

SENSITIVE_EXTENSIONS = [
    # Archives & Backups
    '.zip', '.tar', '.tar.gz', '.gz', '.rar', '.7z', '.bak', '.backup', '.old',    
    # Configs & Envs
    '.env', '.config', '.conf', '.ini', '.yaml', '.yml', '.xml', '.properties', '.toml',   
    # Logs & Reports
    '.log', '.out', '.report', '.trace', '.dump', '.core',    
    # Source Code & Packages
    '.php', '.py', '.java', '.rb', '.go', '.js', '.ts', '.sql', '.db', '.sqlite', '.class',    
    # JSON & Sensitive Metadata
    '.json', '.lock', '.pem', '.crt', '.cert', '.p12', '.key', '.pub', '.csr',    
    # Misc
    '.swp', '.DS_Store', '.bak1', '.old1', '.debug', '.err'
]

VERSION_CONTROL = [
    '.git/', '.git/config', '.gitignore', '.gitattributes', '.gitmodules',
    '.svn/', '.svn/entries', '.svn/wc.db',
    '.hg/', '.hg/hgrc',
    '.bzr/', '.bzr/branch-format',
    '/CVS/', '/CVS/Root', '.fossil-settings/', '_darcs/',
    '.pijul/', '.monotone/', '.metadata/', '.idea/', '.vscode/', '.nvmrc'
]

# Common sitemap locations
COMMON_SITEMAPS = [
    'sitemap.xml',
    'sitemap_index.xml',
    'sitemap-index.xml',
    'sitemap.txt',
    'sitemap.php',
    'sitemap.xml.gz',
    'sitemap/sitemap.xml',
    'sitemap/sitemap_index.xml',
    'sitemap/sitemap-index.xml',
    'sitemap/index.xml',
    'sitemap1.xml', 'sitemap2.xml', 'sitemap3.xml',
    'wp-sitemap.xml',
    'drupal_sitemap.xml',
    'joomla_sitemap.xml',
    'typo3_sitemap.xml',
    'mage_sitemap.xml',
    'prestashop_sitemap.xml',
    'shopify_sitemap.xml',
    'seo_sitemap.xml',
    'google_sitemap.xml',
    'bing_sitemap.xml',
    'custom_sitemap.xml',
    'sitemap_dev.xml',
    'sitemap_test.xml',
    'sitemap_old.xml',
    'sitemap_bak.xml',
    'sitemap~',
    'sitemap.json',
    'sitemap.yml',
    'sitemap.xml.gz',
    'sitemap_index.xml.gz',
    'sitemap-index.xml.gz',
    'sitemap1.xml.gz',
    'sitemap_part1.xml',
    'sitemap_part2.xml',
    'sitemap-news.xml',
    'sitemap-video.xml'
]

# API endpoint patterns
API_KEYWORDS = [
    '/api/', '/rest/', '/graphql', '/rpc/', '/webapi/', '/jsonapi/', '/oas/',    
    '/v1/', '/v2/', '/v3/', '/v4/', '/v0/', '/v1.0/', '/v2.0/', '/v1.1/',    
    '/api-docs/', '/swagger/', '/openapi.json', '/openapi.yaml', '/swagger.json', '/swagger.yaml',    
    '/api/user/', '/api/users/', '/api/admin/', '/api/auth/', '/api/login/', '/api/register/',
    '/api/token/', '/api/session/', '/api/account/', '/api/profile/', '/api/data/', '/api/search/',    
    '/internal-api/', '/admin-api/', '/private-api/', '/debug-api/', '/beta-api/',    
    '/mobile-api/', '/client-api/', '/frontend-api/', '/public-api/',    
    '/graphql/', '/graphiql/', '/gql/', '/playground/',   
    '/action/', '/invoke/', '/exec/', '/command/', '/service/', '/handler/',   
    '/api/github/', '/api/slack/', '/api/aws/', '/api/stripe/', '/api/payment/',    
    '/Api/', '/API/', '/apiV1/', '/apiV2/', '/RestApi/', '/GraphQL/', '/Graphql/'
]

# Debug endpoint patterns
DEBUG_KEYWORDS = [
    '/debug/', '/debug-console/', '/debug/info', '/debug/vars', '/debug/status',
    '/console/', '/admin/console', '/system/console', '/dev-console', '/cli/',
    '/info', '/status', '/system/status', '/server-status', '/app/status', 
    '/health', '/healthz', '/healthcheck', '/actuator/health', '/system/health',
    '/internal/status', '/internal/info', '/internal/debug', '/test/status',
    '/__debug__/', '/__status__/', '/__info__/', '/_debug/', '/_status/', '/_info/',
    '/actuator/', '/actuator/info', '/actuator/metrics', '/actuator/env',
    '/actuator/configprops', '/actuator/loggers', '/actuator/beans',
    '/flask-debug/', '/django-debug/', '/debug-toolbar/', '/__debug__/',
    '/dev/debug/', '/dev/status/', '/dev/info/', '/api/debug/', '/debug/api/',
    '/metrics', '/ready', '/readyz', '/live', '/livez', '/readiness', '/liveness',
    '/playground', '/graphiql', '/graphql-playground/', '/debug/graphql',
    '/env', '/version', '/vars', '/dump', '/trace', '/threads', '/heapdump', 
    '/logs', '/log', '/logging', '/profiling', '/diagnostics'
]

# Redirect parameter patterns
REDIRECT_KEYWORDS = [
    'url=',
    'redirect=',
    'next=',
    'target=',
    'return=',
    'return_url=',
    'dest=',
    'destination=',
    'redir=',
    'redirect_url=',
    'redirect_uri=',
    'redirect_to=',
    'goto=',
    'out=',
    'view=',
    'continue=',
    'forward=',
    'navigation=',
    'path=',
    'file=',
    'location=',
    'ref=',
    'referrer=',
    'spring-redirect=',
    'nextUrl=',
    'nextPath=',
    'urlPath=',
    'redirUrl=',
    'retUrl=',
    'returnTo=',
    'to=',
    'r=',
    'u=',
    'callback=',
    'back=',
    'home=',
    'loadUrl=',
    'viewUrl=',
    'open=',
    'link='
]

# Leak patterns
LEAK_PATTERNS = [
    'api_key', 'apikey', 'secret', 'password', 'passwd', 'passphrase',
    'credential', 'credentials', 'auth_token', 'access_token', 'refresh_token',
    'session_token', 'auth', 'authentication_token', 'authorization_token',
    'token', 'secret_key', 'access_key', 'client_secret', 'client_id',
    'secret_token', 'auth_key', 'key_secret', 'security_key',
    'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token',
    'azure_client_id', 'azure_client_secret', 'azure_tenant_id',
    'gcp_project_id', 'gcp_private_key', 'gcp_client_email',
    'google_api_key', 'firebase_api_key', 'firebase_secret',
    'db_password', 'db_pass', 'database_password', 'database_url',
    'db_connection_string', 'sql_connection', 'mysql_pwd', 'pg_password',
    'mongo_uri', 'mongodb_password', 'redis_password',
    'rsa_private_key', 'ssh_private_key', 'ssh_key', 'id_rsa',
    'private_key', 'public_key', 'pem_key', 'dsa_key', 'tls_private_key',
    'gpg_private_key', 'encryption_key', 'signing_key', 'pfx_password',
    'vault_token', 'vault_secret', 'vault_key',
    'ansible_vault_password', 'jenkins_token', 'travis_token',
    'circleci_token', 'github_token', 'gitlab_token', 'bitbucket_token',
    'docker_password', 'docker_auth', 'npm_token', 'pypi_token',
    'slack_token', 'discord_token', 'telegram_token',
    'stripe_secret_key', 'stripe_publishable_key',
    'paypal_secret', 'twilio_auth_token', 'sendgrid_api_key',
    'mailgun_api_key', 'zoom_jwt_token', 'okta_token', 'datadog_api_key',
    'webhook_secret', 'webhook_url', 'app_secret', 'bot_token',
    'api_token', 'api_secret', 'consumer_key', 'consumer_secret',
    'app_key', 'application_key', 'integration_token',
    'smtp_password', 'email_password', 'ftp_password',
    'admin_password', 'root_password', 'service_account_key',
    'machine_token', 'proxy_password', 'wifi_password',
    'netrc_password', 'windows_password', 'mac_password'
]

# Vulnerability type names
VULN_NAMES = {
    'sensitive_directories': 'sensitive directory',
    'sensitive_params': 'sensitive parameter',
    'backup_files': 'backup file',
    'version_control': 'version control exposure',
    'api_endpoints': 'api endpoint',
    'debug_endpoints': 'debug endpoint',
    'potential_leaks': 'potential credential leak',
    'misconfigured_redirects': 'misconfigured redirect',
    'graphql_endpoints': 'graphql endpoint'
}

# Results storage
results = {
    'target': '',
    'vulnerabilities': {
        'sensitive_directories': set(),
        'sensitive_params': set(),
        'backup_files': set(),
        'version_control': set(),
        'api_endpoints': set(),
        'debug_endpoints': set(),
        'potential_leaks': set(),
        'misconfigured_redirects': set(),
        'graphql_endpoints': set()
    },
    'sitemaps_tested': [],
    'timestamp': datetime.now().isoformat()
}

# Session with custom headers
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive'
})

def print_banner():
    print(f"""{colors.BLUE}
  ___  ___            _   _       _       
  |  \\/  |           | | | |     | |      
  | .  . | __ _ _ __ | | | |_   _| |_ __  
  | |\\/| |/ _` | '_ \\| | | | | | | | '_ \\ 
  | |  | | (_| | |_) \\ \\_/ / |_| | | | | |
  \\_|  |_/\\__,_| .__/ \\___/ \\__,_|_|_| |_|
               | |                        
               |_|                        
{colors.YELLOW}                      {colors.RED}[By XploitPoy-777]{colors.YELLOW}{colors.RESET}
""")
    print(f"{colors.YELLOW}Sitemap.xml Vulnerability Scanner{colors.RESET}")
    print(f"{colors.CYAN}Version: 2.4 | Final Release{colors.RESET}\n")

def print_help():
    print(f"{colors.BOLD}Usage:{colors.RESET}")
    print("  python sitemap_scanner.py -u https://example.com")
    print("  python sitemap_scanner.py -i urls.txt -o vulns.json")
    print("\nOptions:")
    print("  -u, --url         Single URL to scan")
    print("  -i, --input       File containing list of URLs to scan")
    print("  -o, --output      Output file (JSON format)")
    print("  -p, --proxy       Proxy to use (e.g., http://127.0.0.1:8080)")
    print("  -t, --threads     Number of threads (default: 5)")
    print("  -h, --help        Show this help message")
    print("\nExample:")
    print("  python sitemap_scanner.py -u https://example.com -o vulns.json -p http://localhost:8080")

def setup_proxy(proxy_url):
    if proxy_url:
        print(f"{colors.YELLOW}[*] Using proxy: {proxy_url}{colors.RESET}")
        session.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }

def get_sitemap_urls(base_url):
    """Discover sitemap URLs from common locations"""
    sitemap_urls = []
    for sitemap in COMMON_SITEMAPS:
        url = urljoin(base_url, sitemap)
        try:
            response = session.get(url, timeout=10)
            if response.status_code == 200 and ('xml' in response.headers.get('Content-Type', '') or 'text/xml' in response.headers.get('Content-Type', '')):
                sitemap_urls.append(url)
                print(f"{colors.GREEN}[+] Found sitemap: {url}{colors.RESET}")
        except requests.RequestException:
            continue
    
    return sitemap_urls if sitemap_urls else [urljoin(base_url, 'sitemap.xml')]

def parse_sitemap(sitemap_url):
    """Parse sitemap XML and extract URLs, handling nested sitemaps recursively"""
    try:
        response = session.get(sitemap_url, timeout=10)
        if response.status_code == 200:
            results['sitemaps_tested'].append(sitemap_url)
            
            if '<sitemapindex' in response.text.lower():
                print(f"{colors.YELLOW}[*] Found sitemap index: {sitemap_url}{colors.RESET}")
                nested_sitemaps = re.findall(r'<loc>(.*?)</loc>', response.text, re.IGNORECASE)
                all_urls = set()
                
                for nested_sitemap in nested_sitemaps:
                    print(f"{colors.YELLOW}[*] Processing nested sitemap: {nested_sitemap}{colors.RESET}")
                    nested_urls = parse_sitemap(nested_sitemap)
                    if nested_urls:
                        all_urls.update(nested_urls)
                return list(all_urls)
            
            urls = re.findall(r'<loc>(.*?)</loc>', response.text, re.IGNORECASE)
            return list(set(urls))
        return []
    except requests.RequestException as e:
        print(f"{colors.RED}[-] Error parsing sitemap {sitemap_url}: {str(e)}{colors.RESET}")
        return []

def check_url_access(url, check_redirects=False):
    """Check if URL returns 200, 403, or (optionally) 302 status code"""
    try:
        response = session.get(url, timeout=10, allow_redirects=False)
        if check_redirects:
            if response.status_code in [200, 302, 403]:
                return True, response.status_code
        else:
            if response.status_code in [200, 403]:
                return True, response.status_code
        return False, response.status_code
    except requests.RequestException:
        return False, None

def print_vulnerability(vuln_type, url, status_code):
    """Print vulnerability with exact requested formatting"""
    status_color = colors.GREEN if status_code == 200 else colors.YELLOW
    print(
        f"{colors.YELLOW}[!]{colors.RESET} "
        f"{colors.WHITE}Found {colors.RED}{VULN_NAMES[vuln_type]}{colors.RESET} "
        f"{colors.WHITE}({status_color}HTTP {status_code}{colors.RESET}) "
        f"{colors.WHITE}{url}{colors.RESET}"
    )

def check_sensitive_directories(url):
    """Check for sensitive directories in URL path"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    for directory in SENSITIVE_DIRS:
        if directory.lower() in path:
            accessible, status_code = check_url_access(url)
            if accessible:
                vuln_str = f"{url} (HTTP {status_code})"
                if vuln_str not in results['vulnerabilities']['sensitive_directories']:
                    results['vulnerabilities']['sensitive_directories'].add(vuln_str)
                    print_vulnerability('sensitive_directories', url, status_code)
                return True
    return False

def check_sensitive_params(url):
    """Check for sensitive parameters in URL"""
    parsed = urlparse(url)
    query = parsed.query.lower()
    
    for param in SENSITIVE_PARAMS:
        if param.lower() in query:
            accessible, status_code = check_url_access(url)
            if accessible:
                vuln_str = f"{url} (HTTP {status_code})"
                if vuln_str not in results['vulnerabilities']['sensitive_params']:
                    results['vulnerabilities']['sensitive_params'].add(vuln_str)
                    print_vulnerability('sensitive_params', url, status_code)
                return True
    return False

def check_backup_files(url):
    """Check for backup or log files in URL"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    for ext in SENSITIVE_EXTENSIONS:
        if path.endswith(ext.lower()):
            accessible, status_code = check_url_access(url)
            if accessible:
                vuln_str = f"{url} (HTTP {status_code})"
                if vuln_str not in results['vulnerabilities']['backup_files']:
                    results['vulnerabilities']['backup_files'].add(vuln_str)
                    print_vulnerability('backup_files', url, status_code)
                return True
    return False

def check_version_control(url):
    """Check for version control exposure in URL"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    for vc in VERSION_CONTROL:
        if vc.lower() in path:
            accessible, status_code = check_url_access(url)
            if accessible:
                vuln_str = f"{url} (HTTP {status_code})"
                if vuln_str not in results['vulnerabilities']['version_control']:
                    results['vulnerabilities']['version_control'].add(vuln_str)
                    print_vulnerability('version_control', url, status_code)
                return True
    return False

def check_api_endpoints(url):
    """Check for API endpoints"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    for keyword in API_KEYWORDS:
        if keyword.lower() in path:
            accessible, status_code = check_url_access(url)
            if accessible:
                vuln_str = f"{url} (HTTP {status_code})"
                if vuln_str not in results['vulnerabilities']['api_endpoints']:
                    results['vulnerabilities']['api_endpoints'].add(vuln_str)
                    print_vulnerability('api_endpoints', url, status_code)
                
                if 'graphql' in path and vuln_str not in results['vulnerabilities']['graphql_endpoints']:
                    results['vulnerabilities']['graphql_endpoints'].add(vuln_str)
                    print_vulnerability('graphql_endpoints', url, status_code)
                
                return True
    return False

def check_debug_endpoints(url):
    """Check for debug endpoints"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    for keyword in DEBUG_KEYWORDS:
        if keyword.lower() in path:
            accessible, status_code = check_url_access(url)
            if accessible:
                vuln_str = f"{url} (HTTP {status_code})"
                if vuln_str not in results['vulnerabilities']['debug_endpoints']:
                    results['vulnerabilities']['debug_endpoints'].add(vuln_str)
                    print_vulnerability('debug_endpoints', url, status_code)
                return True
    return False

def check_redirects(url):
    """Check for misconfigured redirects"""
    parsed = urlparse(url)
    query = parsed.query.lower()
    
    for keyword in REDIRECT_KEYWORDS:
        if keyword.lower() in query:
            accessible, status_code = check_url_access(url, check_redirects=True)
            if accessible:
                vuln_str = f"{url} (HTTP {status_code})"
                if vuln_str not in results['vulnerabilities']['misconfigured_redirects']:
                    results['vulnerabilities']['misconfigured_redirects'].add(vuln_str)
                    print_vulnerability('misconfigured_redirects', url, status_code)
                return True
    return False

def check_for_leaks(url):
    """Check for potential credential leaks in JS/JSON files"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    if path.endswith('.js') or path.endswith('.json') or path.endswith('.env'):
        accessible, status_code = check_url_access(url)
        if accessible:
            try:
                response = session.get(url, timeout=10)
                if response.status_code == 200:
                    content = response.text.lower()
                    for pattern in LEAK_PATTERNS:
                        if pattern in content:
                            vuln_str = f"{url} (HTTP {status_code})"
                            if vuln_str not in results['vulnerabilities']['potential_leaks']:
                                results['vulnerabilities']['potential_leaks'].add(vuln_str)
                                print_vulnerability('potential_leaks', url, status_code)
                            return True
            except requests.RequestException:
                pass
    return False

def test_url(url):
    """Run all checks against a single URL"""
    check_sensitive_directories(url)
    check_sensitive_params(url)
    check_backup_files(url)
    check_version_control(url)
    check_api_endpoints(url)
    check_debug_endpoints(url)
    check_redirects(url)
    check_for_leaks(url)

def scan_sitemap(target_url, threads=5):
    """Main scanning function"""
    print(f"\n{colors.BOLD}[*] Scanning: {target_url}{colors.RESET}")
    results['target'] = target_url
    
    sitemap_urls = get_sitemap_urls(target_url)
    all_urls = []
    for sitemap_url in sitemap_urls:
        urls = parse_sitemap(sitemap_url)
        if urls:
            all_urls.extend(urls)
    
    if not all_urls:
        print(f"{colors.YELLOW}[-] No URLs found in any sitemaps{colors.RESET}")
        return
    
    unique_urls = list(set(all_urls))
    print(f"{colors.YELLOW}[*] Testing {len(unique_urls)} unique URLs across {len(results['sitemaps_tested'])} sitemaps{colors.RESET}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(test_url, unique_urls)
    
    for vuln_type in results['vulnerabilities']:
        results['vulnerabilities'][vuln_type] = sorted(list(results['vulnerabilities'][vuln_type]))

def save_results(output_file):
    """Save results to JSON file"""
    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"{colors.GREEN}[+] Vulnerabilities saved to {output_file}{colors.RESET}")
        except IOError as e:
            print(f"{colors.RED}[-] Error saving results: {str(e)}{colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description='Sitemap.xml Vulnerability Scanner', add_help=False)
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-i', '--input', help='File containing list of URLs to scan')
    parser.add_argument('-o', '--output', help='Output file (JSON format)')
    parser.add_argument('-p', '--proxy', help='Proxy to use (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    
    args = parser.parse_args()
    
    if args.help or (not args.url and not args.input):
        print_banner()
        print_help()
        sys.exit(0)
    
    print_banner()
    
    if args.proxy:
        setup_proxy(args.proxy)
    
    targets = []
    if args.url:
        targets.append(args.url)
    elif args.input:
        try:
            with open(args.input, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except IOError as e:
            print(f"{colors.RED}[-] Error reading input file: {str(e)}{colors.RESET}")
            sys.exit(1)
    
    for target in targets:
        scan_sitemap(target, args.threads)
    
    if any(len(v) > 0 for v in results['vulnerabilities'].values()):
        if args.output:
            save_results(args.output)
        else:
            print(f"\n{colors.BOLD}Vulnerabilities Found:{colors.RESET}")
            print(json.dumps(results, indent=4))
    else:
        print(f"{colors.GREEN}[+] No vulnerabilities found across all sitemaps{colors.RESET}")

if __name__ == '__main__':
    main()
