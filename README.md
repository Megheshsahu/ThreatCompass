# ThreatCompass

**Navigate Your Security Landscape**

ThreatCompass is a professional-grade Python security reconnaissance and vulnerability assessment tool designed for penetration testers, security researchers, and bug bounty hunters. It automates the entire reconnaissance workflow from subdomain discovery to vulnerability detection with comprehensive reporting.

## Features

- **Dynamic Subdomain Enumeration** - Automated DNS bruteforcing with 56+ common subdomains
- **Advanced Port Scanning** - Nmap integration with service version detection and OS fingerprinting
- **Threat Intelligence Integration** - Real-time queries to Shodan and Censys databases
- **CVE Vulnerability Detection** - Automated NVD API lookups with CVSS risk scoring
- **Multi-Phase Reconnaissance** - 5-phase scanning workflow for complete attack surface mapping
- **Stealth Scanning Capabilities** - Fragmented packets and timing controls to evade IDS/IPS
- **Professional Report Generation** - HTML and JSON formats with risk categorization
- **Concurrent Multi-Target Scanning** - Thread-based parallel processing for efficiency

## Installation

### Prerequisites
- Python 3.9 or higher
- Nmap (highly recommended for full functionality)

### Quick Install

1. Clone the repository:
```bash
git clone https://github.com/Megheshsahu/ThreatCompass.git
cd ThreatCompass
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install Nmap (platform-specific):

**Windows:**
- Download from https://nmap.org/download.html
- Add to PATH environment variable

**Linux:**
```bash
sudo apt-get install nmap  # Debian/Ubuntu
sudo yum install nmap      # CentOS/RHEL
```

**macOS:**
```bash
brew install nmap
```

## Usage

Run the tool:

### Basic Scan
```bash
python main.py --target example.com
```

### Full Reconnaissance with All Features
```bash
python main.py --target example.com --enumerate-subdomains --threat-intel --out results
```

### Stealth Scan (Evasion Mode)
```bash
python main.py --target example.com --stealth --out stealth_results
```

### Scan Multiple Targets
```bash
python main.py --target-list targets.txt --out batch_results
```

### Deep Vulnerability Scan
```bash
python main.py --target example.com \
  --enumerate-subdomains \
  --threat-intel \
  --nmap-args "-p- -sV -sC -O -A --script=vuln" \
  --out deep_scan
```

## Configuration

### API Keys (Optional but Recommended)

ThreatCompass integrates with external threat intelligence services for enhanced results:

**Shodan API:**
1. Create account at https://account.shodan.io/
2. Get API key from dashboard
3. Use with: `--shodan-api-key YOUR_KEY`

**Censys API:**
1. Register at https://search.censys.io/account/api
2. Obtain API ID and Secret
3. Use with: `--censys-api-id ID --censys-api-secret SECRET`

**NVD (CVE Database):**
1. Request key at https://nvd.nist.gov/developers/request-an-api-key
2. Use with: `--nvd-api-key YOUR_KEY`

## Command-Line Options

```
Targeting:
  --target TARGET              Single target (domain or IP address)
  --target-list FILE           File containing multiple targets (one per line)

Reconnaissance:
  --enumerate-subdomains       Enable subdomain enumeration via DNS bruteforce
  --no-subdomains              Disable subdomain enumeration
  --threat-intel               Query Shodan/Censys for threat intelligence
  --no-threat-intel            Skip threat intelligence gathering

Scanning:
  --nmap-args ARGS             Custom Nmap arguments (default: -sV -sC -O -T4)
  --top-ports N                Scan only top N ports instead of full scan
  --nmap-timeout SECONDS       Nmap scan timeout in seconds (default: 900)
  --stealth                    Enable stealth mode with packet fragmentation

API Integration:
  --shodan-api-key KEY         Shodan API key for enhanced threat data
  --censys-api-id ID           Censys API ID
  --censys-api-secret SECRET   Censys API secret
  --nvd-api-key KEY            NVD API key for CVE lookups

Output:
  --out DIRECTORY              Output directory for reports (default: out)
  --format FORMAT              Report format: json, html, or both (default: json,html)
  --workers N                  Number of concurrent target workers (default: 4)
```

## Output & Reports

ThreatCompass generates comprehensive reports in two formats:

**HTML Report:**
- Interactive, color-coded vulnerability dashboard
- Risk severity visualization (Critical, High, Medium, Low)
- Service and port details with CVE mappings
- Threat intelligence data integration
- Recommended remediation actions

**JSON Report:**
- Machine-readable structured data
- API integration ready
- Automated pipeline compatible
- Complete scan metadata and findings

Report Contents:
- Target profile (DNS, WHOIS, IP resolution)
- Discovered subdomains with status
- Open ports and running services
- Detected vulnerabilities with CVSS scores
- Threat intelligence findings
- Risk assessment and prioritization

## Technical Architecture

**Reconnaissance Phases:**
1. **Target Profiling** - DNS resolution, WHOIS lookup, subdomain enumeration
2. **Threat Intelligence** - Shodan and Censys database queries
3. **Active Scanning** - Nmap port scanning with service detection
4. **Vulnerability Assessment** - CVE lookups and CVSS scoring
5. **Report Generation** - HTML and JSON output with risk categorization

**Core Technologies:**
- Python 3.9+ with type hints
- Nmap for network scanning
- DNSPython for DNS operations
- Shodan & Censys Python SDKs
- NVD API for CVE data
- Jinja2 for report templating
- Multi-threading for performance

## Use Cases

- **Penetration Testing** - Initial reconnaissance phase
- **Bug Bounty Hunting** - Asset discovery and attack surface mapping
- **Security Audits** - Comprehensive infrastructure assessment
- **Red Team Operations** - Target profiling and intelligence gathering
- **Vulnerability Research** - CVE correlation and risk analysis
- **Compliance Reporting** - Security posture documentation

## Legal Disclaimer

**IMPORTANT:** This tool is designed for authorized security testing only. 

⚠️ You must have explicit permission to scan any target systems. Unauthorized scanning may be illegal in your jurisdiction and could result in criminal charges. The authors assume no liability for misuse or damage caused by this program.

**Use responsibly and ethically.**

## Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and create pull requests for:
- Bug fixes
- New features
- Documentation improvements
- Performance optimizations

## License

This project is licensed under a **Custom License - Attribution-NonCommercial**. You may use, modify, and share the project with proper credit, but you may not earn money from it without permission. Contact **megheshkumarsahu@gmail.com** for commercial licensing. See the [LICENSE](LICENSE) file for full terms.

## Author

Developed by Meghesh Sahu
- GitHub: [@Megheshsahu](https://github.com/Megheshsahu)

## Acknowledgments

ThreatCompass integrates and builds upon several open-source tools and APIs:
- Nmap - Network scanning framework
- Shodan - Internet intelligence platform
- Censys - Attack surface management
- NVD - National Vulnerability Database

---

**ThreatCompass** - Navigate Your Security Landscape
