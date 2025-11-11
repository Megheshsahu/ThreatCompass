# 🧭 ThreatCompass

**Navigate Your Security Landscape**

A professional-grade Python reconnaissance and vulnerability assessment tool that automates security assessments, performs subdomain enumeration, integrates threat intelligence APIs, conducts port scanning, and generates comprehensive reports.

## 🚀 Features

- **🔍 Subdomain Enumeration** - Discover subdomains with DNS bruteforcing
- **🌐 Port Scanning** - Full port scanning with Nmap integration
- **🛡️ Threat Intelligence** - Shodan & Censys API integration
- **🐛 CVE Detection** - Automated vulnerability lookups with CVSS scoring
- **🎯 Risk Assessment** - Intelligent risk scoring and categorization
- **📊 Comprehensive Reports** - Beautiful HTML and JSON reports
- **🥷 Stealth Mode** - Evasion techniques to avoid detection
- **⚡ Multi-threaded** - Concurrent scanning for speed

## 📦 Installation

### Quick Install
```bash
pip install -r requirements.txt
```

### External Dependencies
**Nmap (Required for scanning)**
- Windows: Download from https://nmap.org/download.html
- Linux: `sudo apt-get install nmap`
- macOS: `brew install nmap`

## 🎯 Usage

### Basic Scan
```bash
python main.py --target example.com
```

### Full Reconnaissance
```bash
python main.py --target example.com --enumerate-subdomains --threat-intel --out results
```

### Stealth Scan
```bash
python main.py --target example.com --stealth --out stealth_results
```

### Multiple Targets
```bash
python main.py --target-list targets.txt --out batch_results
```

### Deep Scan with Vulnerability Detection
```bash
python main.py --target example.com --enumerate-subdomains --threat-intel --nmap-args "-p- -sV -sC -O -A --script=vuln" --out deep_scan
```

## 📖 Options

```
--target TARGET              Single target (domain or IP)
--target-list FILE           File with multiple targets
--enumerate-subdomains       Enable subdomain enumeration
--threat-intel               Query Shodan/Censys for threat intelligence
--stealth                    Use stealth scanning techniques
--nmap-args ARGS             Custom Nmap arguments
--top-ports N                Scan only top N ports (faster)
--out FOLDER                 Output directory (default: out)
--format json,html           Report format
--shodan-api-key KEY         Shodan API key
--censys-api-id ID           Censys API ID
--censys-api-secret SECRET   Censys API secret
--nvd-api-key KEY            NVD API key for CVE lookups
```

## 🔑 API Keys (Optional but Recommended)

### Shodan
1. Sign up at https://account.shodan.io/
2. Get your API key
3. Use with: `--shodan-api-key YOUR_KEY`

### Censys
1. Sign up at https://search.censys.io/account/api
2. Get API ID and Secret
3. Use with: `--censys-api-id ID --censys-api-secret SECRET`

### NVD
1. Request API key at https://nvd.nist.gov/developers/request-an-api-key
2. Use with: `--nvd-api-key YOUR_KEY`

## 📊 Example Output

ThreatCompass generates two types of reports:

- **HTML Report** - Beautiful, interactive report with risk visualization
- **JSON Report** - Machine-readable data for automation

Reports include:
- Target information and WHOIS data
- Discovered subdomains
- Open ports and services
- Detected vulnerabilities (CVEs)
- Risk scores and severity levels
- Threat intelligence data
- Recommended actions

## 🛠️ Technical Details

**Built With:**
- Python 3.9+
- Nmap for port scanning
- Shodan & Censys APIs for threat intelligence
- NVD API for CVE lookups
- Multi-threading for performance
- Jinja2 for report generation

**Scanning Phases:**
1. **Target Profiling** - DNS/WHOIS and subdomain enumeration
2. **Threat Intelligence** - Shodan/Censys queries
3. **Active Scanning** - Nmap port and service detection
4. **Vulnerability Assessment** - CVE lookups and risk scoring
5. **Report Generation** - HTML and JSON output

## 🎓 Use Cases

- **Bug Bounty Hunting** - Discover attack surface
- **Penetration Testing** - Initial reconnaissance
- **Security Audits** - Comprehensive assessments
- **Asset Discovery** - Map your infrastructure
- **Compliance** - Security posture reporting

## ⚠️ Legal Disclaimer

**IMPORTANT:** Only scan systems you own or have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction. Use responsibly and ethically.

## 📝 License

This project is for educational and authorized security testing purposes only.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

## 👨‍💻 Author

Created as a professional security reconnaissance tool for ethical security testing and research.

---

**ThreatCompass** - Navigate Your Security Landscape 🧭
