# ReconXpert Setup Guide

## Quick Installation

### Option 1: Install from requirements.txt (Recommended)
```bash
pip install -r requirements.txt
```

### Option 2: Install minimal dependencies only
```bash
pip install -r requirements-minimal.txt
```

### Option 3: Manual installation
```bash
# Core dependencies (required)
pip install requests dnspython python-whois jinja2

# Threat intelligence APIs (optional but recommended)
pip install shodan censys

# Additional utilities (optional)
pip install colorama tqdm
```

### Option 4: Use installation scripts
**Windows:**
```cmd
install_dependencies.bat
```

**Linux/Mac:**
```bash
chmod +x install_dependencies.sh
./install_dependencies.sh
```

## External Dependencies

### Nmap (Highly Recommended)
**Windows:**
1. Download from: https://nmap.org/download.html
2. Install and add to PATH environment variable

**Linux:**
```bash
sudo apt-get install nmap  # Ubuntu/Debian
sudo yum install nmap      # CentOS/RHEL
```

**Mac:**
```bash
brew install nmap
```

## API Keys Setup (Optional but Recommended)

### NVD API Key
1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Request free API key
3. Use with: `--nvd-api-key YOUR_KEY`

### Shodan API Key
1. Visit: https://account.shodan.io/
2. Sign up for free account
3. Get API key from account page
4. Use with: `--shodan-api-key YOUR_KEY`

### Censys API Keys
1. Visit: https://search.censys.io/account/api
2. Sign up for free account
3. Get API ID and Secret
4. Use with: `--censys-api-id YOUR_ID --censys-api-secret YOUR_SECRET`

## Verification

Test installation:
```bash
python -c "import requests, dns.resolver, whois, jinja2; print('Installation successful!')"
```

Test ReconXpert:
```bash
python recon_xpert_intelligent_recon_risk_reporter_python.py --help
```

## Troubleshooting

### Common Issues:

**ImportError: No module named 'dns'**
```bash
pip install dnspython
```

**ImportError: No module named 'whois'**
```bash
pip install python-whois
```

**Nmap not found**
- Install nmap and add to PATH
- Or run without nmap (limited functionality)

### Version Compatibility
- Python 3.9+ recommended
- Python 3.7+ minimum supported
- Windows 10+, Linux, macOS supported

## Optional Enhancements

### Performance
```bash
pip install psutil memory-profiler
```

### Development
```bash
pip install pytest black flake8 mypy
```

### Rich output
```bash
pip install rich
```
