#!/bin/bash
# ReconXpert Dependencies Installation Script for Linux/Mac

echo "Installing ReconXpert Dependencies..."
echo

echo "Installing core dependencies..."
pip3 install requests dnspython python-whois jinja2

echo
echo "Installing threat intelligence APIs (optional)..."
pip3 install shodan censys

echo
echo "Installing additional utilities..."
pip3 install colorama tqdm

echo
echo "Installation complete!"
echo
echo "To verify installation, run:"
echo "python3 -c \"import requests, dns.resolver, whois, jinja2; print('All core dependencies installed successfully!')\""
echo
