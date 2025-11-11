@echo off
echo Installing ReconXpert Dependencies...
echo.

echo Installing core dependencies...
pip install requests dnspython python-whois jinja2

echo.
echo Installing threat intelligence APIs (optional)...
pip install shodan censys

echo.
echo Installing additional utilities...
pip install colorama tqdm

echo.
echo Installation complete!
echo.
echo To verify installation, run:
echo python -c "import requests, dns.resolver, whois, jinja2; print('All core dependencies installed successfully!')"
echo.
pause
