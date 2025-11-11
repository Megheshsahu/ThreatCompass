#!/usr/bin/env python3
"""
ReconXpert Environment Check
Verifies all dependencies and external tools are properly installed
"""

import sys
import subprocess
import importlib.util

def check_python_version():
    """Check Python version compatibility"""
    print(f"Python version: {sys.version}")
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ required")
        return False
    elif sys.version_info < (3, 9):
        print("⚠️  Python 3.9+ recommended for best compatibility")
    else:
        print("✅ Python version compatible")
    return True

def check_module(module_name, package_name=None):
    """Check if a Python module is available"""
    try:
        if module_name == "dns.resolver":
            import dns.resolver
        elif module_name == "shodan":
            import shodan
        elif module_name == "censys.search":
            import censys.search
        else:
            __import__(module_name)
        print(f"✅ {module_name} - Available")
        return True
    except ImportError:
        pkg = package_name or module_name
        print(f"❌ {module_name} - Missing (install with: pip install {pkg})")
        return False

def check_external_tool(tool_name, command):
    """Check if external tool is available"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"✅ {tool_name} - Available")
            return True
        else:
            print(f"❌ {tool_name} - Not working properly")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print(f"❌ {tool_name} - Not found in PATH")
        return False

def main():
    print("🔍 ReconXpert Environment Check")
    print("=" * 40)
    
    # Check Python version
    python_ok = check_python_version()
    print()
    
    # Check core dependencies
    print("📦 Core Dependencies:")
    core_modules = [
        ("requests", "requests"),
        ("dns.resolver", "dnspython"),
        ("whois", "python-whois"),
        ("jinja2", "jinja2")
    ]
    
    core_ok = all(check_module(mod, pkg) for mod, pkg in core_modules)
    print()
    
    # Check optional dependencies
    print("🔧 Optional Dependencies:")
    optional_modules = [
        ("shodan", "shodan"),
        ("censys.search", "censys")
    ]
    
    optional_ok = all(check_module(mod, pkg) for mod, pkg in optional_modules)
    print()
    
    # Check external tools
    print("🛠️  External Tools:")
    external_tools = [
        ("nmap", ["nmap", "--version"]),
    ]
    
    external_ok = all(check_external_tool(name, cmd) for name, cmd in external_tools)
    print()
    
    # Summary
    print("📊 Summary:")
    if python_ok and core_ok:
        print("✅ ReconXpert can run with basic functionality")
        if optional_ok:
            print("✅ All optional APIs available")
        else:
            print("⚠️  Some API features will be limited")
        if external_ok:
            print("✅ All external tools available")
        else:
            print("⚠️  Some scanning features will be limited")
        print("\n🎯 Ready to use ReconXpert!")
    else:
        print("❌ Critical dependencies missing")
        print("Run: pip install -r requirements.txt")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
