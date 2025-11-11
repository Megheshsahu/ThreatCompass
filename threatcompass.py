#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ThreatCompass - Security Reconnaissance Tool
# Author: Meghesh Sahu (https://github.com/Megheshsahu)
# Repository: https://github.com/Megheshsahu/ThreatCompass
# License: For educational and authorized security testing only
# Copyright (c) 2025 Meghesh Sahu. All rights reserved.
#
# WARNING: Unauthorized modification, distribution, or use without proper
# attribution is strictly prohibited. This software is protected by copyright.
#
# Digital Signature: ThreatCompass-v1.0-MS-2025-GITHUB-MEGHESHSAHU
# Build ID: TC-4d65676865736873616875-0x54433230323500
# Checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""
ThreatCompass - Navigate Your Security Landscape

A Python-based security reconnaissance and vulnerability assessment tool.
Performs subdomain enumeration, port scanning, threat intelligence gathering,
and vulnerability detection with automated reporting.

Main features:
    - DNS/WHOIS profiling and subdomain discovery
    - Shodan/Censys threat intelligence integration
    - Nmap port scanning with service detection
    - CVE lookups with risk scoring
    - HTML and JSON report generation

Requirements:
    - Python 3.9+
    - nmap (optional but recommended)
    - Python packages: requests, dnspython, python-whois, jinja2, shodan, censys

Basic usage:
    python reconxpert.py --target example.com --out ./out
    python reconxpert.py --target-list targets.txt --enumerate-subdomains

"""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import traceback
import typing as t
from pathlib import Path

# Optional dependencies - install with: pip install -r requirements.txt
try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import whois
except ImportError:
    whois = None

try:
    from jinja2 import Template
except ImportError:
    Template = None

try:
    import shodan
except ImportError:
    shodan = None

try:
    import censys.search
except ImportError:
    censys = None

# Data models for scan results
@dataclasses.dataclass
class ServiceFinding:
    port: int
    proto: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    os_info: str | None = None
    web_tech: str | None = None
    cves: list[dict] = dataclasses.field(default_factory=list)
    risk_score: float = 0.0
    risk_label: str = "Informational"

@dataclasses.dataclass
class SubdomainFinding:
    subdomain: str
    ips: list[str] = dataclasses.field(default_factory=list)
    status: str = "active"  # active, inactive, timeout

@dataclasses.dataclass
class ShodanFinding:
    ip: str
    port: int
    service: str | None = None
    banner: str | None = None
    location: str | None = None
    org: str | None = None
    vulns: list[str] = dataclasses.field(default_factory=list)

@dataclasses.dataclass
class TargetReport:
    target: str
    resolved_ips: list[str] = dataclasses.field(default_factory=list)
    subdomains: list[SubdomainFinding] = dataclasses.field(default_factory=list)
    shodan_data: list[ShodanFinding] = dataclasses.field(default_factory=list)
    whois_summary: str | None = None
    os_fingerprint: str | None = None
    services: list[ServiceFinding] = dataclasses.field(default_factory=list)
    key_findings: list[str] = dataclasses.field(default_factory=list)
    errors: list[str] = dataclasses.field(default_factory=list)
    started_at: str = dataclasses.field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat())
    finished_at: str | None = None

# Simple logging utility
class Log:
    @staticmethod
    def info(msg: str):
        print(f"[+] {msg}")
    @staticmethod
    def warn(msg: str):
        print(f"[!] {msg}")
    @staticmethod
    def err(msg: str):
        print(f"[-] {msg}")

RISK_BUCKETS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "Informational"),
]

def label_for_score(score: float) -> str:
    for threshold, label in RISK_BUCKETS:
        if score >= threshold:
            return label
    return "Informational"

# Digital watermark validation - DO NOT REMOVE
# This function verifies the authenticity of ThreatCompass
_AUTHOR_SIGNATURE = "4d65676865736873616875"  # Hex encoded
_PROJECT_HASH = "546872656174436f6d70617373"  # Hex encoded
_REPO_ID = "68747470733a2f2f6769746875622e636f6d2f4d65676865736873616875"  # Hex

def _verify_integrity():
    """Internal integrity check - validates project authenticity"""
    _owner = bytes.fromhex(_AUTHOR_SIGNATURE).decode('utf-8')
    _project = bytes.fromhex(_PROJECT_HASH).decode('utf-8')
    _source = bytes.fromhex(_REPO_ID).decode('utf-8')
    return (_owner, _project, _source)

def _get_attribution():
    """Returns project attribution information"""
    try:
        author, project, repo = _verify_integrity()
        return {
            'author': author,
            'project': project,
            'repository': repo,
            'version': '1.0',
            'year': '2025'
        }
    except:
        return None

# DNS resolution and WHOIS lookup
class Profiler:
    def __init__(self, resolver_timeout: float = 3.0):
        self.resolver_timeout = resolver_timeout

    def resolve(self, target):
        ips = []
        # Check if target is already an IP address
        try:
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            pass
        
        if dns is None:
            Log.warn("dnspython not installed; skipping DNS resolution")
            return ips
        
        try:
            r = dns.resolver.Resolver()
            r.lifetime = self.resolver_timeout
            # Query both IPv4 and IPv6
            for qtype in ["A", "AAAA"]:
                try:
                    answers = r.resolve(target, qtype)
                    for ans in answers:
                        ips.append(ans.to_text())
                except:
                    pass
        except Exception as e:
            Log.warn(f"DNS resolution failed for {target}: {e}")
        
        # Remove duplicates
        return list(dict.fromkeys(ips))

    def enumerate_subdomains(self, domain, wordlist=None):
        """Bruteforce common subdomains using DNS queries"""
        if dns is None:
            Log.warn("dnspython not installed; skipping subdomain enumeration")
            return []
        
        # Common subdomain list
        if not wordlist:
            wordlist = [
                "www", "mail", "ftp", "admin", "test", "dev", "staging", "api", "app",
                "blog", "shop", "store", "secure", "vpn", "remote", "portal", "cdn",
                "m", "mobile", "static", "assets", "img", "images", "upload", "downloads",
                "support", "help", "docs", "wiki", "forum", "news", "beta", "alpha",
                "demo", "sandbox", "git", "jenkins", "ci", "build", "deploy", "monitoring",
                "grafana", "kibana", "elk", "prometheus", "mysql", "db", "database",
                "redis", "cache", "queue", "rabbitmq", "smtp", "pop", "imap", "webmail"
            ]
        
        findings = []
        r = dns.resolver.Resolver()
        r.lifetime = self.resolver_timeout
        
        Log.info(f"Enumerating subdomains for {domain} (testing {len(wordlist)} names)")
        
        for sub in wordlist:
            subdomain = f"{sub}.{domain}"
            try:
                ips = []
                for qtype in ["A", "AAAA"]:
                    try:
                        answers = r.resolve(subdomain, qtype)
                        for ans in answers:
                            ips.append(ans.to_text())
                    except:
                        continue
                
                if ips:
                    findings.append(SubdomainFinding(
                        subdomain=subdomain,
                        ips=list(dict.fromkeys(ips)),
                        status="active"
                    ))
                    Log.info(f"Found subdomain: {subdomain} -> {', '.join(ips)}")
            except dns.resolver.NXDOMAIN:
                continue
            except Exception:
                findings.append(SubdomainFinding(
                    subdomain=subdomain,
                    ips=[],
                    status="timeout"
                ))
        
        return findings

    def whois_summary(self, target):
        if whois is None:
            return None
        
        try:
            w = whois.whois(target)
            fields = [
                ("domain_name", "Domain"),
                ("org", "Org"),
                ("registrar", "Registrar"),
                ("creation_date", "Created"),
                ("expiration_date", "Expires"),
                ("country", "Country"),
            ]
            lines = []
            for field, label in fields:
                val = w.get(field)
                if isinstance(val, (list, tuple)) and val:
                    val = val[0]
                if val:
                    lines.append(f"{label}: {val}")
            return " | ".join(lines) if lines else None
        except:
            return None

# Nmap integration for port scanning
class NmapRunner:
    def __init__(self, nmap_path: str | None = None, timeout: int = 900):
        self.nmap_path = nmap_path or shutil.which("nmap")
        self.timeout = timeout
        if not self.nmap_path:
            Log.warn("nmap not found in PATH; active scanning will be skipped")

    def scan(self, target, extra_args="-sV -sC -O -T4", top_ports=None, stealth=False):
        if not self.nmap_path:
            return None
        
        xml_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
        xml_tmp.close()
        cmd = [self.nmap_path, "-oX", xml_tmp.name]
        
        if stealth:
            cmd += ["-sS", "-f", "-T2", "--randomize-hosts"]
            Log.info("Using stealth scan mode")
        
        if top_ports:
            cmd += ["--top-ports", str(top_ports)]
        else:
            # Full port scan for comprehensive coverage
            cmd += ["-p-"]
            
        cmd += extra_args.split()
        cmd += [target]
        Log.info(f"Running nmap: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout, text=True)
            if proc.returncode != 0:
                Log.warn(f"nmap exited with code {proc.returncode}: {proc.stderr.strip()[:200]}")
            return xml_tmp.name
        except subprocess.TimeoutExpired:
            Log.err("nmap timed out; results may be incomplete")
            return xml_tmp.name
        except Exception as e:
            Log.err(f"nmap failed: {e}")
            with contextlib.suppress(Exception):
                os.unlink(xml_tmp.name)
            return None

    def web_scan(self, target: str, port: int = 80) -> dict:
        """Scan for web technologies using Nmap HTTP scripts"""
        if not self.nmap_path:
            return {}
        
        xml_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
        xml_tmp.close()
        
        # Use HTTP enumeration scripts
        scripts = [
            "http-enum", "http-headers", "http-methods", "http-robots.txt",
            "http-title", "http-server-header", "http-waf-detect",
            "http-wordpress-enum", "http-drupal-enum", "http-joomla-brute"
        ]
        
        cmd = [
            self.nmap_path, "-sV", "-p", str(port),
            "--script", ",".join(scripts),
            "-oX", xml_tmp.name, target
        ]
        
        Log.info(f"Running web enumeration on {target}:{port}")
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, text=True)
            return self._parse_web_results(xml_tmp.name)
        except Exception as e:
            Log.warn(f"Web scan failed: {e}")
            return {}
        finally:
            with contextlib.suppress(Exception):
                os.unlink(xml_tmp.name)
    
    def _parse_web_results(self, xml_path: str) -> dict:
        """Parse web technology detection results"""
        import xml.etree.ElementTree as ET
        web_info = {}
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall("host"):
                for port in host.findall("ports/port"):
                    for script in port.findall("script"):
                        script_id = script.get("id", "")
                        output = script.get("output", "")
                        
                        if "http-server-header" in script_id:
                            web_info["server"] = output.strip()
                        elif "http-title" in script_id:
                            web_info["title"] = output.strip()
                        elif "wordpress" in script_id.lower():
                            web_info["cms"] = "WordPress"
                            web_info["cms_details"] = output.strip()
                        elif "drupal" in script_id.lower():
                            web_info["cms"] = "Drupal"
                            web_info["cms_details"] = output.strip()
                        elif "joomla" in script_id.lower():
                            web_info["cms"] = "Joomla"
                            web_info["cms_details"] = output.strip()
                        elif "http-waf-detect" in script_id:
                            web_info["waf"] = output.strip()
        except Exception as e:
            Log.warn(f"Failed to parse web results: {e}")
        
        return web_info

# ------------------ Nmap XML Parser ------------------
class NmapParser:
    @staticmethod
    def parse_services(xml_path: str) -> tuple[list[ServiceFinding], str | None]:
        import xml.etree.ElementTree as ET
        findings: list[ServiceFinding] = []
        os_info = None
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for host in root.findall("host"):
                # Parse OS information
                os_elem = host.find("os")
                if os_elem is not None:
                    os_matches = []
                    for osmatch in os_elem.findall("osmatch"):
                        name = osmatch.get("name", "")
                        accuracy = osmatch.get("accuracy", "0")
                        if name:
                            os_matches.append(f"{name} ({accuracy}% accuracy)")
                    if os_matches:
                        os_info = "; ".join(os_matches[:3])  # Top 3 matches
                
                # Parse ports and services
                for port in host.findall("ports/port"):
                    try:
                        portid = int(port.get("portid", "0"))
                        proto = port.get("protocol", "tcp")
                        state_elem = port.find("state")
                        if state_elem is None or state_elem.get("state") != "open":
                            continue
                            
                        svc = port.find("service")
                        service = svc.get("name") if svc is not None else None
                        product = svc.get("product") if svc is not None else None
                        version = svc.get("version") if svc is not None else None
                        extrainfo = svc.get("extrainfo") if svc is not None else None
                        ostype = svc.get("ostype") if svc is not None else None
                        
                        # Combine OS info from service detection
                        service_os = ostype if ostype else None
                        
                        # Parse script output for web technologies
                        web_tech = None
                        for script in port.findall("script"):
                            script_id = script.get("id", "")
                            output = script.get("output", "")
                            
                            if any(x in script_id for x in ["http-server-header", "http-title", "wordpress", "drupal", "joomla"]):
                                if web_tech:
                                    web_tech += f"; {output.strip()[:100]}"
                                else:
                                    web_tech = output.strip()[:100]
                        
                        findings.append(ServiceFinding(
                            port=portid,
                            proto=proto,
                            service=service,
                            product=product,
                            version=version,
                            extrainfo=extrainfo,
                            os_info=service_os,
                            web_tech=web_tech,
                        ))
                    except Exception:
                        continue
        except Exception as e:
            Log.err(f"Failed to parse nmap XML: {e}")
        
        return findings, os_info

# ------------------ Shodan/Censys Integration ------------------
class ThreatIntelligence:
    def __init__(self, shodan_api_key: str | None = None, censys_api_id: str | None = None, censys_api_secret: str | None = None):
        self.shodan_api_key = shodan_api_key
        self.censys_api_id = censys_api_id
        self.censys_api_secret = censys_api_secret
        self.shodan_api = None
        self.censys_api = None
        
        if shodan and shodan_api_key:
            try:
                self.shodan_api = shodan.Shodan(shodan_api_key)
                Log.info("Shodan API initialized")
            except Exception as e:
                Log.warn(f"Failed to initialize Shodan: {e}")
        
        if censys and censys_api_id and censys_api_secret:
            try:
                self.censys_api = censys.search.CensysHosts(censys_api_id, censys_api_secret)
                Log.info("Censys API initialized")
            except Exception as e:
                Log.warn(f"Failed to initialize Censys: {e}")

    def query_shodan(self, ip: str) -> list[ShodanFinding]:
        """Query Shodan for host information"""
        if not self.shodan_api:
            return []
        
        findings: list[ShodanFinding] = []
        try:
            host_info = self.shodan_api.host(ip)
            
            for service in host_info.get('data', []):
                port = service.get('port', 0)
                service_name = service.get('product', service.get('_shodan', {}).get('module', 'unknown'))
                banner = service.get('data', '').strip()[:500]  # Limit banner size
                location = f"{host_info.get('city', '')}, {host_info.get('country_name', '')}"
                org = host_info.get('org', '')
                vulns = list(service.get('vulns', {}).keys())
                
                findings.append(ShodanFinding(
                    ip=ip,
                    port=port,
                    service=service_name,
                    banner=banner,
                    location=location.strip(', '),
                    org=org,
                    vulns=vulns
                ))
                
            Log.info(f"Shodan found {len(findings)} services for {ip}")
            
        except Exception as e:
            if shodan and "APIError" in str(type(e)):
                Log.warn(f"Shodan API error for {ip}: {e}")
            else:
                Log.warn(f"Shodan query failed for {ip}: {e}")
        
        return findings
    
    def query_censys(self, ip: str) -> list[ShodanFinding]:
        """Query Censys for host information"""
        if not self.censys_api:
            return []
        
        findings: list[ShodanFinding] = []
        try:
            host_info = self.censys_api.view(ip)
            services = host_info.get('services', [])
            
            for service in services:
                port = service.get('port', 0)
                service_name = service.get('service_name', 'unknown')
                banner = service.get('banner', '')[:500]
                location = f"{host_info.get('location', {}).get('city', '')}, {host_info.get('location', {}).get('country', '')}"
                org = host_info.get('autonomous_system', {}).get('organization', '')
                
                findings.append(ShodanFinding(
                    ip=ip,
                    port=port,
                    service=service_name,
                    banner=banner,
                    location=location.strip(', '),
                    org=org,
                    vulns=[]  # Censys doesn't provide vuln data in the same format
                ))
                
            Log.info(f"Censys found {len(findings)} services for {ip}")
            
        except Exception as e:
            Log.warn(f"Censys query failed for {ip}: {e}")
        
        return findings

# ------------------ CVE Lookup (NVD) ------------------
class CveLookup:
    def __init__(self, api_key: str | None = None, timeout: int = 15):
        self.api_key = api_key
        self.timeout = timeout
        if requests is None:
            Log.warn("requests not installed; CVE lookup disabled")

    def query_nvd(self, product: str, version: str | None) -> list[dict]:
        if requests is None:
            return []
        # NVD 2.0 API example endpoint (keyword search). This is a simplified, best-effort query.
        base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        q = product
        if version:
            q = f"{product} {version}"
        params = {"keywordSearch": q, "resultsPerPage": 20}
        headers = {"User-Agent": "ReconXpert/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            resp = requests.get(base, params=params, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            out: list[dict] = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cvss = None
                metrics = cve.get("metrics", {})
                # Prefer CVSS v3.1 if present
                for key in ["cvssMetricV31", "cvssMetricV3", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                        break
                out.append({
                    "id": cve.get("id"),
                    "score": float(cvss) if isinstance(cvss, (int, float)) else None,
                    "description": (cve.get("descriptions", [{}])[0] or {}).get("value"),
                    "source": "NVD",
                })
            return out
        except requests.exceptions.HTTPError as e:
            # Handle rate limiting gracefully
            if e.response is not None and e.response.status_code == 429:
                Log.warn("NVD rate-limited (429). Consider adding --nvd-api-key. Falling back to heuristics.")
            else:
                Log.warn(f"NVD lookup HTTP error: {e}")
        except Exception as e:
            Log.warn(f"NVD lookup failed: {e}")
        return []

    def enrich_services(self, services: list[ServiceFinding]):
        for s in services:
            # Only query when we have at least product or service name
            product = (s.product or s.service or "").strip()
            version = (s.version or "").strip() or None
            if not product:
                continue
            cves = self.query_nvd(product, version)
            s.cves = cves
            # Compute a quick risk score from top CVE score if any
            best = max((c.get("score") or 0.0 for c in cves), default=0.0)
            # Add heuristics for inherently risky services if no CVEs
            if best == 0.0:
                risky = {22: 6.0, 23: 7.5, 3389: 9.0, 445: 8.5, 21: 7.0, 5900: 7.5}
                best = risky.get(s.port, 0.0)
            s.risk_score = round(float(best), 1)
            s.risk_label = label_for_score(s.risk_score)

# ------------------ Reporting ------------------
class Reporter:
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def save_json(self, report: TargetReport) -> Path:
        p = self.out_dir / f"{safe_name(report.target)}.json"
        report_dict = dataclasses.asdict(report)
        # Embed attribution watermark in metadata
        attribution = _get_attribution()
        if attribution:
            report_dict['_metadata'] = {
                'tool': attribution['project'],
                'author': attribution['author'],
                'repository': attribution['repository'],
                'version': attribution['version'],
                'generated_by': f"{attribution['project']} by {attribution['author']}"
            }
        with open(p, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2)
        Log.info(f"Saved JSON report: {p}")
        return p

    def save_html(self, report: TargetReport) -> Path:
        p = self.out_dir / f"{safe_name(report.target)}.html"
        html = self.render_html(report)
        with open(p, "w", encoding="utf-8") as f:
            f.write(html)
        Log.info(f"Saved HTML report: {p}")
        return p

    def render_html(self, report: TargetReport) -> str:
        template = DEFAULT_HTML_TEMPLATE
        if Template is not None:
            try:
                return Template(DEFAULT_HTML_TEMPLATE).render(report=report)
            except Exception:
                pass
        # Minimal string format fallback
        services_rows = []
        for s in report.services:
            cve_list = ", ".join(c.get("id") for c in s.cves[:5]) if s.cves else "—"
            services_rows.append(
                f"<tr><td>{s.port}/{s.proto}</td><td>{safe(s.service)}</td><td>{safe(s.product)} {safe(s.version)}</td>"
                f"<td>{safe(s.os_info)}</td><td>{safe(s.web_tech)}</td><td><b>{s.risk_label}</b> ({s.risk_score})</td><td>{safe(cve_list)}</td></tr>"
            )
        key_findings_li = "".join(f"<li>{safe(k)}</li>" for k in report.key_findings)
        
        # Build subdomains section
        subdomains_section = ""
        if report.subdomains:
            subdomain_items = []
            for sub in report.subdomains[:10]:
                ips_str = ", ".join(sub.ips) if sub.ips else "No IPs"
                subdomain_items.append(f"<li><b>{safe(sub.subdomain)}</b> → {safe(ips_str)} ({safe(sub.status)})</li>")
            subdomains_section = f"<h2>Subdomains ({len(report.subdomains)} found)</h2><ul>{''.join(subdomain_items)}</ul>"
        
        # Build threat intel section
        threat_intel_section = ""
        if report.shodan_data:
            threat_rows = []
            for shodan in report.shodan_data[:10]:
                vulns_str = ", ".join(shodan.vulns[:3]) if shodan.vulns else "—"
                threat_rows.append(
                    f"<tr><td>{safe(shodan.ip)}</td><td>{safe(shodan.port)}</td><td>{safe(shodan.service)}</td>"
                    f"<td>{safe(shodan.location)}</td><td>{safe(shodan.org)}</td><td>{safe(vulns_str)}</td></tr>"
                )
            threat_intel_section = f"""
            <h2>Threat Intelligence ({len(report.shodan_data)} findings)</h2>
            <table border="1"><thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Location</th><th>Organization</th><th>Vulnerabilities</th></tr></thead>
            <tbody>{''.join(threat_rows)}</tbody></table>
            """
        
        return DEFAULT_HTML_TEMPLATE_SIMPLE.format(
            target=safe(report.target),
            started=safe(report.started_at),
            finished=safe(report.finished_at or ""),
            whois=safe(report.whois_summary or "—"),
            os_info=safe(report.os_fingerprint or "—"),
            ips=safe(", ".join(report.resolved_ips) or "—"),
            subdomains_section=subdomains_section,
            threat_intel_section=threat_intel_section,
            rows="\n".join(services_rows),
            key_findings=key_findings_li or "<li>None</li>",
        )

# Helper functions
def safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", s)

def safe(s: t.Any) -> str:
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

# ------------------ Orchestrator ------------------
class ReconXpert:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.profiler = Profiler()
        self.nmap = NmapRunner(timeout=args.nmap_timeout)
        self.cve = CveLookup(api_key=args.nvd_api_key)
        self.threat_intel = ThreatIntelligence(
            shodan_api_key=getattr(args, 'shodan_api_key', None),
            censys_api_id=getattr(args, 'censys_api_id', None),
            censys_api_secret=getattr(args, 'censys_api_secret', None)
        )
        self.reporter = Reporter(Path(args.out))

    def run_target(self, target: str) -> TargetReport:
        rep = TargetReport(target=target)
        try:
            # Phase 1: DNS/WHOIS & Subdomain Enumeration
            Log.info(f"Phase 1: Profiling target {target}")
            rep.resolved_ips = self.profiler.resolve(target)
            rep.whois_summary = self.profiler.whois_summary(target)
            
            # Subdomain enumeration (only for domains, not IPs)
            if not self._is_ip(target) and getattr(self.args, 'enumerate_subdomains', True):
                rep.subdomains = self.profiler.enumerate_subdomains(target)

            # Phase 2: Threat Intelligence (Shodan/Censys)
            if getattr(self.args, 'threat_intel', True) and rep.resolved_ips:
                Log.info("Phase 2: Gathering threat intelligence")
                for ip in rep.resolved_ips[:3]:  # Limit to first 3 IPs to avoid rate limiting
                    shodan_data = self.threat_intel.query_shodan(ip)
                    censys_data = self.threat_intel.query_censys(ip)
                    rep.shodan_data.extend(shodan_data + censys_data)

            # Phase 3: Active Reconnaissance (Nmap)
            Log.info("Phase 3: Active scanning")
            stealth_mode = getattr(self.args, 'stealth', False)
            xml = self.nmap.scan(target, 
                               extra_args=self.args.nmap_args, 
                               top_ports=self.args.top_ports,
                               stealth=stealth_mode)
            
            services: list[ServiceFinding] = []
            os_info = None
            if xml and os.path.exists(xml):
                services, os_info = NmapParser.parse_services(xml)
                rep.os_fingerprint = os_info
                
                # Web technology detection for HTTP/HTTPS services
                for service in services:
                    if service.port in [80, 443, 8080, 8443] and service.service in ['http', 'https', 'http-proxy']:
                        web_info = self.nmap.web_scan(target, service.port)
                        if web_info:
                            tech_details = []
                            for key, value in web_info.items():
                                if value:
                                    tech_details.append(f"{key}: {value}")
                            service.web_tech = "; ".join(tech_details)
                
                with contextlib.suppress(Exception):
                    os.unlink(xml)
            else:
                rep.errors.append("Nmap scan skipped or failed")

            # Phase 4: CVE enrichment
            Log.info("Phase 4: CVE lookup and risk assessment")
            if services:
                self.cve.enrich_services(services)

            # Phase 5: Key findings and reporting
            Log.info("Phase 5: Generating findings and report")
            services.sort(key=lambda s: (-s.risk_score, s.port))
            rep.services = services
            rep.key_findings = self._build_key_findings(services, rep.shodan_data)
            
        except KeyboardInterrupt:
            rep.errors.append("Aborted by user")
        except Exception as e:
            rep.errors.append(f"Unexpected error: {e}")
            Log.err(traceback.format_exc())
        finally:
            rep.finished_at = dt.datetime.now(dt.timezone.utc).isoformat()
        return rep

    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def _build_key_findings(self, services: list[ServiceFinding], shodan_data: list[ShodanFinding] = None) -> list[str]:
        findings: list[str] = []
        
        # High-risk services from Nmap
        for s in services[:10]:  # top items only
            if s.risk_score >= 7.0:
                note = f"{s.risk_label}: Port {s.port}/{s.proto} – {s.product or s.service or 'Unknown'} {s.version or ''}".strip()
                if s.cves:
                    top = [c['id'] for c in s.cves[:3] if c.get('id')]
                    if top:
                        note += f" | CVEs: {', '.join(top)}"
                # Add web technology info if available
                if s.web_tech:
                    note += f" | Web Tech: {s.web_tech[:50]}"
                findings.append(note)
        
        # Shodan/Censys findings with vulnerabilities
        if shodan_data:
            for shodan in shodan_data[:5]:  # Top 5 Shodan findings
                if shodan.vulns:
                    vulns_str = ', '.join(shodan.vulns[:3])
                    findings.append(f"Threat Intel: {shodan.ip}:{shodan.port} ({shodan.service}) has vulnerabilities: {vulns_str}")
                elif shodan.service and shodan.port in [3389, 445, 23, 21, 22]:
                    findings.append(f"Threat Intel: {shodan.ip}:{shodan.port} running {shodan.service} (exposed to internet)")
        
        # Heuristic flags for dangerous services
        risky_ports = {
            3389: "RDP exposed to internet", 
            445: "SMB exposed (lateral movement risk)", 
            23: "Telnet (clear-text)", 
            21: "FTP (clear-text)",
            1433: "MSSQL exposed to internet",
            3306: "MySQL exposed to internet",
            5432: "PostgreSQL exposed to internet",
            6379: "Redis exposed to internet",
            27017: "MongoDB exposed to internet"
        }
        
        for s in services:
            if s.port in risky_ports and s.risk_score < 7.0:
                findings.append(f"Warning: {risky_ports[s.port]} on port {s.port}")
        
        # Web technology findings
        web_services = [s for s in services if s.web_tech and any(cms in s.web_tech.lower() for cms in ['wordpress', 'joomla', 'drupal'])]
        for s in web_services:
            findings.append(f"CMS Detected: {s.web_tech} on port {s.port} (check for known vulnerabilities)")
        
        return findings[:15] or ["No high-severity issues detected (based on available data)"]

    def run(self, targets: list[str]) -> list[TargetReport]:
        results: list[TargetReport] = []
        # Concurrent targets with thread pool for I/O bound operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.workers) as ex:
            futs = {ex.submit(self.run_target, t): t for t in targets}
            for fut in concurrent.futures.as_completed(futs):
                results.append(fut.result())
        # Save per-target reports
        for rep in results:
            if "json" in self.args.format:
                self.reporter.save_json(rep)
            if "html" in self.args.format:
                self.reporter.save_html(rep)
        return results

# ------------------ CLI ------------------
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="ReconXpert – Automated recon, CVE scoring, and reporting with subdomain enum, OS fingerprinting, and threat intel",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    g_target = p.add_argument_group("Targets")
    g_target.add_argument("--target", help="Single target (IP or domain)")
    g_target.add_argument("--target-list", help="File with one target per line")

    g_recon = p.add_argument_group("Reconnaissance")
    g_recon.add_argument("--enumerate-subdomains", action="store_true", default=True, help="Enumerate subdomains (domains only)")
    g_recon.add_argument("--no-subdomains", dest="enumerate_subdomains", action="store_false", help="Skip subdomain enumeration")
    g_recon.add_argument("--threat-intel", action="store_true", default=True, help="Query Shodan/Censys for threat intelligence")
    g_recon.add_argument("--no-threat-intel", dest="threat_intel", action="store_false", help="Skip threat intelligence gathering")

    g_scan = p.add_argument_group("Scanning")
    g_scan.add_argument("--nmap-args", default="-sV -sC -O -T4", help="Extra nmap arguments (now includes OS detection)")
    g_scan.add_argument("--top-ports", type=int, help="Scan top-N ports instead of full scan")
    g_scan.add_argument("--nmap-timeout", type=int, default=900, help="Nmap timeout (seconds)")
    g_scan.add_argument("--stealth", action="store_true", help="Use stealth scanning mode (slower but less detectable)")

    g_cve = p.add_argument_group("CVE Lookup")
    g_cve.add_argument("--nvd-api-key", help="NVD API key for higher rate limits")

    g_intel = p.add_argument_group("Threat Intelligence")
    g_intel.add_argument("--shodan-api-key", help="Shodan API key for threat intelligence")
    g_intel.add_argument("--censys-api-id", help="Censys API ID")
    g_intel.add_argument("--censys-api-secret", help="Censys API secret")

    g_out = p.add_argument_group("Output")
    g_out.add_argument("--out", default="out", help="Output directory")
    g_out.add_argument("--format", default="json,html", help="Comma-separated: json,html")
    g_out.add_argument("--workers", type=int, default=4, help="Concurrent targets")

    args = p.parse_args(argv)

    if not args.target and not args.target_list:
        p.error("Provide --target or --target-list")

    args.format = [s.strip().lower() for s in args.format.split(",") if s.strip()]
    return args

# ------------------ HTML Templates ------------------
DEFAULT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ReconXpert Report – {{ report.target }}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 24px; }
    header { display:flex; justify-content:space-between; align-items:center; }
    .pill { padding:4px 10px; border-radius:16px; background:#eef; }
    table { border-collapse: collapse; width: 100%; margin-top: 16px; }
    th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; }
    th { background: #f7f7f7; text-align: left; }
    .sev-Critical { background:#ffebee; }
    .sev-High { background:#fff3e0; }
    .sev-Medium { background:#fffde7; }
    .sev-Low { background:#e8f5e9; }
    .sev-Informational { background:#eceff1; }
    .muted { color:#666; }
    .section { margin-top: 24px; }
    ul { margin: 8px 0 0 20px; }
  </style>
</head>
<body>
  <header>
    <h1>ReconXpert – Report</h1>
    <div class="pill">Target: <b>{{ report.target }}</b></div>
  </header>
  <p class="muted">Started: {{ report.started_at }} | Finished: {{ report.finished_at }}</p>

  <div class="section">
    <h2>Overview</h2>
    <p><b>Resolved IPs:</b> {{ ", ".join(report.resolved_ips) or "—" }}<br/>
       <b>WHOIS:</b> {{ report.whois_summary or "—" }}<br/>
       <b>OS Fingerprint:</b> {{ report.os_fingerprint or "—" }}</p>
  </div>

  {% if report.subdomains %}
  <div class="section">
    <h2>Subdomains ({{ report.subdomains|length }} found)</h2>
    <ul>
    {% for sub in report.subdomains[:10] %}
      <li><b>{{ sub.subdomain }}</b> → {{ ", ".join(sub.ips) if sub.ips else "No IPs" }} ({{ sub.status }})</li>
    {% endfor %}
    {% if report.subdomains|length > 10 %}
      <li><i>... and {{ report.subdomains|length - 10 }} more</i></li>
    {% endif %}
    </ul>
  </div>
  {% endif %}

  {% if report.shodan_data %}
  <div class="section">
    <h2>Threat Intelligence ({{ report.shodan_data|length }} findings)</h2>
    <table>
      <thead>
        <tr><th>IP</th><th>Port</th><th>Service</th><th>Location</th><th>Organization</th><th>Vulnerabilities</th></tr>
      </thead>
      <tbody>
      {% for shodan in report.shodan_data[:10] %}
        <tr>
          <td>{{ shodan.ip }}</td>
          <td>{{ shodan.port }}</td>
          <td>{{ shodan.service or "—" }}</td>
          <td>{{ shodan.location or "—" }}</td>
          <td>{{ shodan.org or "—" }}</td>
          <td>{% if shodan.vulns %}{{ ", ".join(shodan.vulns[:3]) }}{% else %}—{% endif %}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <div class="section">
    <h2>Key Findings</h2>
    <ul>
    {% for k in report.key_findings %}
      <li>{{ k }}</li>
    {% endfor %}
    </ul>
  </div>

  <div class="section">
    <h2>Services</h2>
    <table>
      <thead>
        <tr><th>Port</th><th>Service</th><th>Product</th><th>OS Info</th><th>Web Tech</th><th>Risk</th><th>CVEs</th></tr>
      </thead>
      <tbody>
      {% for s in report.services %}
        <tr class="sev-{{ s.risk_label }}">
          <td>{{ s.port }}/{{ s.proto }}</td>
          <td>{{ s.service or '' }}</td>
          <td>{{ (s.product or '') + (' ' + s.version if s.version else '') }}</td>
          <td>{{ s.os_info or '' }}</td>
          <td>{{ s.web_tech or '' }}</td>
          <td><b>{{ s.risk_label }}</b> ({{ '%.1f' % s.risk_score }})</td>
          <td>{% if s.cves %}{% for c in s.cves[:5] %}{{ c.id }}{% if not loop.last %}, {% endif %}{% endfor %}{% else %}—{% endif %}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  {% if report.errors %}
  <div class="section">
    <h2>Errors / Warnings</h2>
    <ul>
      {% for e in report.errors %}<li>{{ e }}</li>{% endfor %}
    </ul>
  </div>
  {% endif %}

  <footer class="section muted">
    Generated by ThreatCompass | 
    <a href="https://github.com/Megheshsahu/ThreatCompass" style="color:#666;">GitHub Repository</a> | 
    &copy; 2025 Meghesh Sahu
    <!-- Digital Signature: TC-MS-2025-4d65676865736873616875 -->
    <!-- Build: ThreatCompass-v1.0-AUTHENTICATED -->
  </footer>
</body>
</html>
"""

DEFAULT_HTML_TEMPLATE_SIMPLE = """
<!DOCTYPE html>
<html><head><meta charset=\"utf-8\"><title>ReconXpert Report – {target}</title>
<style>
 body{font-family:Arial,Helvetica,sans-serif;margin:24px}
 table{border-collapse:collapse;width:100%;margin:16px 0}
 th,td{border:1px solid #ddd;padding:8px;font-size:14px}
 th{background:#f7f7f7}
 .muted{color:#666}
 ul{margin:8px 0 0 20px}
</style></head>
<body>
<h1>ReconXpert – Report</h1>
<p class=muted>Started: {started} | Finished: {finished}</p>
<p><b>Target:</b> {target}<br><b>Resolved IPs:</b> {ips}<br><b>WHOIS:</b> {whois}<br><b>OS Fingerprint:</b> {os_info}</p>
{subdomains_section}
{threat_intel_section}
<h2>Key Findings</h2>
<ul>{key_findings}</ul>
<h2>Services</h2>
<table>
<thead><tr><th>Port</th><th>Service</th><th>Product</th><th>OS Info</th><th>Web Tech</th><th>Risk</th><th>CVEs</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body></html>
"""

# Main entry point
def main(argv: list[str] | None = None):
    argv = argv if argv is not None else sys.argv[1:]
    args = parse_args(argv)

    targets: list[str] = []
    if args.target:
        targets.append(args.target.strip())
    if args.target_list:
        try:
            with open(args.target_list, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except Exception as e:
            Log.err(f"Failed to read --target-list: {e}")
            sys.exit(2)

    app = ReconXpert(args)
    app.run(targets)

if __name__ == "__main__":
    main()
