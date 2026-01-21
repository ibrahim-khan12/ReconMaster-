#!/usr/bin/env python3
"""
Quick Start Guide for ReconMaster
==================================

This file contains quick start examples for using ReconMaster.
Run these commands from the project directory.
"""

# BASIC USAGE EXAMPLES
# ====================

# 1. Quick passive reconnaissance (no active scanning)
# python reconmaster.py example.com

# 2. Full reconnaissance scan with all modules
# python reconmaster.py example.com --all

# 3. Passive reconnaissance only
# python reconmaster.py example.com --passive

# 4. Active reconnaissance only (ports, banners, tech detection)
# python reconmaster.py example.com --active

# 5. Run specific modules
# python reconmaster.py example.com --whois --dns --subdomains
# python reconmaster.py example.com --ports --banners --tech

# ADVANCED USAGE
# ==============

# 1. Full scan with verbose output
# python reconmaster.py example.com --all -v

# 2. Very verbose (debug) output
# python reconmaster.py example.com --all -vv

# 3. Generate only HTML report
# python reconmaster.py example.com --all --format html --output my_report

# 4. Generate all report formats
# python reconmaster.py example.com --all --format all --output my_report

# 5. Fast port scan with custom threading
# python reconmaster.py example.com --ports --threads 200

# 6. Port scan with custom timeout
# python reconmaster.py example.com --ports --timeout 3

# 7. Skip report generation
# python reconmaster.py example.com --all --no-report

# 8. Individual module execution
# python reconmaster.py example.com --whois
# python reconmaster.py example.com --dns
# python reconmaster.py example.com --subdomains
# python reconmaster.py example.com --ports
# python reconmaster.py example.com --banners
# python reconmaster.py example.com --tech

# DOCKER USAGE
# ============

# 1. Build Docker image
# docker build -t reconmaster .

# 2. Run basic scan
# docker run --rm reconmaster example.com

# 3. Run full scan
# docker run --rm reconmaster example.com --all

# 4. Run with custom options
# docker run --rm reconmaster example.com --passive -v

# 5. Mount local directory for report output
# docker run --rm -v C:\reports:/app/reports reconmaster example.com --all

# PRACTICAL EXAMPLES
# ==================

# Target: google.com
# Quick check of what's public
python_command = "python reconmaster.py google.com --passive -v"

# Target: github.com
# Check security headers and technologies
python_command = "python reconmaster.py github.com --tech -v"

# Target: scanme.nmap.org (test target)
# Full scan with all modules
python_command = "python reconmaster.py scanme.nmap.org --all --output nmap_scan"

# Target: any domain
# Port scanning only
python_command = "python reconmaster.py example.com --ports --threads 150"

# Target: any domain
# Technology detection with detailed output
python_command = "python reconmaster.py example.com --tech -vv"

# OUTPUT AND REPORTS
# ==================

# Reports are generated in the 'reports/' directory by default
# Three formats are created:
# 1. .html - Styled, professional HTML report with tables and formatting
# 2. .txt  - Plain text report, easy to read and parse
# 3. .json - Machine-readable JSON format for integration

# To view reports:
# Windows: start reports\example.com_report_*.html
# Linux:   firefox reports/example.com_report_*.html
# macOS:   open reports/example.com_report_*.html

# USEFUL TARGETS FOR TESTING
# ===========================

"""
These domains are designed for testing:
- example.com         - Simple ICANN example domain
- scanme.nmap.org     - Nmap project test server (allows scanning)
- google.com          - Large corporation
- github.com          - Tech company
- wikipedia.org       - Public knowledge base

REMEMBER: Always ensure you have permission before scanning!
"""

# TROUBLESHOOTING
# ===============

# Issue: DNS resolution fails
# Solution: Check internet connectivity
# python reconmaster.py example.com --passive

# Issue: Port scan too slow
# Solution: Increase threading or reduce port range
# python reconmaster.py example.com --ports --threads 200
# python reconmaster.py example.com --ports -p 80 443 8080

# Issue: Timeout on banner grabbing
# Solution: Increase timeout value
# python reconmaster.py example.com --banners --timeout 10

# Issue: No open ports found
# Solution: Target may have firewall, try with extended scan
# python reconmaster.py example.com --ports --format extended

# ADDITIONAL NOTES
# ================

# 1. Default port scan uses 'common' ports (20+ well-known ports)
#    For more thorough scan, use extended or full range

# 2. Subdomain enumeration uses multiple sources and DNS bruteforce
#    Results may vary based on internet connectivity

# 3. Technology detection analyzes HTTP headers and HTML content
#    May not detect all technologies

# 4. Reports include timestamps for tracking multiple scans

# 5. All modules support being run individually or together

# 6. Logging is color-coded in the console for easy reading

# NEXT STEPS
# ==========

# 1. Read README.md for comprehensive documentation
# 2. Explore the recon_tool/ directory structure
# 3. Customize report output for your needs
# 4. Integrate with your security workflow
# 5. Contribute improvements back to the project

print(__doc__)
