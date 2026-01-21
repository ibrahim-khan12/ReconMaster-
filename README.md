# ReconMaster - Modular Reconnaissance Tool

A lightweight, modular CLI-based reconnaissance tool for automating initial information gathering during penetration testing engagements.

## Overview

ReconMaster is designed to familiarize security professionals and interns with offensive tooling techniques, scripting, and modular architecture in real-world red team scenarios. The tool integrates both **passive** and **active** reconnaissance techniques with comprehensive reporting capabilities.

## Features

## Report Formats

### HTML Report
Professional, styled report with:
- Color-coded sections
- Organized table layouts
- Security scoring
- Responsive design
- Mobile-friendly layout

### Text Report
Plain-text report with:
- Readable formatting
- Timestamp information
- All data included
- Easy to parse

### JSON Report
Machine-readable format with:
- Structured data
- All results included
- Timestamps
- Easy integration with other tools

## Project Structure

```
reconmaster/
├── reconmaster.py          # Main CLI entry point
├── recon_tool/
│   ├── __init__.py
│   ├── utils.py            # Logging and utilities
│   ├── reporting.py        # Report generation
│   └── modules/
│       ├── __init__.py
│       ├── passive/
│       │   ├── __init__.py
│       │   ├── whois_lookup.py
│       │   ├── dns_enum.py
│       │   └── subdomain_enum.py
│       └── active/
│           ├── __init__.py
│           ├── port_scanner.py
│           ├── banner_grabber.py
│           └── tech_detector.py
├── README.md               # This file
├── requirements.txt        # Python dependencies
└── Dockerfile              # Docker configuration
```

## Logging and Verbosity

ReconMaster supports multiple verbosity levels:

```bash
# Normal output (INFO level)
python reconmaster.py example.com --all

# Debug output (-v or -vv)
python reconmaster.py example.com --all -v

# Verbose debug output
python reconmaster.py example.com --all -vv
```

**Log format:**
- Normal: `[TIMESTAMP] LEVEL - MESSAGE`
- Debug: `[TIMESTAMP] LEVEL [MODULE] - MESSAGE`
- Verbose: `[TIMESTAMP] LEVEL [MODULE:FUNCTION:LINE] - MESSAGE`

Color-coded console output for easy reading.

## Performance Tips

1. **Reduce Threading**: Lower thread count for slower connections
   ```bash
   python reconmaster.py example.com --ports --threads 50
   ```

2. **Increase Timeout**: For unstable connections
   ```bash
   python reconmaster.py example.com --ports --timeout 5
   ```

3. **Selective Scanning**: Run specific modules instead of all
   ```bash
   python reconmaster.py example.com --whois --dns
   ```

4. **Skip Bruteforce**: Disable DNS bruteforce for faster subdomain enumeration
   Module supports disabling this via code modification

## Legal Disclaimer

⚠️ **IMPORTANT LEGAL NOTICE:**

ReconMaster is intended for **authorized security testing only**. Users must:

1. Have written permission from system owners before conducting any reconnaissance
2. Comply with all applicable laws and regulations
3. Use this tool ethically and responsibly
4. Understand that unauthorized access to computer systems is illegal

The developers are not responsible for misuse or damage caused by this tool. Users assume all legal responsibility for their actions.

## Contributing

Contributions are welcome! Areas for enhancement:

- Additional passive recon sources
- Nmap integration for advanced port scanning
- Additional service detection signatures
- Database storage for results
- Web UI
- More export formats

## Troubleshooting

### DNS Resolution Fails
- Check internet connectivity
- Verify domain name spelling
- Try alternative DNS server

### Port Scan Too Slow
- Increase thread count: `--threads 200`
- Reduce port range: `--ports 80 443 8080`
- Lower scan type: use 'common' instead of 'extended'

### SSL Certificate Errors
- This is expected for self-signed certificates
- Tool ignores SSL verification by design
- Check detailed report for certificate information

### No Results on Some Modules
- Check console output for errors
- Verify internet connectivity
- Try with increased verbosity: `-v`

## Version History

### v1.0.0 (Current)
- Initial release
- All core modules functional
- HTML, TXT, JSON reporting
- Comprehensive logging

## License

MIT License - See LICENSE file for details

## References

- [OWASP Reconnaissance Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)
- [Nmap Reference Guide](https://nmap.org/book/)
- [DNS Records Reference](https://en.wikipedia.org/wiki/List_of_DNS_record_types)

## Support

For issues, questions, or suggestions:
1. Check the troubleshooting section
2. Review log output with `-v` flag
3. Open an issue on GitHub
4. Contact the development team

## Acknowledgments

- Built for cybersecurity interns and penetration testers
- Inspired by industry-standard reconnaissance tools
- Community feedback and contributions

---
