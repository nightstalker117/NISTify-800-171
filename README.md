# NIST SP 800-171 R2 Compliance Scanner

A comprehensive Python-based network security assessment tool that scans networks and endpoints for compliance with NIST SP 800-171 Rev 2 requirements. The scanner automatically generates compliance reports in multiple formats, calculates SPRS scores, creates network topology diagrams, and produces Plan of Action & Milestones (POA&M) documents.

## 🚀 Features

### 🔍 **Network Discovery & Scanning**
- Automated network host discovery and port scanning
- Service version detection and OS fingerprinting
- MAC address and vendor identification
- Gateway and routing topology mapping

### 🎯 **NIST SP 800-171 Compliance Assessment**
- Automated assessment against NIST SP 800-171 Rev 2 controls
- Risk-based finding categorization (High/Medium/Low severity)
- Evidence collection and documentation
- Compliance percentage calculations

### 📊 **SPRS Score Calculation**
- Supplier Performance Risk System (SPRS) score computation
- Automated point deductions based on findings severity
- Compliance metrics and trending analysis

### 📈 **Network Topology Visualization**
- Interactive network topology diagrams
- Node classification (servers, clients, network devices)
- Subnet grouping and visualization
- Gateway relationship mapping

### 📋 **Multi-Format Reporting**
- **HTML**: Interactive web-based reports with embedded diagrams
- **PDF**: Professional documents for executive briefings
- **JSON**: Machine-readable data for integration
- **XML**: Structured data exchange format
- **Text**: Plain text for terminal viewing
- **Excel POA&M**: Detailed remediation tracking spreadsheet

## 🛠️ Installation

### Prerequisites

#### 1. Install Nmap
**Windows:**
- Download from [https://nmap.org/download.html](https://nmap.org/download.html)
- Run installer as Administrator
- Ensure nmap is added to system PATH

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**macOS:**
```bash
brew install nmap
```

#### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Requirements File
Create `requirements.txt`:
```
python-nmap==0.7.1
pandas>=1.3.0
jinja2>=3.0.0
pdfkit>=1.0.0
openpyxl>=3.0.0
requests>=2.25.0
networkx>=2.6.0
matplotlib>=3.5.0
numpy>=1.21.0
```

#### 3. Additional Requirements for PDF Generation
**Linux:**
```bash
sudo apt-get install wkhtmltopdf
```

**Windows:**
- Download from [wkhtmltopdf.org](https://wkhtmltopdf.org/downloads.html)

**macOS:**
```bash
brew install wkhtmltopdf
```

## 🚦 Quick Start

### Basic Network Scan
```bash
python nist_compliance_scanner.py 192.168.1.0/24
```

### Multiple Network Ranges
```bash
python nist_compliance_scanner.py 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12
```

### Custom Port Scanning
```bash
python nist_compliance_scanner.py 192.168.1.0/24 --ports "22,80,443,3389,5432"
```

### Skip Topology Generation (Faster)
```bash
python nist_compliance_scanner.py 192.168.1.0/24 --no-topology
```

### Verbose Output
```bash
python nist_compliance_scanner.py 192.168.1.0/24 --verbose
```

## 📝 Usage Examples

### Enterprise Network Assessment
```bash
# Comprehensive scan of corporate network
python nist_compliance_scanner.py 10.0.0.0/8 \
    --ports "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3389" \
    --output-dir /reports/quarterly_assessment \
    --verbose
```

### Quick Security Check
```bash
# Fast scan without topology for immediate results
python nist_compliance_scanner.py 192.168.1.0/24 \
    --no-topology \
    --ports "22,80,443"
```

### DMZ Assessment
```bash
# Focus on web-facing services
python nist_compliance_scanner.py 203.0.113.0/24 \
    --ports "80,443,8080,8443" \
    --output-dir /reports/dmz_scan
```

## 📊 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `networks` | Network ranges to scan (required) | - |
| `--ports` | Comma-separated ports to scan | `22,23,53,80,135,139,443,445,993,995` |
| `--output-dir` | Output directory for reports | `reports` |
| `--no-topology` | Skip network topology generation | `False` |
| `--verbose`, `-v` | Enable verbose logging | `False` |

## 📁 Output Files

The scanner generates the following files in the output directory:

```
reports/
├── compliance_report_YYYYMMDD_HHMMSS.html    # Interactive HTML report
├── compliance_report_YYYYMMDD_HHMMSS.pdf     # Professional PDF document
├── compliance_report_YYYYMMDD_HHMMSS.json    # Machine-readable data
├── compliance_report_YYYYMMDD_HHMMSS.xml     # Structured XML format
├── compliance_report_YYYYMMDD_HHMMSS.txt     # Plain text report
├── poam_YYYYMMDD_HHMMSS.xlsx                 # POA&M Excel spreadsheet
├── network_topology.png                       # Network diagram
├── network_topology_subnets.png              # Subnet overview
└── nist_compliance.log                       # Detailed log file
```

## 🎨 Report Features

### HTML Reports
- **Interactive Design**: Responsive web-based interface
- **Embedded Diagrams**: Network topology visualizations
- **Color-Coded Findings**: Visual severity indicators
- **Executive Summary**: High-level compliance metrics
- **Detailed Tables**: Comprehensive system and finding data

### POA&M Excel Documents
- **Remediation Tracking**: Detailed action plans
- **Target Dates**: Risk-based timelines
- **Responsible Parties**: Assignment tracking
- **Status Management**: Progress monitoring
- **Color-Coded Severity**: Visual risk indicators

### Network Topology Diagrams
- **Node Classification**: Visual system type identification
- **Subnet Grouping**: Network segment visualization
- **Connection Mapping**: Network relationship display
- **Legend and Statistics**: Comprehensive network overview

## 🔧 Configuration

### Custom Control Assessment
Extend the `ComplianceAssessor` class to add custom compliance checks:

```python
def assess_custom_control(self, system: SystemInfo) -> ComplianceResult:
    # Custom assessment logic
    return ComplianceResult(
        control_id="3.X.X",
        control_name="Custom Control",
        # ... other fields
    )
```

### Custom Report Templates
Modify the HTML template in `ReportGenerator.generate_html_report()` to customize report appearance and content.

## 🔐 Security Considerations

### Permissions
- **Windows**: Run as Administrator for comprehensive scanning
- **Linux/macOS**: Run with `sudo` for privileged operations
- **Network**: Ensure appropriate network access permissions

### Firewall Considerations
- Configure firewalls to allow nmap traffic
- Consider impact on network monitoring systems
- Review corporate security policies before scanning

### Data Protection
- Reports may contain sensitive network information
- Secure storage and transmission of generated reports
- Consider data retention policies for compliance documentation

## 🐛 Troubleshooting

### Common Issues

#### Nmap Not Found
```
Error: nmap program was not found in path
```
**Solution**: Install nmap and ensure it's in system PATH

#### Permission Denied
```
Error: Permission denied during scan
```
**Solution**: Run with elevated privileges (Administrator/sudo)

#### No Hosts Found
```
Found 0 active hosts
```
**Solutions**:
- Verify network range is correct
- Check firewall settings
- Ensure network connectivity
- Try different scan arguments

#### PDF Generation Failed
```
Error generating PDF report
```
**Solution**: Install wkhtmltopdf

### Debug Mode
Enable verbose logging for detailed troubleshooting:
```bash
python nist_compliance_scanner.py 192.168.1.0/24 --verbose
```

## 📖 NIST SP 800-171 Controls

The scanner currently assesses the following control families:

- **AC (Access Control)**: System access management
- **AT (Awareness and Training)**: Security awareness
- **AU (Audit and Accountability)**: Logging and monitoring
- **CM (Configuration Management)**: System configuration
- **IA (Identification and Authentication)**: User authentication
- **IR (Incident Response)**: Security incident handling
- **MA (Maintenance)**: System maintenance
- **MP (Media Protection)**: Removable media handling
- **PE (Physical and Environmental Protection)**: Physical security
- **PS (Personnel Security)**: Personnel screening
- **RA (Risk Assessment)**: Risk management
- **SA (System and Services Acquisition)**: Secure acquisition
- **SC (System and Communications Protection)**: System protection
- **SI (System and Information Integrity)**: System integrity

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup
```bash
git clone https://github.com/yourusername/nist-compliance-scanner.git
cd nist-compliance-scanner
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

### Code Style
- Follow PEP 8 Python style guidelines
- Add docstrings to all functions and classes
- Include type hints where appropriate
- Write unit tests for new features

## 📄 License

This project is licensed under the GNU General Public License version 3 (GNU GPLv3) - see the [LICENSE](https://github.com/nightstalker117/nistify-800-171r2?tab=GPL-3.0-1-ov-file#readme) file for details.

## ⚠️ Disclaimer

This tool is provided for legitimate security assessment purposes only. Users are responsible for:

- Obtaining proper authorization before scanning networks
- Complying with applicable laws and regulations
- Using the tool in accordance with organizational policies
- Ensuring responsible disclosure of identified vulnerabilities

The authors are not responsible for any misuse of this tool or any damages resulting from its use.

## 🙏 Acknowledgments

- **NIST**: For the SP 800-171 security requirements framework
- **Nmap Project**: For the powerful network scanning capabilities
- **Python Community**: For the excellent libraries and tools
- **Security Researchers**: For continuous improvement suggestions

## 📞 Support

- **Issues**: Report bugs and feature requests on [GitHub Issues](https://github.com/nightstalker117/nistify-800-171r2/issues)
- **Discussions**: Join community discussions on [GitHub Discussions](https://github.com/nightstalker117/nistify-800-171r2/discussions)
- **Documentation**: Additional documentation available in the [Wiki](https://github.com/nightstalker117/nistify-800-171r2/wiki)

## 🗺️ Roadmap

### Upcoming Features
- [*] -- **Enhanced Control Coverage**: Additional NIST SP 800-171 controls --
- [ ] **Database Integration**: PostgreSQL/MySQL support for result storage
- [ ] **REST API**: Web API for integration with other tools
- [ ] **Docker Support**: Containerized deployment options
- [ ] **Scheduled Scanning**: Automated periodic assessments
- [ ] **Vulnerability Integration**: CVE database correlation
- [ ] **Custom Dashboards**: Web-based monitoring interface
- [ ] **SCAP Integration**: Security Content Automation Protocol support

### Version History
- **v1.0.0**: Initial release with basic scanning and reporting
- **v1.1.0**: Added network topology visualization
- **v1.2.0**: Enhanced Windows compatibility and error handling

---

**Made with ❤️**
