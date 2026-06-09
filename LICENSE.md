# MIT License

Copyright (c) 2026 Matt/ Texas Tech Squad 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

# ⚠️ IMPORTANT DISCLAIMER AND TERMS OF USE

## Legal Notice & Intended Use

### Purpose and Scope

This software is designed exclusively for **legitimate vulnerability assessment and security monitoring** within organizations where you have **proper authorization and legal rights**. 

### Permitted Uses ✅

This tool is intended for:

- ✅ **Internal vulnerability management** within your organization
- ✅ **Compliance and audit reporting** (PCI-DSS, ISO 27001, HIPAA, SOC 2, etc.)
- ✅ **Security monitoring and remediation tracking**
- ✅ **IT operations and patch management**
- ✅ **Risk assessment and mitigation**
- ✅ **Educational purposes** in controlled lab environments

### Prohibited Uses ❌

This software must **NOT** be used for:

- ❌ **Unauthorized scanning** of systems you do not own or manage
- ❌ **Malicious purposes** or exploitation of vulnerabilities
- ❌ **Circumventing security controls** or access restrictions
- ❌ **Any illegal activities** under applicable laws
- ❌ **Commercial redistribution** without proper attribution
- ❌ **Scanning third-party systems** without explicit written permission

---

## Licensing and Compliance Requirements

### Microsoft Licenses Required

To use this software, you must have appropriate Microsoft licenses:

**Required Licenses:**
- ✅ **Microsoft Intune P1 or P2** (for automated deployment)
- ✅ **Microsoft 365 E3, E5, or Business Premium** (for SharePoint and Planner)
- ✅ **Appropriate Windows licenses** for all scanned devices

**Your Responsibilities:**
- Verify you have proper licenses before deployment
- Comply with Microsoft Terms of Service
- Maintain active subscriptions for continued use
- Ensure license compliance across all scanned devices

### Third-Party API Usage

**NVD API (NIST National Vulnerability Database):**
- Free API provided by the U.S. Government
- Subject to NVD's terms of use: https://nvd.nist.gov/general/legal-disclaimer
- Rate limited to 50 requests per 30 seconds (with API key)
- Must comply with all NVD usage terms

**MSRC API (Microsoft Security Response Center):**
- Free API provided by Microsoft
- Subject to Microsoft's terms of service
- Must comply with Microsoft API usage guidelines

### Data Protection and Privacy

**GDPR Compliance (if applicable):**
- This tool processes vulnerability data that may contain personal information
- You are the **data controller** and must ensure GDPR compliance
- Implement appropriate data retention and deletion policies
- Provide privacy notices to users whose devices are scanned

**Other Privacy Regulations:**
- CCPA (California Consumer Privacy Act)
- PIPEDA (Canada)
- Any applicable regional privacy laws

**Your Responsibilities:**
- ✅ Ensure compliance with all applicable data protection laws
- ✅ Secure API keys and credentials
- ✅ Control access to vulnerability reports (they contain sensitive data)
- ✅ Implement data retention and deletion policies
- ✅ Provide appropriate privacy notices
- ✅ Maintain audit logs of system access

---

## No Warranty and Limitation of Liability

### No Warranty

**THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.**

The authors and contributors:

- ⚠️ Make **NO guarantees** about accuracy of vulnerability detection
- ⚠️ Are **NOT responsible** for missed vulnerabilities or false positives
- ⚠️ **DO NOT guarantee** fitness for any particular purpose
- ⚠️ Provide **NO official support** or service level agreements (SLA)
- ⚠️ Make **NO claims** about completeness or reliability

### Accuracy and Limitations

**This tool:**

- ✅ Provides vulnerability information from public sources (MSRC, NVD)
- ⚠️ **May not detect all vulnerabilities** present on a system
- ⚠️ **May produce false positives** (flagging non-vulnerable systems)
- ⚠️ **May produce false negatives** (missing actual vulnerabilities)
- ⚠️ **Depends on third-party APIs** which may be incomplete or outdated
- ⚠️ Should be used as **ONE component** of a comprehensive security program

**This tool does NOT:**

- ❌ Replace professional security assessments or penetration testing
- ❌ Guarantee complete vulnerability coverage
- ❌ Automatically remediate vulnerabilities
- ❌ Provide legal or compliance advice
- ❌ Constitute a security certification or validation

### Limitation of Liability

**IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY**, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software, **INCLUDING BUT NOT LIMITED TO:**

- **Lost data** or data corruption
- **Security breaches** or incidents resulting from use
- **Missed vulnerabilities** or false negatives
- **False positives** or incorrect vulnerability reports
- **Compliance violations** or audit failures
- **Business interruption** or system downtime
- **Financial losses** of any kind
- **Reputational damage**
- **Legal liability** or regulatory penalties
- Any **direct, indirect, incidental, special, exemplary, or consequential damages**
- Any **damages whatsoever**, even if advised of the possibility

**Maximum Liability:**
In no event shall the total liability of the authors or contributors exceed **ZERO DOLLARS ($0.00)**.

---

## Professional Advice and Testing

### Before Production Deployment

**You MUST:**

- ⚠️ **Test thoroughly** in a non-production environment first
- ⚠️ **Validate results** against known vulnerabilities
- ⚠️ **Review all generated reports** for accuracy before using for decisions
- ⚠️ **Ensure compliance** with organizational policies and procedures
- ⚠️ **Obtain proper approvals** from management and legal teams
- ⚠️ **Document your testing** and validation process

### Consult Qualified Professionals

**For the following, consult with qualified professionals:**

- **Legal counsel** - For legal compliance and authorization questions
- **Information security professionals** - For comprehensive security assessments
- **Compliance officers** - For regulatory compliance requirements
- **Network architects** - For deployment planning and network security
- **Privacy officers** - For data protection and privacy compliance

---

## Compliance and Audit Reporting

### No Guarantee of Compliance

**Important:** This tool may **assist** with compliance requirements, but:

- ⚠️ Does **NOT guarantee** compliance with any standard or regulation
- ⚠️ **Should be reviewed** by qualified compliance professionals
- ⚠️ **May require additional controls** for regulated industries
- ⚠️ **Compliance interpretations** are your sole responsibility

### Standards Addressed

While this tool provides templates for:
- PCI-DSS (Payment Card Industry Data Security Standard)
- ISO 27001 (Information Security Management)
- HIPAA (Health Insurance Portability and Accountability Act)
- NIST CSF (Cybersecurity Framework)
- SOC 2 (Service Organization Control 2)

**These templates:**
- Are provided as **starting points only**
- Must be **customized** to your specific environment
- Should be **reviewed by auditors** before submission
- Do **NOT guarantee** audit or compliance success

---

## Modifications and Redistribution

### Permitted Modifications

Under the MIT License, you **MAY**:

- ✅ Modify the software for internal use
- ✅ Fork and create derivative works
- ✅ Distribute modified versions (with proper attribution)

**If you modify this software:**

- ⚠️ **Modified versions may behave differently** than the original
- ⚠️ **You are responsible** for testing and validating changes
- ⚠️ **You assume all liability** for your modifications
- ⚠️ Consider **contributing improvements** back to the project

### Attribution Requirements

When redistributing or using this software:

- ✅ **Include this license** and copyright notice
- ✅ **Provide attribution** to the original authors
- ✅ **Indicate if changes were made**

---

## Security and Vulnerability Disclosure

### Responsible Disclosure

If you discover security vulnerabilities in this software:

1. **DO NOT** disclose publicly until a fix is available
2. **Report to**: [your-email@company.com]
3. Allow **90 days** for remediation before public disclosure
4. See [SECURITY.md](.github/SECURITY.md) for full policy

### No Security Guarantees

The authors:
- Make **NO claims** about the security of this software itself
- Are **NOT liable** for security vulnerabilities in the code
- Provide **NO guarantees** of timely security updates
- Recommend **regular security reviews** of any deployed code

---

## Support and Maintenance

### No Official Support

**This is open-source software with:**

- ❌ **No official support** channels
- ❌ **No service level agreements** (SLAs)
- ❌ **No guaranteed response** times
- ❌ **No professional services** available

**Community support only:**
- GitHub Issues for bug reports
- GitHub Discussions for questions
- Pull requests for contributions
- No phone or email support

### No Guarantee of Updates

- ⚠️ Updates and bug fixes are **at the maintainers' discretion**
- ⚠️ **No commitment** to ongoing maintenance
- ⚠️ **No roadmap guarantees** for future features
- ⚠️ **You are responsible** for keeping your deployment updated
- ⚠️ Monitor the GitHub repository for updates and security patches

---

## Third-Party Dependencies

This software relies on:

- **Microsoft MSRC API** - Microsoft's vulnerability database
- **NIST NVD API** - U.S. Government vulnerability database  
- **Microsoft Graph API** - For Planner integration
- **PowerShell modules** - PnP.PowerShell and others

**Acknowledgment:**

- These services **may change** or become unavailable
- API **rate limits** may affect functionality
- **Third-party terms of service** apply to all external services
- **No warranties** provided for third-party services

---

## Jurisdiction and Applicable Law

This software and license shall be governed by the laws of **[Your Jurisdiction]**, without regard to conflict of law principles.

Any disputes shall be resolved in the courts of **[Your Jurisdiction]**.

---

## Export Control

This software may be subject to export control laws and regulations. You are responsible for complying with all applicable export control laws when using or distributing this software.

---

## User Agreement

**By using this software, you acknowledge that you have:**

- ✅ **Read and understood** this entire license and disclaimer
- ✅ **Agreed to all terms** and conditions
- ✅ **Accepted all risks** associated with use
- ✅ **Obtained proper authorization** to scan systems
- ✅ **Verified proper licensing** (Microsoft, etc.)
- ✅ **Agreed to indemnify** the authors against any claims
- ✅ **Understand** that this software is provided without warranty

**If you do not agree with these terms, DO NOT use this software.**

---

## Indemnification

You agree to **indemnify, defend, and hold harmless** the authors, contributors, and copyright holders from any and all claims, damages, liabilities, costs, and expenses (including reasonable attorneys' fees) arising from:

- Your use or misuse of this software
- Your violation of these terms
- Your violation of any laws or regulations
- Any unauthorized scanning or security testing
- Any data breaches or security incidents
- Any claims by third parties related to your use

---

## Severability

If any provision of this license is found to be unenforceable or invalid, that provision shall be limited or eliminated to the minimum extent necessary, and the remaining provisions shall remain in full force and effect.

---

## Changes to This License

The authors reserve the right to update this license and disclaimer at any time. Continued use of the software after changes constitutes acceptance of the modified terms.

Check the GitHub repository for the latest version of this license.

---

## Questions About This License?

For questions about this license or terms of use:

- **Email**: [support@txtechsquad.com]
- **GitHub Issues**: https://github.com/Muthannaaljanabi/VulnWatch/issues
- **Legal Counsel**: Consult your own attorney for legal questions

---

**IMPORTANT: This software is provided for legitimate security purposes only. Unauthorized use is prohibited. Use at your own risk.**

**Last Updated**: June 2026  
**Version**: 2.0.0
