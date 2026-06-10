# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Yes    |
| < 2.0   | ❌ No     |

Only the latest 2.x release receives security updates. Please upgrade before
reporting an issue against an older version.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
**privately** — do not open a public issue, pull request, or discussion that
describes the vulnerability before a fix is available.

Preferred method:

1. **GitHub Private Vulnerability Reporting** — go to the **Security** tab of this
   repository and click **Report a vulnerability**. (Maintainer: enable this under
   *Settings → Code security → Private vulnerability reporting*.)

Alternative method:

2. **Email** — contact the maintainer at **<Support@txtechsquad.com>**.
   Use a clear subject line such as `VulnWatch security report`.

Please include, where possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof of concept
- The version/commit affected
- Any suggested remediation

## Response Expectations

- **Acknowledgement:** we aim to confirm receipt within **5 business days**.
- **Assessment:** an initial assessment and severity rating will follow.
- **Remediation window:** please allow up to **90 days** for a fix before any
  public disclosure. We will coordinate a disclosure timeline with you.
- **Credit:** with your permission, we are happy to credit you in the release notes.

## Scope

In scope:

- Vulnerabilities in the PowerShell scripts and modules in this repository
  (e.g. command injection, insecure handling of credentials or output files,
  path traversal, insecure deserialization).
- Documentation that could lead a user to an insecure configuration.

Out of scope:

- Vulnerabilities in third-party services this project queries
  (Microsoft Graph, MSRC, NVD) — report those to the respective vendor.
- Issues that require the operator to deliberately misconfigure the tool or run
  it without authorization.
- The accuracy or completeness of vulnerability data returned by MSRC or NVD;
  that data is supplied by those third parties.

## A Note on This Project

This is a security tool that handles **credentials and sensitive vulnerability
data**. To keep your own deployment secure:

- **Never commit real secrets.** No tenant IDs, client IDs, client secrets, API
  keys, or SharePoint URLs should appear in source control. Use environment
  variables or a local, git-ignored config file (see `CONFIGURATION_GUIDE.md`).
- **Rotate the client secret** before it expires, and immediately if it is ever
  exposed.
- Treat generated output files (JSON, CSV, HTML) as sensitive — they may contain
  hostnames, CVEs, and patch status for real systems.

Thank you for helping keep this project and its users safe.
