# Disclaimer

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND**, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. In no event shall the authors or
copyright holders be liable for any claim, damages, or other liability, whether in
an action of contract, tort, or otherwise, arising from, out of, or in connection
with the software or the use or other dealings in the software.

## Use at your own risk

- Test thoroughly in a **non-production environment** before deploying across a fleet.
- The scripts read system information, query external APIs, and write data to
  SharePoint/Planner. Review the code and understand what it does before running it
  with elevated or application-level permissions.

## Not affiliated with Microsoft

This is an **independent, community-maintained project**. It is **not affiliated with,
endorsed by, sponsored by, or supported by Microsoft Corporation**. Product names such
as *MSRC, Microsoft Entra, Microsoft Intune, Microsoft Defender, SharePoint Online,*
and *Microsoft Planner* are trademarks of Microsoft Corporation and are used here for
descriptive and interoperability purposes only.

## Third-party data and APIs

This project queries the Microsoft Security Response Center (MSRC) API, the National
Vulnerability Database (NVD), and Microsoft Graph. You are responsible for:

- Complying with each provider's **terms of use and rate limits**.
- Obtaining and securing your own **API keys and credentials**.
- The accuracy and completeness of vulnerability data, which is **provided by those
  third parties** and may contain errors or omissions.

## Your responsibility

- Scan only devices and systems you are **explicitly authorized** to assess.
- Output files (JSON, CSV, HTML) may contain **sensitive vulnerability and system data** —
  classify, store, and share them according to your organization's policies.
- **No secrets are included in this repository.** You must supply your own tenant ID,
  client ID, client secret, NVD API key, SharePoint URL, and Drive ID. Never commit
  real secrets — keep them in environment variables or a local, git-ignored config file.

By using this software you accept these terms.
