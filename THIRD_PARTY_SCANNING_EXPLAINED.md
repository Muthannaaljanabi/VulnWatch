# Third-Party Application Scanning - Quick Reference

## Why Does "Third-Party Apps" Show 0?

There are **three possible reasons** why you see "0" for Third-Party Apps:

### Reason 1: You Didn't Enable Third-Party Scanning (Most Common)
The script has **two modes**:

**Mode 1: Microsoft Only (Default)**
```powershell
.\Check-Vulnerabilities-Dashboard.ps1
```
- Scans ONLY Microsoft products via MSRC
- Third-Party Apps will show **0**
- This is the **default behavior**

**Mode 2: Microsoft + Third-Party (Must Specify)**
```powershell
.\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty
```
- Scans BOTH Microsoft and third-party apps
- Checks Chrome, Firefox, Adobe, Java, VLC, etc.
- Third-Party Apps will show actual count

### Reason 2: No Vulnerable Third-Party Apps Installed
Even with `-IncludeThirdParty` enabled, you might see 0 if:
- ✅ You don't have Chrome, Firefox, Adobe, etc. installed
- ✅ Your third-party apps are already up-to-date
- ✅ The installed versions are not in the known vulnerability database

### Reason 3: Limited Vulnerability Database (Current Limitation)
The current script uses a **basic known-vulnerability database** that includes:
- Google Chrome (sample vulnerabilities)
- Mozilla Firefox (sample vulnerabilities)
- Adobe Acrobat Reader DC (sample vulnerabilities)
- Oracle Java (sample vulnerabilities)
- VLC Media Player (sample vulnerabilities)

**For comprehensive third-party scanning**, you need to integrate with:
- NIST NVD API (National Vulnerability Database)
- Commercial vulnerability scanners (Nessus, Qualys)
- See `VULNERABILITY_COVERAGE_GUIDE.md` for details

## Quick Fix: Enable Third-Party Scanning

### Option 1: Run with Parameter
```powershell
.\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty
```

### Option 2: Run with All Options
```powershell
.\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty -Months 6 -ExportCSV
```

### Option 3: Make it Default
Edit the script and change this line:
```powershell
[Parameter()]
[switch]$IncludeThirdParty,
```

To:
```powershell
[Parameter()]
[switch]$IncludeThirdParty = $true,
```

## What Third-Party Apps Are Checked?

When you run with `-IncludeThirdParty`, the script looks for:

| Application | What It Checks |
|-------------|----------------|
| **Google Chrome** | Version from registry, checks against known CVEs |
| **Mozilla Firefox** | Installed version, checks against known CVEs |
| **Adobe Acrobat Reader** | All Adobe Reader variants |
| **Oracle Java** | Java Runtime Environment (JRE) |
| **VLC Media Player** | VLC version |
| **7-Zip** | Archive utility |
| **WinRAR** | Archive utility |
| **Notepad++** | Text editor |
| **TeamViewer** | Remote access |

## Example Output Comparison

### WITHOUT -IncludeThirdParty (Default)
```
Total Vulnerabilities: 431
  - Microsoft (MSRC): 431
  - Third-Party Apps: 0    ← Shows 0 because not enabled

⚠️  NOTE: Third-party application scanning is DISABLED
   To scan Chrome, Adobe, Firefox, Java, etc., run with:
   .\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty
```

### WITH -IncludeThirdParty
```
Total Vulnerabilities: 475
  - Microsoft (MSRC): 470
  - Third-Party Apps: 5    ← Shows actual count

✓ Third-party scanning enabled
  Found vulnerabilities in:
  • Google Chrome (CVE-2024-0517)
  • Adobe Acrobat Reader (CVE-2024-20747)
  • Java (CVE-2024-20918)
```

## Understanding the Dashboard Display

### Statistics Panel in HTML Dashboard

The dashboard shows **four boxes**:

```
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│ 475             │ 475             │ 0               │ [Script Name]   │
│ TOTAL           │ MICROSOFT       │ THIRD-PARTY     │ UNPATCHED       │
│ VULNERABILITIES │ (MSRC)          │ APPS            │                 │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

- **Total Vulnerabilities**: Sum of all vulnerabilities found
- **Microsoft (MSRC)**: Vulnerabilities from Microsoft products only
- **Third-Party Apps**: Vulnerabilities from Chrome, Adobe, etc.
- **Unpatched Vulnerabilities**: Items that don't have KB patches installed

### When Third-Party Shows 0
The dashboard will display a small red note under the "0":
```
0
THIRD-PARTY APPS
Run with -IncludeThirdParty
```

This reminds you that third-party scanning is not enabled.

## Fixing the "Microsoft.PowerShell.C" Display Issue

The truncated text "Microsoft.PowerShell.C" in the "Unpatched" box has been fixed by:

1. **Increasing box size** to accommodate longer text
2. **Adding word-wrap** for long script names
3. **Better padding** around text

The full script name will now display properly:
```
475
UNPATCHED VULNERABILITIES
```

## Best Practice Recommendations

### For Regular Scans
```powershell
# Weekly Microsoft scan (fast)
.\Check-Vulnerabilities-Dashboard.ps1

# Monthly comprehensive scan (includes third-party)
.\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty -Months 6
```

### For Complete Coverage
```powershell
# Step 1: Run the script with third-party enabled
.\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty -ExportCSV

# Step 2: Use commercial tools for deeper third-party scanning
# - Microsoft Defender for Endpoint
# - Nessus
# - Qualys
```

### For Production Environments
1. **Microsoft products**: Use this script (excellent coverage via MSRC)
2. **Third-party apps**: Use enterprise vulnerability management tools
3. **Combine both**: Export results and consolidate in your SIEM

## Enhancing Third-Party Detection

To get **better third-party vulnerability coverage**, you can:

### Option 1: Integrate with NVD API (Free)
See the example in `VULNERABILITY_COVERAGE_GUIDE.md` for how to integrate with NIST's National Vulnerability Database.

### Option 2: Use Microsoft Defender for Endpoint
If you have a Microsoft 365 E5 or Defender for Endpoint license:
- It automatically scans third-party applications
- Provides vulnerability assessments
- Includes remediation tracking

### Option 3: Deploy Enterprise Vulnerability Scanner
Consider tools like:
- **Nessus Professional** ($2,390/year)
- **Qualys VMDR** (Quote-based)
- **Rapid7 InsightVM** (Quote-based)
- **ManageEngine Vulnerability Manager Plus** (Affordable)

## Testing Third-Party Scanning

To verify third-party scanning is working:

1. **Install a test application** (e.g., Google Chrome)
2. **Run the script with -IncludeThirdParty**
3. **Check the dashboard** - Third-Party Apps count should be > 0

```powershell
# Test run
.\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty -Verbose

# Check output
# Should show: "Checking third-party applications..."
# Should list: Applications found and checked
```

## Summary

| Scenario | Command | Third-Party Count |
|----------|---------|-------------------|
| Default run | `.\Check-Vulnerabilities-Dashboard.ps1` | **0** (not enabled) |
| With third-party | `.\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty` | **Actual count** |
| No vulnerable apps | `.\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty` | **0** (nothing found) |

**Key Takeaway**: The script defaults to **Microsoft-only** scanning. You **must** add `-IncludeThirdParty` to scan Chrome, Adobe, Firefox, and other third-party applications!

## Questions?

- **Q: Why is third-party scanning disabled by default?**
  - A: It's faster to scan only Microsoft products, and most organizations focus on OS/Microsoft vulnerabilities first.

- **Q: Is the third-party database comprehensive?**
  - A: No, it's a basic sample database. For production, integrate with NVD API or use commercial scanners.

- **Q: Can I add more third-party apps to scan?**
  - A: Yes! Edit the `$ThirdPartyVulnerabilities` hashtable in the script to add more applications.

- **Q: Why doesn't it find my outdated Chrome?**
  - A: The script checks against a sample CVE database. You may need to update the vulnerability definitions or integrate with NVD.
