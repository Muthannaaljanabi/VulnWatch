# Intune Deployment Guide - Vulnerability Scanner

## Overview
This guide will walk you through deploying the vulnerability scanner to your 1,000+ Windows devices using Microsoft Intune Proactive Remediations.

**Estimated Time**: 30-45 minutes  
**Skill Level**: Beginner (GUI-focused, no PowerShell knowledge required)  
**Prerequisites**: 
- Intune P1 or P2 license (you have this ✅)
- Intune administrator access
- SharePoint library configured (see SHAREPOINT_SETUP_GUIDE.md)

---

## What is Intune Proactive Remediations?

**Intune Proactive Remediations** (formerly known as "Script Packages") allows you to:
- Run PowerShell scripts on all managed devices
- Schedule automatic execution (daily, weekly, etc.)
- Monitor compliance and execution status
- No manual intervention required

**Perfect for your use case!** The vulnerability scanner will:
- Run bi-weekly on all 1,000+ devices
- Scan for vulnerabilities automatically
- Upload results to SharePoint
- Require zero end-user interaction

---

## Architecture Overview

```
┌──────────────────┐         ┌──────────────────┐
│  Intune Portal   │────────>│  Your Devices    │
│                  │         │  (1,000+ PCs)    │
│ Deploy Script    │         │                  │
│ Set Schedule     │         │ Runs Scan        │
└──────────────────┘         │ Uploads JSON     │
                             └──────────────────┘
                                      │
                                      ▼
                             ┌──────────────────┐
                             │   SharePoint     │
                             │   VulnScans/     │
                             │   CurrentScan/   │
                             └──────────────────┘
                                      │
                                      ▼
                             ┌──────────────────┐
                             │  Your Admin PC   │
                             │  Runs Fleet      │
                             │  Dashboard       │
                             └──────────────────┘
```

---

## Part 1: Prepare the Script for Deployment

### Step 1: Download and Edit the Script

1. **Download the Script**
   - File: `Invoke-VulnerabilityScan-JSON.ps1`
   - Location: From the package provided

2. **Open in Text Editor**
   - Right-click the file
   - Select **Edit** (opens in Notepad or VS Code)

3. **Update SharePoint URL**
   
   Find this line (near the top):
   ```powershell
   [string]$SharePointSiteUrl = "SHAREPOINT_SITE_URL_PLACEHOLDER",
   ```
   
   Replace with YOUR SharePoint URL:
   ```powershell
   [string]$SharePointSiteUrl = "https://contoso.sharepoint.com/sites/VulnerabilityManagement",
   ```
   
   **Replace `contoso` with your actual tenant name!**

4. **Save the File**
   - Press `Ctrl+S` to save
   - Keep the filename as `Invoke-VulnerabilityScan-JSON.ps1`

---

## Part 2: Deploy to Intune

### Step 2: Access Intune Admin Center

1. **Navigate to Intune**
   - Go to: https://Intune.microsoft.com/
   

2. **Sign In**
   - Use your admin account
   - Requires Intune Administrator or Global Administrator role

3. **Navigate to Script Packages**
   - Click **Devices** in the left menu
   - Click **Scripts and remediations**
   - Click **Proactive remediations** tab

---

### Step 3: Create New Remediation Package

1. **Click "+ Create script package"**
   - Button is at the top of the page

2. **Basics Tab**
   
   Fill in these details:
   - **Name**: `Vulnerability Scanner - Bi-Weekly`
   - **Description**: `Scans devices for Microsoft and third-party vulnerabilities. Uploads results to SharePoint for fleet dashboard.`
   - **Publisher**: `IT Security Team`
   - Click **Next**

---

### Step 4: Configure Settings

On the **Settings** tab, configure as follows:

#### Detection Script

1. **Upload Detection Script**
   - Click **Browse** next to "Detection script file"
   - Select: `Invoke-VulnerabilityScan-JSON.ps1`
   - Click **Open**

2. **Configure Detection Script Settings**
   - **Run this script using the logged-on credentials**: ❌ **No** (leave unchecked)
   - **Enforce script signature check**: ❌ **No**
   - **Run script in 64-bit PowerShell**: ✅ **Yes** (check this box)

#### Remediation Script

- **Remediation script file**: Leave empty (we don't need remediation)
- This is DETECTION-ONLY mode

#### Additional Settings

- **Run script in 64-bit PowerShell**: ✅ **Yes**
- **Run this script using the logged-on credentials**: ❌ **No**

**Why these settings?**
- Run as SYSTEM account: Ensures consistent execution regardless of who is logged in
- 64-bit: Required for full system access and MSRC API calls
- No remediation: We're only collecting data, not fixing issues

Click **Next**

---

### Step 5: Configure Scope Tags (Optional)

If your organization uses scope tags:
- Add appropriate tags (e.g., "Production", "Windows Devices")
- Otherwise, leave as default

Click **Next**

---

### Step 6: Assign to Devices

This is where you specify WHICH devices will run the scan.

#### Option A: All Windows Devices (Recommended for Your 1,000+ Device Fleet)

1. **Click "+ Add group"**
2. **Search for**: `All Windows Devices` or similar group
3. **Select the group**
4. **Click Select**

#### Option B: Specific Device Groups

If you want to start with a pilot:

**Pilot Phase (First Week)**
1. Create a test group with 10-20 devices
2. Deploy to test group first
3. Verify uploads to SharePoint
4. Then expand to full deployment

**Production Deployment**
1. **Click "+ Add group"**
2. **Search for**: Your device group
   - Examples:
     - `All Windows 10 Devices`
     - `All Windows 11 Devices`
     - `Corporate Windows Devices`
     - `CONTOSO-All-Computers`
3. **Select** the appropriate group(s)
4. **Click Select**

**Multiple groups?** You can add multiple groups if needed.

#### Exclusions (Optional)

If certain devices should NOT be scanned:
1. Click **+ Add group** under "Exclude"
2. Select devices to exclude (e.g., kiosks, conference room PCs)

Click **Next**

---

### Step 7: Configure Schedule

This is where you set the bi-weekly scan schedule.

#### Schedule Settings

1. **Schedule type**: Select **Schedule**

2. **Frequency**: Configure for bi-weekly
   
   **Option 1: Using Daily with Custom Schedule**
   - Set to **Daily**
   - Manually adjust run days (not ideal)
   
   **Option 2: Using Weekly (Recommended)**
   - Set to **Weekly**
   - Check **Week 1** and **Week 3** (for bi-weekly)
   - OR just select **Weekly** and run every week (safer option)

3. **Start time**: Recommended settings
   - **3:00 AM** (off-hours to minimize user impact)
   - OR **12:00 AM** (midnight)
   - Choose a time when devices are typically on but users are not working

4. **Run script once or every time the user signs in**:
   - Select: **Once**

#### Our Recommendation

**For Your 1,000+ Device Environment:**
```
Schedule type: Schedule
Frequency: Weekly
Day: Every Sunday (or your preference)
Time: 3:00 AM
Run: Once per schedule
```

**Why Sunday at 3 AM?**
- Devices are typically on (not powered off for weekend)
- Users are not working
- Gives IT team Monday morning to review results
- Minimal impact on business operations

Click **Next**

---

### Step 8: Review and Create

1. **Review all settings**
   - Name: `Vulnerability Scanner - Bi-Weekly`
   - Detection script: `Invoke-VulnerabilityScan-JSON.ps1`
   - Run as: System
   - Assignment: All Windows Devices (or your groups)
   - Schedule: Weekly, Sunday, 3:00 AM

2. **Click "Create"**
   - Intune will now create the remediation package
   - This may take 1-2 minutes

3. **Success!**
   - You'll see a confirmation message
   - The package is now deployed

---

## Part 3: Monitor Deployment

### Step 9: Check Deployment Status

1. **Navigate Back to Proactive Remediations**
   - Devices → Scripts and remediations → Proactive remediations

2. **Click on Your Script Package**
   - Name: `Vulnerability Scanner - Bi-Weekly`

3. **View Device Status**
   - Click **Device status** tab
   - You'll see:
     - **Pending**: Devices haven't checked in yet
     - **Succeeded**: Scan completed successfully
     - **Failed**: Scan had errors
     - **Not applicable**: Device doesn't meet requirements

4. **Initial Sync Time**
   - Devices check in every 8 hours by default
   - It may take up to 8 hours for devices to receive the script
   - First scheduled run will be on the scheduled day/time

---

### Step 10: Force Immediate Sync (For Testing)

To test immediately rather than waiting for the schedule:

#### Option A: From a Test Device

1. **RDP or log into a test device**
2. **Open Settings**
   - Windows Settings → Accounts → Access work or school
3. **Click on your work account**
4. **Click "Info"**
5. **Scroll down and click "Sync"**
6. **Wait 5-10 minutes**
7. **Check Event Log**
   - Open Event Viewer
   - Navigate to: Applications and Services Logs → Microsoft → Windows → DeviceManagement-Enterprise-Diagnostics-Provider → Admin
   - Look for "Script executed successfully"

#### Option B: Using Intune Portal (Bulk Sync)

Unfortunately, there's no bulk "force sync" button. You'll need to:
1. Wait for devices to check in naturally (up to 8 hours)
2. OR manually sync a few test devices as shown above

---

### Step 11: Verify SharePoint Uploads

1. **Navigate to SharePoint**
   - Go to your SharePoint site
   - Open: `VulnerabilityScans/CurrentScan/`

2. **Check for JSON Files**
   - You should see files like:
     - `DESKTOP-ABC123_20260215_143022.json`
     - `LAPTOP-XYZ789_20260215_143045.json`
     - etc.

3. **Download and Inspect a JSON File** (Optional)
   - Click on a JSON file
   - Click **Download**
   - Open in Notepad
   - Verify it contains device data and vulnerabilities

4. **First Files Appear When?**
   - If you deployed on a Friday
   - And schedule is Sunday 3 AM
   - First files will appear Sunday morning after 3 AM
   - Could take 30-60 minutes for all 1,000+ devices

---

## Part 4: Troubleshooting

### Issue: Devices Show "Failed" Status

**Steps to Diagnose:**

1. **Click on the Failed Device**
   - In Intune, click the device name

2. **View Error Details**
   - Look at the error message
   - Common errors and solutions below

3. **Common Errors and Solutions**

   **Error: "Access Denied"**
   - **Cause**: SharePoint permissions not configured
   - **Solution**: Review SharePoint setup guide, verify app registration

   **Error: "Cannot connect to MSRC API"**
   - **Cause**: Firewall blocking outbound HTTPS to api.msrc.microsoft.com
   - **Solution**: Allow outbound HTTPS to *.microsoft.com

   **Error: "PnP.PowerShell module not found"**
   - **Cause**: First run, module is installing
   - **Solution**: Wait and check again in 30 minutes. Module installs automatically.

   **Error: "Script execution disabled"**
   - **Cause**: PowerShell execution policy too restrictive
   - **Solution**: Intune scripts bypass execution policy. If this error appears, check device configuration.

4. **Check Event Logs on Device**
   
   On the failing device:
   - Open **Event Viewer**
   - Navigate to: **Application** log
   - Filter by Source: `VulnerabilityScanner`
   - Look for ERROR or WARNING events
   - Read the error details

---

### Issue: No Files in SharePoint

**Checklist:**

✅ **Script has run at least once?**
   - Check Intune device status
   - If all show "Pending", devices haven't checked in yet

✅ **SharePoint URL correct in script?**
   - Verify URL matches your tenant
   - No typos in the site name

✅ **SharePoint permissions configured?**
   - App registration has Sites.ReadWrite.All
   - Admin consent granted

✅ **Devices online during scheduled time?**
   - Devices must be powered on and connected to internet
   - Check device status in Intune

---

### Issue: Some Devices Never Upload

**Possible Causes:**

1. **Devices are Off During Schedule**
   - **Solution**: Device will run on next check-in. Consider changing schedule to business hours for these devices.

2. **Devices Not Intune-Managed**
   - **Solution**: Verify device enrollment status in Intune

3. **Network Connectivity Issues**
   - **Solution**: Check VPN connectivity, firewall rules

4. **Device Group Assignment**
   - **Solution**: Verify device is in assigned group

---

## Part 5: Optimizations and Best Practices

### For Your 1,000+ Device Environment

#### 1. **Stagger Execution Times**

To avoid 1,000+ devices hitting MSRC API simultaneously:

**Option A: Use Multiple Schedules**
- Create 4 remediation packages
- Package 1: Sunday 1 AM (250 devices)
- Package 2: Sunday 2 AM (250 devices)
- Package 3: Sunday 3 AM (250 devices)
- Package 4: Sunday 4 AM (250 devices)

**Option B: Add Random Delay to Script**

Add this to the top of the script (after parameters):
```powershell
# Random delay 0-30 minutes to stagger execution
$delay = Get-Random -Minimum 0 -Maximum 1800
Start-Sleep -Seconds $delay
```

#### 2. **Monitor SharePoint Storage**

With 1,000+ devices uploading bi-weekly:
- Each JSON: ~30 KB
- Per scan: 30 MB
- Per year: ~780 MB

**Recommendations:**
- Archive old scans monthly (move to Archive folder)
- Keep only last 2-3 scans in CurrentScan
- Consider auto-archive Power Automate flow

#### 3. **Set Up Alerting**

Create alerts for:
- Script failures > 5% of devices
- No uploads in 48 hours
- Critical vulnerabilities detected

**Using Intune:**
- Intune → Reports → Script status report
- Create alert rule for failures

**Using SharePoint:**
- Library settings → Alert me
- Alert when no files uploaded in 48 hours

#### 4. **Compliance Policies** (Optional Advanced)

Integrate with Intune Compliance:
1. Create compliance policy based on vulnerability count
2. Devices with >10 critical vulnerabilities = Non-compliant
3. Non-compliant devices flagged for remediation

---

## Part 6: Maintenance

### Weekly Tasks

✅ **Check Intune Status**
   - Review device execution status
   - Investigate any failures

✅ **Verify SharePoint Uploads**
   - Check CurrentScan folder
   - Ensure all devices uploaded

### Bi-Weekly Tasks (After Each Scan)

✅ **Generate Fleet Dashboard**
   - Run `Generate-FleetDashboard.ps1`
   - Review results
   - Share with management

✅ **Archive Old Scans**
   - Move files from CurrentScan to Archive
   - Create dated subfolder (e.g., `Archive/2026-02-15`)

### Monthly Tasks

✅ **Review Failed Devices**
   - Identify persistently failing devices
   - Troubleshoot connectivity or configuration issues

✅ **Update Vulnerability Database** (If using NVD integration)
   - Refresh third-party CVE definitions
   - Update script if needed

### Quarterly Tasks

✅ **Review Script Performance**
   - Execution time trends
   - Storage usage
   - Network impact

✅ **Update Script Version** (If available)
   - Check for updated scripts
   - Test in pilot group
   - Deploy to production

✅ **App Secret Renewal** (If expiring)
   - Renew Azure AD app secret
   - Update in SharePoint setup

---

## Part 7: Rollback Plan

If you need to disable or remove the scanner:

### Disable Scans

1. **Navigate to Proactive Remediations**
2. **Click your script package**
3. **Click "Properties"**
4. **Change Assignment to "None"**
5. **Save**

Devices will stop receiving the script on next check-in.

### Complete Removal

1. **Navigate to Proactive Remediations**
2. **Select your script package**
3. **Click "Delete"**
4. **Confirm deletion**

---

## Quick Reference Card

### Deployment Checklist

✅ **Prerequisites**
- [ ] SharePoint site created
- [ ] Document library configured
- [ ] App registration completed
- [ ] Script edited with SharePoint URL

✅ **Intune Deployment**
- [ ] Script package created
- [ ] Detection script uploaded
- [ ] Run as System (not user)
- [ ] 64-bit PowerShell enabled
- [ ] Device groups assigned
- [ ] Schedule configured (bi-weekly)

✅ **Verification**
- [ ] Devices showing in Intune status
- [ ] JSON files appearing in SharePoint
- [ ] Fleet dashboard generates successfully

✅ **Monitoring Setup**
- [ ] Alerts configured
- [ ] Maintenance schedule established
- [ ] Documentation updated

---

## Support and Resources

### Getting Help

**Intune Issues:**
- Microsoft Intune Admin Center: https://endpoint.microsoft.com/
- Microsoft Docs: https://docs.microsoft.com/mem/intune/

**SharePoint Issues:**
- SharePoint Admin Center: https://admin.microsoft.com/sharepoint
- PnP PowerShell Docs: https://pnp.github.io/powershell/

**Script Issues:**
- Check Event Viewer on device
- Review Intune device status logs
- Contact: IT Security Team

### Internal Contacts

- **Intune Administrator**: [Name] <[Email]>
- **SharePoint Administrator**: [Name] <[Email]>
- **IT Security Lead**: [Name] <[Email]>

---

## Success Criteria

Your deployment is successful when:

✅ **All devices checked in** (or >95%)  
✅ **JSON files in SharePoint** from all devices  
✅ **Fleet dashboard generates** without errors  
✅ **No critical failures** in Intune status  
✅ **Team can access** and understand dashboard  

---

## Next Steps

✅ **Intune deployment complete!**

**Next: Generate Your First Fleet Dashboard**
- See: `ADMIN_QUICKSTART.md`
- Run `Generate-FleetDashboard.ps1`
- View fleet-wide vulnerability posture

**Then: Establish Remediation Process**
- Prioritize Critical and High vulnerabilities
- Create patching schedules
- Track remediation progress

---

## Appendix: Example Configurations

### Small Pilot (10 devices)
```
Assignment: Pilot-Devices group (10 devices)
Schedule: Daily, 2 PM
Purpose: Testing and validation
```

### Production Deployment (1,000+ devices)
```
Assignment: All Windows Devices
Schedule: Weekly, Sunday, 3 AM
Purpose: Full fleet scanning
```

### Aggressive Scanning (Weekly)
```
Assignment: High-Risk Devices group
Schedule: Weekly, Multiple times
Purpose: Critical infrastructure monitoring
```

---

**Congratulations!** Your vulnerability scanner is now deployed across your entire fleet! 🎉
