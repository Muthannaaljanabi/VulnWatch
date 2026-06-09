# SharePoint Setup Guide for Vulnerability Management

## Overview
This guide will walk you through setting up a SharePoint document library to store vulnerability scan results from your 1,000+ devices.

**Estimated Time**: 15-20 minutes  
**Skill Level**: Beginner (GUI-focused)  
**Prerequisites**: SharePoint site administrator access

---

## Step 1: Create SharePoint Site (If You Don't Have One)

### Option A: Use Existing Site
If you already have a SharePoint site for IT or Security, you can use that. Skip to Step 2.

### Option B: Create New Site

1. **Navigate to SharePoint Admin Center**
   - Go to: https://admin.microsoft.com/
   - Click **SharePoint** in the left menu
   - Click **Active sites**

2. **Create New Site**
   - Click **+ Create** button
   - Select **Team site** (recommended) or **Communication site**

3. **Configure Site Settings**
   - **Site name**: `Vulnerability Management`
   - **Site address**: `/sites/VulnerabilityManagement` (or your preference)
   - **Privacy settings**: Private (recommended for security data)
   - **Language**: English
   - Click **Finish**

4. **Add Site Members**
   - Add your IT Security team
   - Add admin accounts that will run the aggregation script
   - Set appropriate permissions:
     - **Owners**: IT Security admins
     - **Members**: IT staff who need to view reports
     - **Visitors**: Management (read-only)

**Your SharePoint Site URL will be:**
```
https://[YourTenant].sharepoint.com/sites/VulnerabilityManagement
```
**📝 Note**: Copy this URL - you'll need it later!

---

## Step 2: Create Document Library Structure

### Create Main Library

1. **Navigate to Your Site**
   - Open: `https://[YourTenant].sharepoint.com/sites/VulnerabilityManagement`

2. **Create New Document Library**
   - Click **+ New** (top left)
   - Select **Document library**
   - Name: `VulnerabilityScans`
   - Description: `Storage for device vulnerability scan results`
   - Click **Create**

### Create Folder Structure

1. **Open the VulnerabilityScans Library**
   - Click on the library name in the left navigation

2. **Create Folders**
   Click **+ New** → **Folder** and create these folders:

   **Folder 1: CurrentScan**
   - Name: `CurrentScan`
   - Purpose: Stores the latest JSON scan files from all devices
   
   **Folder 2: Archive**
   - Name: `Archive`
   - Purpose: Stores historical scans for trend analysis
   - Create subfolders by date (optional):
     - `2026-02-15`
     - `2026-02-01`
     - `2026-01-15`
     - etc.
   
   **Folder 3: Dashboards**
   - Name: `Dashboards`
   - Purpose: Stores generated HTML fleet dashboards
   
   **Folder 4: Documentation**
   - Name: `Documentation`
   - Purpose: Stores guides and reference materials

Your structure should look like:
```
VulnerabilityScans/
├── CurrentScan/        ← Devices upload here
├── Archive/            ← Historical data
├── Dashboards/         ← Generated reports
└── Documentation/      ← Guides
```

---

## Step 3: Configure Library Permissions

### Set Appropriate Access Levels

1. **Open Library Settings**
   - Click the **gear icon** (⚙️) → **Library settings**
   - Click **Permissions for this document library**

2. **Break Permission Inheritance** (if needed)
   - Click **Stop Inheriting Permissions**
   - Confirm by clicking **OK**

3. **Configure Permissions**

   **For IT Security Team (Full Access):**
   - Click **Grant Permissions**
   - Add: `IT-Security-Team@company.com`
   - Permission level: **Edit** or **Full Control**
   - Uncheck "Send an email invitation"
   - Click **Share**

   **For IT Staff (View Reports):**
   - Click **Grant Permissions**
   - Add: `IT-Staff@company.com`
   - Permission level: **Read**
   - Click **Share**

   **For Management (View Only):**
   - Click **Grant Permissions**
   - Add: `Management@company.com`
   - Permission level: **Read**
   - Access only to `Dashboards` folder

4. **Configure Folder-Specific Permissions** (Optional)
   
   For tighter security, set different permissions on each folder:
   
   **CurrentScan folder:**
   - Devices (managed identity): **Contribute**
   - IT Security: **Full Control**
   - Others: **No Access**
   
   **Dashboards folder:**
   - Everyone: **Read**
   - IT Security: **Edit**

---

## Step 4: Enable Versioning (Recommended)

### Why Versioning?
- Keeps history of changes
- Allows rollback if needed
- Tracks who uploaded what

### Enable Version History

1. **Go to Library Settings**
   - Click **gear icon** → **Library settings**

2. **Configure Versioning Settings**
   - Click **Versioning settings**
   - Enable: **Create major versions**
   - Set: **Number of versions to retain** = `10`
   - Enable: **Require content approval** = `No` (for automatic uploads)
   - Click **OK**

---

## Step 5: Register App Principal (For Managed Identity Upload)

This step allows devices to upload files using their managed identity (device-based authentication).

### Option A: Using Azure AD App Registration (Recommended)

1. **Navigate to Azure Portal**
   - Go to: https://portal.azure.com/
   - Search for: **Azure Active Directory**

2. **Create App Registration**
   - Click **App registrations** → **+ New registration**
   - Name: `Vulnerability Scanner Service`
   - Supported account types: **Accounts in this organizational directory only**
   - Redirect URI: Leave blank
   - Click **Register**

3. **Note Application Details**
   📝 Copy these values:
   - **Application (client) ID**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
   - **Directory (tenant) ID**: `yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy`

4. **Create Client Secret**
   - Click **Certificates & secrets**
   - Click **+ New client secret**
   - Description: `Vulnerability Scanner Upload`
   - Expires: **24 months** (or per your policy)
   - Click **Add**
   - 📝 **Copy the secret value immediately** (you won't see it again!)

5. **Grant SharePoint Permissions**
   - Click **API permissions**
   - Click **+ Add a permission**
   - Select **SharePoint**
   - Select **Application permissions**
   - Check: `Sites.ReadWrite.All`
   - Click **Add permissions**
   - Click **Grant admin consent for [Your Organization]**
   - Click **Yes** to confirm

### Option B: Using SharePoint App-Only Authentication (Alternative)

If you prefer SharePoint-native authentication:

1. **Navigate to SharePoint App Registration Page**
   - Go to: `https://[YourTenant].sharepoint.com/sites/VulnerabilityManagement/_layouts/15/appregnew.aspx`

2. **Generate App Details**
   - Click **Generate** next to Client Id
   - Click **Generate** next to Client Secret
   - 📝 Copy both values
   - App Domain: `localhost`
   - Redirect URI: `https://localhost`
   - Click **Create**

3. **Grant App Permissions**
   - Navigate to: `https://[YourTenant].sharepoint.com/sites/VulnerabilityManagement/_layouts/15/appinv.aspx`
   - Paste the Client ID
   - Click **Lookup**
   - In the Permission Request XML field, paste:
   ```xml
   <AppPermissionRequests AllowAppOnlyPolicy="true">
       <AppPermissionRequest Scope="http://sharepoint/content/sitecollection/web" Right="Write"/>
   </AppPermissionRequests>
   ```
   - Click **Create**
   - Click **Trust It**

---

## Step 6: Test Upload Access

### Manual Test Upload

1. **Open CurrentScan Folder**
   - Navigate to: `VulnerabilityScans/CurrentScan`

2. **Upload Test File**
   - Click **+ New** → **Files**
   - Select any file (e.g., test.txt)
   - Click **Open**

3. **Verify Upload**
   - Check that file appears in the folder
   - Try downloading it
   - Delete the test file

### Programmatic Test (PowerShell)

Run this test script to verify app authentication:

```powershell
# Install module
Install-Module -Name "PnP.PowerShell" -Force -AllowClobber

# Connect
$siteUrl = "https://[YourTenant].sharepoint.com/sites/VulnerabilityManagement"
Connect-PnPOnline -Url $siteUrl -Interactive

# Test upload
$testFile = "C:\temp\test.json"
"{ 'test': 'data' }" | Out-File $testFile

Add-PnPFile -Path $testFile -Folder "VulnerabilityScans/CurrentScan"

# Verify
Get-PnPFolderItem -FolderSiteRelativeUrl "VulnerabilityScans/CurrentScan"

# Cleanup
Remove-PnPFile -ServerRelativeUrl "VulnerabilityScans/CurrentScan/test.json" -Force

# Disconnect
Disconnect-PnPOnline
```

If this works, your SharePoint is configured correctly! ✅

---

## Step 7: Configure Alerts (Optional but Recommended)

### Set Up Alert for New Scan Results

1. **Navigate to CurrentScan Folder**
2. **Create Alert**
   - Click **...** (More options)
   - Select **Alert me**
   - Configure:
     - Alert title: `New Vulnerability Scans Uploaded`
     - Send alerts: To your email
     - When: `New items are added`
     - Frequency: `Send a daily summary`
   - Click **OK**

---

## Step 8: Document Your Configuration

Create a document in the `Documentation` folder with:

### Your Configuration Details

```
SharePoint Configuration - Vulnerability Management
====================================================

Site URL: https://[YourTenant].sharepoint.com/sites/VulnerabilityManagement
Document Library: VulnerabilityScans

Application Registration:
- App Name: Vulnerability Scanner Service
- Client ID: [Your Client ID]
- Tenant ID: [Your Tenant ID]
- Secret Expiration: [Date]

Permissions:
- IT Security Team: Full Control
- IT Staff: Read
- Management: Read (Dashboards only)
- Devices (App): Contribute (CurrentScan only)

Folder Structure:
- CurrentScan: Latest device scans (auto-uploaded)
- Archive: Historical scans for trend analysis
- Dashboards: Generated fleet dashboards
- Documentation: Guides and references

Contacts:
- SharePoint Admin: [Name] <email@company.com>
- IT Security Lead: [Name] <email@company.com>

Last Updated: [Date]
```

---

## Step 9: Upload Supporting Documents

Upload these files to the `Documentation` folder:

1. This SharePoint setup guide
2. Intune deployment guide (from next file)
3. Admin quick start guide
4. PowerShell scripts (as reference)

---

## Step 10: Configure Intune Scripts

Now that SharePoint is ready, update your Intune deployment script with the SharePoint URL.

**In the script `Invoke-VulnerabilityScan-JSON.ps1`:**

Replace this line:
```powershell
[string]$SharePointSiteUrl = "SHAREPOINT_SITE_URL_PLACEHOLDER",
```

With your actual URL:
```powershell
[string]$SharePointSiteUrl = "https://[YourTenant].sharepoint.com/sites/VulnerabilityManagement",
```

---

## Troubleshooting

### Issue: "Access Denied" When Uploading

**Solution**:
1. Check app registration permissions
2. Verify Sites.ReadWrite.All permission is granted
3. Ensure admin consent was given
4. Check library permissions

### Issue: "Library Not Found"

**Solution**:
1. Verify library name is exactly `VulnerabilityScans`
2. Check that library was created in the correct site
3. Ensure folder structure exists: `VulnerabilityScans/CurrentScan`

### Issue: Devices Can't Upload

**Solution**:
1. Check managed identity is enabled in Intune
2. Verify app principal has correct permissions
3. Test with Connect-PnPOnline using app credentials
4. Check Azure AD app registration is not expired

### Issue: Too Many Files in CurrentScan

**Solution**:
Create a Power Automate flow to archive old files:
1. Trigger: When a file is created in CurrentScan
2. Condition: File age > 7 days
3. Action: Move file to Archive folder

---

## Maintenance Tasks

### Weekly
- ✅ Verify devices are uploading scans
- ✅ Check for failed uploads in Event Log
- ✅ Review storage usage

### Monthly
- ✅ Archive old scans (move from CurrentScan to Archive)
- ✅ Clean up test files
- ✅ Review permissions
- ✅ Check app secret expiration date

### Quarterly
- ✅ Review and update permissions
- ✅ Audit access logs
- ✅ Update documentation
- ✅ Test disaster recovery

---

## Next Steps

✅ SharePoint is now configured and ready!

**Next: Deploy to Intune**
- See: `INTUNE_DEPLOYMENT_GUIDE.md`
- Deploy the scan script to your 1,000+ devices
- Schedule bi-weekly scans

**Questions?**
Contact your SharePoint administrator or IT Security team.

---

## Quick Reference Card

**SharePoint Site URL**: `https://[YourTenant].sharepoint.com/sites/VulnerabilityManagement`

**Key Locations**:
- Device uploads: `/VulnerabilityScans/CurrentScan/`
- Fleet dashboards: `/VulnerabilityScans/Dashboards/`
- Historical data: `/VulnerabilityScans/Archive/`

**Permissions**:
- Devices: Contribute (upload only)
- IT Security: Full Control
- IT Staff: Read
- Management: Read (Dashboards)

**Support**:
- SharePoint Admin: [Name] <[Email]>
- IT Security: [Name] <[Email]>
