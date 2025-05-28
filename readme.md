# XIQ-AD-User-Sync

## Project Overview

This project automates the synchronization of Active Directory (AD) users with ExtremeCloud IQ (XIQ) Private Pre-Shared Key (PPSK) user groups. It is designed to streamline onboarding and offboarding of users and devices for Wi-Fi access, leveraging AD group membership to manage XIQ PPSK users and optionally Private Client Groups (PCGs).

PPSK is a solution provided by Extreme Networks that allows each user or device to have a unique Wi-Fi key on the same SSID, improving security and reducing the need for multiple SSIDs. This script ensures that your AD group membership is always reflected in XIQ PPSK user groups, including automatic removal of users who are disabled or removed from AD groups.

## Key Features
- **Automated Sync:** Creates and removes PPSK users in XIQ based on AD group membership.
- **PCG Support:** Optionally manages Private Client Groups for advanced segmentation.
- **Logging:** All actions and errors are logged for auditing and troubleshooting.
- **Customizable:** Easily map AD groups to XIQ user group IDs and policies.

## Typical Use Cases
- Identity for IoT devices
- BYOD for employees
- Staff device onboarding
- Secure guest onboarding (time-based keys with employee sponsorship)
- Hospitality verticals using Private Client Groups (PCGs)
- Third-party integrations via API

## Requirements
- Python 3.x
- Access to your AD server and XIQ API credentials
- Install dependencies:

```powershell
pip install -r requirements.txt
```

## Quick Start
1. **Configure Credentials:**
   - Edit `XIQ-AD-PPSK-Sync.py` and set your AD and XIQ credentials.
   - Map your AD groups to XIQ user group IDs in the `group_roles` variable.
2. **Run the Script:**
   - Execute the sync with:
     ```powershell
     python XIQ-AD-PPSK-Sync.py
     ```
3. **Check Logs:**
   - Review `XIQ-AD-PPSK-sync.log` for details on actions and errors.

## Example Code Snippet
Retrieve and print AD users:
```python
ad_users = retrieveADUsers("CN=MyGroup,OU=Groups,DC=example,DC=com")
for user in ad_users:
    print(user.name, user.mail)
```

## Additional Notes
- Each AD user must have a unique email address for correct operation.
- For advanced PCG integration, see the documentation in `DOCUMENTATION.md`.
- For troubleshooting or more details, see the included `XIQ-AD-PPSK-Sync-Guide.docx`.
