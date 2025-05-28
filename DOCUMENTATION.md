# XIQ-AD-User-Sync Documentation

## Overview

This project automates the synchronization of Active Directory (AD) users with ExtremeCloud IQ (XIQ) Private Pre-Shared Key (PPSK) user groups. It is designed to streamline onboarding and offboarding of users and devices for Wi-Fi access, leveraging AD group membership to manage XIQ PPSK users and optionally Private Client Groups (PCGs).

---

## Requirements

Install dependencies using pip:

```powershell
pip install -r requirements.txt
```

**requirements.txt:**
```
requests
ldap3
pycryptodome
```

---

## Configuration

Edit the following variables in `XIQ-AD-PPSK-Sync.py` and `AD_Test.py`:

```python
server_name = "enter the server name/ IP"
domain_name = "enter the domain name"
user_name = "enter AD username"
password = " enter AD password"
# For XIQ:
XIQ_token = "****"
# Or use XIQ_username and XIQ_password
```

Set up AD groups and XIQ user group IDs:

```python
group_roles = [
    ("AD Group Distinguished Name", "XIQ User Group ID"),
    # Add more as needed
]
```

---

## Main Script: XIQ-AD-PPSK-Sync.py

### Purpose
- Syncs AD users to XIQ PPSK user groups.
- Optionally manages Private Client Groups (PCGs) if enabled.

### Usage

Run the script:

```powershell
python XIQ-AD-PPSK-Sync.py
```

### Key Functions

#### Retrieve AD Users

```python
def retrieveADUsers(ad_group):
    # Connects to AD and retrieves users in the specified group
    # Returns a list of user entries
```

**Example:**
```python
ad_users = retrieveADUsers("CN=MyGroup,OU=Groups,DC=example,DC=com")
```

#### Create PPSK User

```python
def createPPSKuser(name, mail, usergroupID):
    # Creates a PPSK user in XIQ
```

**Example:**
```python
createPPSKuser("jdoe", "jdoe@example.com", "12345")
```

#### Delete User

```python
def deleteUser(userId):
    # Deletes a PPSK user from XIQ by user ID
```

**Example:**
```python
deleteUser("67890")
```

#### Main Logic
- Collects all AD users and XIQ PPSK users.
- Adds new users to XIQ if present in AD but not in XIQ.
- Removes users from XIQ if not present in AD.
- Handles disabled AD accounts.
- Optionally manages PCG membership.

---

## Testing AD Connectivity: AD_Test.py

Use this script to test AD connectivity and user retrieval.

**Example usage:**

```powershell
python AD_Test.py
```

**Key Function:**

```python
def retrieveADUsers(ad_group):
    # Returns AD users in the specified group
```

---

## Logging

Logs are written to `XIQ-AD-PPSK-sync.log` in the script directory.

---

## Error Handling

- All major operations are wrapped in try/except blocks.
- Errors are logged and printed to the console.

---

## Example Workflow

1. Configure AD and XIQ credentials.
2. Set up group mappings.
3. Run `XIQ-AD-PPSK-Sync.py`.
4. Review logs for any errors or actions taken.

---

## Example Code Snippets

**Retrieve and print AD users:**

```python
ad_users = retrieveADUsers("CN=MyGroup,OU=Groups,DC=example,DC=com")
for user in ad_users:
    print(user.name, user.mail)
```

**Create a new PPSK user:**

```python
createPPSKuser("jdoe", "jdoe@example.com", "12345")
```

**Delete a user by ID:**

```python
deleteUser("67890")
```

---

## Advanced: PCG Integration

To enable PCG management, set `PCG_Enable = True` and configure `PCG_Maping`:

```python
PCG_Enable = True
PCG_Maping = {
    "XIQ User Group ID": {
        "UserGroupName": "XIQ User Group Name",
        "policy_id": "Network Policy ID",
        "policy_name": "Network Policy Name"
    }
}
```

---

## Additional Notes
- Each AD user must have a unique email address for correct operation.
- Review and update the script variables before running in production.
- For more details, see the included `readme.md` and `XIQ-AD-PPSK-Sync-Guide.docx`.
