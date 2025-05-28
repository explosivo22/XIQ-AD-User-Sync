# XIQ-AD-User-Sync Documentation

## Overview

This project automates the synchronization of Active Directory (AD) users with ExtremeCloud IQ (XIQ) Private Pre-Shared Key (PPSK) user groups. It streamlines onboarding and offboarding of users and devices for Wi-Fi access, leveraging AD group membership to manage XIQ PPSK users and optionally Private Client Groups (PCGs).

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

Edit the following variables in `XIQ-AD-PPSK-Sync.py`:

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

## Logging

Logs are written to `XIQ-AD-PPSK-sync.log` in the script directory. Logging includes timestamps, log level, and messages for all major operations and errors.

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

---

## Function Reference & Code Snippets

### 1. `retrieveADUsers(ad_group)`
Connects to AD and retrieves users in the specified group, handling paging and errors.

```python
def retrieveADUsers(ad_group):
    # ...existing code...
    try:
        server = Server(server_name, get_info=ALL)
        conn = Connection(server, user='{}\\{}'.format(domain_name, user_name), password=password, authentication=NTLM, auto_bind=True)
        conn.search(
            search_base= SearchBase,
            search_filter='(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:={}){})'.format(ad_group,AD_Filter),
            search_scope=SUBTREE,
            attributes = ['objectClass', 'userAccountControl', 'sAMAccountName', 'name', 'mail'],
            paged_size = page)
        ad_result.extend(conn.entries)
        # ...existing code...
        return ad_result
    except:
        log_msg = f"Unable to reach server {server_name}"
        logging.error(log_msg)
        print(log_msg)
        print("script exiting....")
        raise SystemExit
```

**Example:**
```python
ad_users = retrieveADUsers("CN=MyGroup,OU=Groups,DC=example,DC=com")
```

---

### 2. `getAccessToken(XIQ_username, XIQ_password)`
Authenticates to XIQ and retrieves an access token for API calls.

```python
def getAccessToken(XIQ_username, XIQ_password):
    url = URL + "/login"
    payload = json.dumps({"username": XIQ_username, "password": XIQ_password})
    response = requests.post(url, headers=headers, data=payload)
    # ...existing code...
    if "access_token" in data:
        headers["Authorization"] = "Bearer " + data["access_token"]
        return 0
    # ...existing code...
```

---

### 3. `createPPSKuser(name, mail, usergroupID)`
Creates a PPSK user in XIQ.

```python
def createPPSKuser(name, mail, usergroupID):
    url = URL + "/endusers"
    payload = json.dumps({"user_group_id": usergroupID ,"name": name,"user_name": name,"password": "", "email_address": mail, "email_password_delivery": mail})
    response = requests.post(url, headers=headers, data=payload, verify=True)
    # ...existing code...
    elif response.status_code ==200:
        logging.info(f"successfully created PPSK user {name}")
        print(f"successfully created PPSK user {name}")
        return True
```

**Example:**
```python
createPPSKuser("jdoe", "jdoe@example.com", "12345")
```

---

### 4. `retrievePPSKUsers(pageSize, usergroupID)`
Retrieves all PPSK users from XIQ for a given user group, handling pagination.

```python
def retrievePPSKUsers(pageSize, usergroupID):
    # ...existing code...
    while page <= pageCount:
        url = URL + "/endusers?page=" + str(page) + "&limit=" + str(pageSize) + "&user_group_ids=" + usergroupID
        response = requests.get(url, headers=headers, verify = True)
        # ...existing code...
        rawList = response.json()
        ppskUsers = ppskUsers + rawList['data']
        if firstCall == True:
            pageCount = rawList['total_pages']
        print(f"completed page {page} of {rawList['total_pages']} collecting PPSK Users")
        page = rawList['page'] + 1 
    return ppskUsers
```

---

### 5. `deleteUser(userId)`
Deletes a PPSK user from XIQ by user ID.

```python
def deleteUser(userId):
    url = URL + "/endusers/" + str(userId)
    response = requests.delete(url, headers=headers, verify=True)
    # ...existing code...
    elif response.status_code == 200:
        return 'Success', str(userId)
```

**Example:**
```python
deleteUser("67890")
```

---

### 6. `addUserToPcg(policy_id, name, email, user_group_name)`
Adds a user to a Private Client Group (PCG) in XIQ.

```python
def addUserToPcg(policy_id, name, email, user_group_name):
    url = URL + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users"
    payload = json.dumps({
                  "users": [
                    {
                      "name": name,
                      "email": email,
                      "user_group_name": user_group_name
                    }
                  ]
                })
    response = requests.post(url, headers=headers, data=payload, verify=True)
    # ...existing code...
    elif response.status_code == 200:
        return 'Success'
```

---

### 7. `retrievePCGUsers(policy_id)`
Retrieves all users in a PCG for a given network policy.

```python
def retrievePCGUsers(policy_id):
    url = URL + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users"
    response = requests.get(url, headers=headers, verify = True)
    # ...existing code...
    rawList = response.json()
    return rawList
```

---

### 8. `deletePCGUsers(policy_id, userId)`
Deletes a user from a PCG by user ID.

```python
def deletePCGUsers(policy_id, userId):
    url = URL + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users"
    payload = json.dumps({
                    "user_ids": [
                                    userId
                                ]
                })
    response = requests.delete(url, headers=headers, data=payload, verify = True)
    # ...existing code...
    elif response.status_code == 202:
        return 'Success'
```

---

### 9. `main()`
Main logic for orchestrating the sync process:
- Authenticates to XIQ (token or username/password)
- Collects all AD users and XIQ PPSK users
- Adds new users to XIQ if present in AD but not in XIQ
- Removes users from XIQ if not present in AD
- Handles disabled AD accounts
- Optionally manages PCG membership and deletions
- Logs all actions and errors

```python
def main():
    # ...existing code...
    if 'XIQ_token' not in globals():
        try:
            login = getAccessToken(XIQ_username, XIQ_password)
        except TypeError as e:
            print(e)
            raise SystemExit
        except:
            log_msg = "Unknown Error: Failed to generate token"
            logging.error(log_msg)
            print(log_msg)
            raise SystemExit     
    else:
        headers["Authorization"] = "Bearer " + XIQ_token
    # ...existing code...
    # Collect PSK users
    ppsk_users = []
    for usergroupID in ListOfXIQUserGroups:
        try:
            ppsk_users += retrievePPSKUsers(100,usergroupID)
        except TypeError as e:
            print(e)
            print("script exiting....")
            raise SystemExit
        except:
            log_msg = ("Unknown Error: Failed to retrieve users from XIQ")
            logging.error(log_msg)
            print(log_msg)
            print("script exiting....")
            raise SystemExit
    # ...existing code...
    # Create PPSK Users
    for name, details in ldap_users.items():
        user_created = False
        if details['email'] == '[]':
            log_msg = (f"User {name} doesn't have an email set and will not be created in xiq")
            logging.warning(log_msg)
            print(log_msg)
            continue
        if not any(d['user_name'] == name for d in ppsk_users) and not any(d == details['userAccountControl'] for d in ldap_disable_codes):
            try:
                user_created = createPPSKuser(name, details["email"], details['xiq_role'])
            except TypeError as e:
                log_msg = f"failed to create {name}: {e}"
                logging.error(log_msg)
                print(log_msg)
                ppsk_create_error+=1
            except:
                log_msg = f"Unknown Error: Failed to create user {name} - {details['email']}"
                logging.error(log_msg)
                print(log_msg)
                ppsk_create_error+=1
            if PCG_Enable == True and user_created == True and str(details['xiq_role']) in PCG_Maping:
                # ...existing code for PCG add...
        elif any(d == details['userAccountControl'] for d in ldap_disable_codes):
            ldap_disabled.append(name)
    # ...existing code for deletions and logging...
```

---

## Error Handling

- All major operations are wrapped in try/except blocks.
- Errors are logged and printed to the console.
- The script will exit on critical failures (e.g., AD or XIQ connectivity issues).

---

## Example Workflow

1. Configure AD and XIQ credentials in the script.
2. Set up group mappings and (optionally) PCG mappings.
3. Run `python XIQ-AD-PPSK-Sync.py`.
4. Review `XIQ-AD-PPSK-sync.log` for any errors or actions taken.

---

## Troubleshooting

- **AD Connection Fails:**
  - Check `server_name`, `domain_name`, `user_name`, and `password`.
  - Ensure the AD server is reachable from the script host.
- **XIQ API Errors:**
  - Verify `XIQ_token` or `XIQ_username`/`XIQ_password`.
  - Ensure the API token has `enduser` and `pcg:key` permissions.
- **User Not Created:**
  - Ensure the AD user has a valid email address.
  - Check for duplicate names or missing group mappings.
- **Logging:**
  - Review `XIQ-AD-PPSK-sync.log` for detailed error messages and stack traces.

---

## Additional Notes
- Each AD user must have a unique email address for correct operation.
- Review and update the script variables before running in production.
- For more details, see the included `readme.md` and `XIQ-AD-PPSK-Sync-Guide.docx`.
