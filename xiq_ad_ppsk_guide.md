# Private Pre-Shared Key Sync with Active Directory Guide

**Author:** Tim Smith, SA  
**Date:** 01/22/2024  
**Version:** v1.4.0

## Overview

This guide covers setting up and running the script to sync your local domain Active directory users with the Private Pre-shared-key (PPSK) within ExtremeCloud IQ (XIQ) public cloud only. PPSK is a solution provided by Extreme Networks to fill in the gap between a Wi-Fi SSID solution using a single PSK for all users and deploying a complete 802.1X solution. 

Extreme Networks' PPSK solution allows the creation of a dedicated key for each user or device on the identical SSID, limiting the number of SSIDs broadcasting in the air and minimizing airtime consumption due to overhead management frames. This solution also adds the ability to assign VLANs based on user/device groups to avoid the need for separate SSIDs to segregate these groups.

This guide enables you to leverage your existing Active Directory security groups to automatically create a Private Pre-shared key for every AD user and remove the PPSK user if a user is disabled or removed from the group in the AD server.

**Important:** Each AD user must have a unique email address for this script to work correctly.

**Target Audience:** Technical

## PPSK Use Cases

- Identity for IoT devices
- BYOD for employees
- Staff device onboarding
- Secure Guest Onboarding (time-based keys with employee sponsorship)
- Hospitality vertical using the hyper-segmentation feature, Private Client Groups (PCGs)
- Third-party via API integration

## Prerequisites

- ExtremeCloud IQ Public Cloud, Private Cloud (IQVA on-prem is not supported)
- The key directory can be stored in the cloud (unlimited keys) or locally on all access points (10,000 key maximum limit)
- Knowledge of XIQ by adding access points, creating network policies, and SSIDs
- XIQ PPSK SSID and associated User Groups configured
- RadSec Proxy requires TCP Port 2083 to be open on your internet firewall
- One or more XIQ native access points
- Not supported on wired systems, A3 NAC, or campus-based Wi-Fi systems (WiNG or IdentiFi)

### Required Files

Download the following files:

- **XIQ-AD-PPSK-Sync.py**
  - Version 2.0.7 is the current version (see lines 8-13 in the script)
- **AD_Test.py** (optional – see troubleshooting section)
  - Version 2.0.4 is the current version (lines 5-10)
- **requirements.txt** (optional – see modules section)

## Scripting Environment Preparation

### Information

The XIQ-AD-PPSK-Sync.py script requires, at minimum, Python 3.6 and tested up to Python 3.12. This script can be executed manually but ideally would be set up as a cronjob to be run every 8, 12, or 24 hours. This script can be executed from any device with Python and the needed modules installed. This device must reach the Active Directory server and access ExtremeCloud IQ.

The script, when run, will create an XIQ-AD-PPSK-Sync.log file. This log file will show information about PPSK users created and deleted. It will also show how many users were parsed from XIQ and Active Directory when run. Any API errors experienced will also show up in the log file.

### Device Choice

This script can be executed from any device running Python 3.6 or higher. The device could be a server running Redhat, a PC/laptop running Windows 10 or Mac OSX, or even a Raspberry Pi-type device. The device will need to be on the network and be able to reach the local Active Directory server as well as reach ExtremeCloud IQ. This can be done through a proxy. The proxy configuration is beyond the scope of this guide.

### Python Installation

Depending on the device that is used, you may need to install Python or a different version of Python. The easiest way to check the Python version is to open the terminal (Power Shell on Windows) and type this command:

```bash
python3 --version
```

Below are some examples of installing python3 for Windows and Mac OSX. Linux systems that were tested all had python3.6 or higher installed by default.

#### Mac OSX Big Sur

- Open the terminal and enter `python3 –version`
- This triggers the installation of Developer Tools
- Click Install
- Click Agree
- pip3 is needed to install Python modules
- With Big Sur, the Developer tools does not install pip3
- Mac terminal will be used to install pip3
- Running this command will check if pip is installed:
  ```bash
  pip3 --version
  ```
- Run the following command to install pip3:
  ```bash
  curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python3 get-pip.py
  ```

#### Windows 10

- Search Microsoft Store for Python 3.9 and click install
- Log in with Microsoft credentials
- The Windows store installs pip3 with python3. Pip3 will be used to install the needed modules

### Required Modules

The requests, ldap3, and pycryptodome modules are the only modules required for the XIQ-AD-PPSK-Sync.py script.

#### Checking for Existing Modules

You can check if the required modules are installed using the terminal (PowerShell for Windows). For each module, run the following command:

```bash
python3 -c "import requests"
python3 -c "import ldap3"
python3 -c "import pycryptodome"
```

The module is not installed if a 'ModuleNotFoundError: No module named '<module name>' error is returned.

#### Installing Required Modules

The required modules can be installed using pip3 using the downloaded requirements.txt file with the following command:

```bash
pip3 install -r requirements.txt
```

Or the modules can be installed individually using:

```bash
pip3 install requests
pip3 install ldap3
pip3 install pycryptodome
```

## Script Variables

The Global Variable section of the script (file name: XIQ-AD-PPSK-Sync.py) must be updated with the correct values. We will briefly cover each of these and, for some, will go into more detail below.

### Lines 17-20: Active Directory Server Info

1. **server_name** – This can be the FQDN or IP address of the Active Directory Server
2. **domain_name** – The configured Domain on the AD server – The domain portion of the FQDN

### Line 23: Max Page Size

Can change the Max page size with the AD call. This should match your AD configuration. 1000 is the default.

### Line 25: AD Filter

Can be used to add a filter to your AD search. See the AD Filter section for more details.

### Lines 27-31: XIQ Authentication

Two methods could be used, but the token method is recommended:

1. **XIQ username and password**
   - Lines 27 and 28 - uncomment by deleting the # at the beginning of the line. Then, fill in the username and password
   - Line 31 - comment out the line by adding # to the beginning of the line

2. **Token method** (Preferred) – A token can be generated to allow access only to view/create/delete PPSK users. Details on generating this token are below in the "Generating the XIQ Token" section.

### Lines 33-37: Group Mapping

Define which AD groups to sync with which XIQ User Groups. Note that the brackets around the groups create a list. Each set of groups should be in a set of parentheses and be separated by a comma.

- We will cover how to get the needed AD Group distinguished Name in the "AD Group Distinguished Name" section
- We will cover how to get the XIQ User Group ID in the "XIQ User Group ID" section
- **NOTE:** The order is very important here. If the same AD user is in multiple groups, the user will be put in the first XIQ User Group in the list. XIQ users can only be in one PPSK User group.

### PCG Support (Optional)

**Line 39:** To enable PCG Support, change the PCG_Enable Variable from False to True

**Lines 41-47:** If PCG is Enabled, PCG_Mapping should be updated with the correct information. If PCG is not Enabled, PCG_Mapping will not be used and does not need to be updated.

1. **Line 42** – This should be replaced with the XIQ User Group ID number that correlates with the PCG
2. **Line 43** – This is the name of the User Group associated with the ID on line 42 (needed to add and remove users from the PCG)
3. **Line 44** – This is the Network Policy ID associated with the PCG
4. **Line 45** – This is the Network Policy Name associated with the PCG

## Generating the XIQ Token

You can view our developer portal site at https://developer.extremecloudiq.com/. There is a link to our swagger page and other developer tools. There is also a Communities section to reach out with any questions.

### Swagger

We will use the swagger interface to generate the token: https://api.extremecloudiq.com/

On the swagger page, clicking on any API will expand information about the API and allow you to try it. Clicking the "Try it out" button, filling out any needed information, and then clicking the execute button will allow you to try that specific API call.

The 2nd generation APIs are based on access tokens generated by an XIQ account. Currently, these tokens can only be generated through the /login POST API request. They cannot be generated through the XIQ GUI.

### Login

The /login POST request is used to generate an access token. In the request body, enter a local administrator XIQ account username and password, and the API will respond with an access token that can be used for any of the following calls. This token will be valid for 24 hours after creation.

**Request Body:**
```json
{
  "username": "xiq@example.com",
  "password": "changeme"
}
```

For this script, we will use this token to generate a separate token with limited access and a specified expiration time. Copy the access token created, not including the quotes.

### Authorize in Swagger

At the top of the Swagger page, click the authorize button. A window will pop up, allowing you to paste the access token. Clicking "Authorize" will set Swagger to use the added access token for the API calls on the page.

### Generating Specific Tokens

The /auth/apitoken POST request allows you to specify an expiration time and set permissions for a token. This is a great way to create a token for a specific application or script, only allowing the token to perform the needed tasks.

The expiration time uses Epoch time, the number of seconds since midnight on Jan 1, 1970 (UTC). https://www.epochconverter.com/ is a webpage that can convert a readable time to epoch time or epoch time to a more readable time. Set a time for 1 year out and get the epoch time.

For this script, we will want to have the following permissions: **enduser, pcg:key**

This will give us access to view, create, and delete PPSK users and view, create, and delete pcg-key-based users if necessary.

**Request Body:**
```json
{
  "description": "Token for XIQ-AD-PPSK-Sync.py script",
  "expire_time": 1628186428,
  "permissions": [
    "enduser",
    "pcg:key"
  ]
}
```

Copy the newly created access_token and add it to the XIQ_token variable in the script.

## AD Group Distinguished Name

The distinguished name includes more details than just the name of the group. It consists of any OUs or folders under which the AD group and the domain controllers are located. These are all needed by the script to identify and query the group details.

An easy way to get the Distinguished name is to use the find objects and search for the group name. The full distinguished name will be shown in the Search results.

Some special characters must be escaped if included in the Distinguished name. For example, if you had a CN like `CN=Users (global)`, the ()'s would need to be escaped out and converted to hex-like `CN=Users \\28global\\29`.

Once that is obtained, add it to the group_roles object in the script:

```python
group_roles = [
    # AD GROUP Distinguished Name, XIQ group ID
    ("CN=Staff_User,CN=Users,DC=SmithHome,DC=local", "XIQ User Group ID"),
    ("AD Group Distinguished Name", "XIQ User Group ID")
]
```

## XIQ User Group ID

Each XIQ User Group will be assigned a unique ID when created. This gets used by the backend systems and is not seen in the GUI. The easiest way to get the ID is from the swagger page.

Return to the swagger page, scroll to the Configuration – User Management section, and find the /usergroups GET request.

Click the "Try it out" button, then the "Execute" button. When you find the Name of the XIQ User Group you want to use, it will be inside a pair of {curly brackets}. Inside the same pair of curly brackets will be an element called id. This is the ID that is needed.

**Response Body Example:**
```json
{
  "page": 1,
  "count": 10,
  "data": [
    {
      "id": 769490635824436,
      "name": "Home_Hive",
      "description": "",
      "predefined": false,
      "create_time": "2021-10-11T18:24:33.000+0000",
      "update_time": "2021-10-11T18:24:33.000+0000"
    }
  ]
}
```

Once that is obtained, add it to the group_roles object in the script:

```python
group_roles = [
    # AD GROUP Distinguished Name, XIQ group ID
    ("CN=Staff_User,CN=Users,DC=SmithHome,DC=local", "769490635824436"),
    ("AD Group Distinguished Name", "XIQ User Group ID")
]
```

## XIQ Network Policy ID

Each XIQ Network Policy will be assigned a unique ID when created. The easiest way to get the ID is to select the Network Policy in the XIQ GUI. When you choose the Network Policy, the ID is the long number listed in the URL. The Policy Name is directly under the Policy Details.

You can also get the Network Policy ID from Swagger for all Network Policies with PCG configured by using the /pcg/key-based GET request.

## AD Filter

Adding an AD Filter will allow the search filter to be performed in AD. This can be beneficial if there are users in the security group that do not have a corporate email address or if you want to filter out particular email addresses.

**Example:**
```python
AD_Filter = "(|(mail=*@example.org)(mail=*@stu.example.org))"
```

This would search only @example.org and @stu.example.org email addresses. All others in the security group would be filtered out.

More information about filtering can be found on the LDAP Filtering website.

## Active Directory Disable Codes

Each user in Active Directory has a userAccountControl number assigned to it, providing the user's status. The script has 4 codes for Users who are disabled:

- **514** – NORMAL_ACCOUNT (512) + ACCOUNTDISABLED (2)
- **642** - NORMAL_ACCOUNT (512) + ACCOUNTDISABLED (2) + ENCRYPTED_TEXT_PWD_ALLOWED (128)
- **66050** - NORMAL_ACCOUNT (512) + ACCOUNTDISABLED (2) + DONT_EXPIRE_PASSWORD (65536)
- **66178** - NORMAL_ACCOUNT (512) + ACCOUNTDISABLED (2) + DONT_EXPIRE_PASSWORD (65536) + ENCRYPTED_TEXT_PWD_ALLOWED (128)

If any other disabled codes are needed, they can be added inside the bracket to line 61:

```python
ldap_disable_codes = ['514','642','66050','66178','2562']
```

## Running the Script

To run the script, open the terminal (PowerShell for Windows) to the location of the script and run:

```bash
python3 XIQ-AD-PPSK-Sync.py
```

You can also make the script executable by running:

```bash
chmod +x XIQ-AD-PPSK-Sync.py
```

Then, you can run the script by typing:

```bash
./XIQ-AD-PPSK-Sync.py
```

### Script Output

The script will print to the screen how many PPSK users and AD users were parsed. If there are any users in the list of AD users and not in the list of PPSK users, an API call will be made to create the PPSK user.

**Success messages:**
- `successfully created PPSK user Tim Smith`
- `User user0200@example.com - 769490635839948 was successfully deleted.`

**Warning messages:**
- `User Sega Smith doesn't have an email set and will not be created in xiq`

### Log File

Upon running the script, a log file will be created named XIQ-AD-PPSK-Sync.log. Additional runs of the script will append to this log file. This file will contain the same information that prints to the screen and any error received when making the API calls.

## Scheduling Script to Run

### Mac & Linux-based Systems

A Cron job can be set up to run the script automatically at a specified interval. Ideally, this could be set for every 8, 12, or 24 hours.

#### Setting up a Cron Job

Open and edit the crontab:

```bash
crontab -e
```

#### Cron Job Time Format

The first 5 characters represent the job's time, date, and repetition:

- **a** – Minute (0-59)
- **b** – Hour (0-23)
- **c** – Day (0-31)
- **d** – Month (0-12) – 0=None and 12 = December
- **e** – Day of the Week (0-7) – 0=Sunday and 7=Sunday

**Examples:**
- Every 8 hours: `0 */8 * * *`
- Every night at midnight: `0 0 * * *`

#### Cron Job Examples

**Every 8 hours, turning off the output:**
```bash
0 */8 * * * python3 /home/admin/documents/scripts/XIQ-AD-PPSK-Sync.py > /dev/null 2>&1
```

**Every 12 hours with saved output:**
```bash
0 */12 * * * ./home/admin/documents/scripts/XIQ-AD-PPSK-Sync.py >> /home/admin/documents/scripts/XIQ-AD-PPSK-Sync-Output.txt
```

### Windows-based Systems

A Windows task schedule can be set up to run the script automatically at a specified interval.

#### Setting up Windows Task Scheduler

1. Open Control Panel > System and Security > Administrative Tools > Task Scheduler
2. Select 'Create basic task…'
3. Give your task a name like 'AD-PPSK-Sync' and click 'Next'
4. Leave the Trigger set to daily and click 'Next'
5. Click 'Next' leaving recur every 1 day
6. Select 'Start a program and click 'Next'

#### Start a Program Configuration

**For the Program/script section:** Enter the path of your python.exe file.

To find the python.exe location:
1. Open Windows PowerShell and enter `python3`
2. In the interpreter enter:
   ```python
   import sys
   sys.executable
   exit()
   ```

**Fields to fill:**
- **Program/Script:** Full path to python.exe
- **Add arguments (optional):** `XIQ-AD-PPSK-Sync.py`
- **Start in (optional):** Script's location path

#### Editing the Time

Once the task is saved, open the Task Scheduler Library folder and find the newly created AD-PPSK-Sync task. Click on it to open, select the Trigger tab, and edit the Daily trigger. Here, you can set what time you want it to run.

If you want the script to run every 8 or 12 hours, check the box next to 'Repeat task every:' and enter '8 hours' or '12 hours'.

## Troubleshooting

### Log File

The XIQ-AD-PPSK-sync.log file is a good place to look for potential issues. This log file will update whenever the script is run, manually or on a schedule.

### Common Errors

#### Invalid XIQ token
```
2021-11-05 16:58:27: root - ERROR - Error retrieving PPSK users from XIQ - HTTP Status Code: 401
2021-11-05 16:58:27: root - WARNING - {'error_code': 'AuthInvalidToken', 'error_id': 'cda656a5157d4c87a5143252aad71bff', 'error_message': 'Unable to read JSON value: ?[\x19???\x14?M??'}
```
**Solution:** Check token using Swagger - remember that if you generate a specific token, it may only have access to the user's APIs.

#### Invalid XIQ token format
```
2021-11-08 13:56:36: root - ERROR - Error retrieving PPSK users from XIQ - HTTP Status Code: 401
2021-11-08 13:56:36: root - WARNING - {'error_code': 'AuthInvalidToken', 'error_id': '555d1ce9f67b40ef83caf4a89ca92b04', 'error_message': 'JWT strings must contain exactly 2 period characters. Found: 0'}
```
**Solution:** This may mean that you are trying to use the XIQ Username and Password but have yet to comment out line 31. Add a # in front of line 31. Or the token wasn't entered correctly.

#### Expired XIQ token – Code 401 & JWT expired
```
2021-11-08 14:14:16: root - ERROR - Error retrieving PPSK users from XIQ - HTTP Status Code: 401
2021-11-08 14:14:16: root - WARNING - {'error_code': 'AuthTokenExpired', 'error_id': '78d8b818a03940dd8d4accfc1b3ffb7e', 'error_message': 'JWT expired at 2021-11-08T19:14:11Z.
```
**Solution:** The XIQ token has expired. Generate a new token using Swagger.

#### Invalid XIQ Username/password – Code 401
```
2021-11-08 13:55:15: root - ERROR - Error getting access token - HTTP Status Code: 401
2021-11-08 13:55:15: root - WARNING - <Response [401]>
```
**Solution:** Check username and password for XIQ. It is recommended to use an XIQ Token.

#### Unable to reach server (Active Directory)
```
2021-11-08 13:46:07: root - ERROR - Unable to reach server DADOH-D.SmithHome.local
```
**Solution:** Check the IP address or server name entered on Line 17. This may need to be the fully qualified name. Try pinging the server from the device where the script is hosted.

#### XIQ User Failed to Create – Code 400
```
2021-11-08 14:19:35: root - INFO - Successfully parsed 0 XIQ users
2021-11-08 14:19:36: root - INFO - Successfully parsed 4 LDAP users
2021-11-08 14:19:36: root - ERROR - Error adding PPSK user Tim Smith - HTTP Status Code: 400
```
**Solution:** There are a couple of possibilities. If 0 XIQ users were parsed and you have configured users in the user group, check the user group ID in the group_roles list. The other cause could be if the username already exists in XIQ PPSK users within a different user group.

#### XIQ Timeout Error
```
2021-10-08 12:43:05: root - ERROR - Failed retrieving PPSK users from XIQ - HTTP Status Code: 504
2021-10-08 12:43:05: root - WARNING - <Response [504]>
```
**Solution:** An HTTP Status Code 504 is a timeout from XIQ. If XIQ cannot respond to the API call within 60 seconds, it will send these 504 errors. The script will need to be rerun with no changes.

#### Email is not set for AD User
```
2021-11-08 14:42:39: root - WARNING - User Tim Smith doesn't have an email set and will not be created in xiq
```
**Solution:** Check the AD User and see if the email is set. Email is required to create a PPSK.

### AD_Test.py

This script was written to help troubleshoot issues with collecting data from AD. The variables are the same in this script. The AD Group Distinguished name should be added to the Distinguished_name variable instead of in the group_roles list.

AD_Filter can be assigned here as well. This can help to see info on a specific email or user.

This script will test resolving the IP address for the server_name. If an IP address is entered, it will try and resolve the DNS name. The connection to the AD Server will be performed.

If there are any errors, they will print to the screen. Otherwise, the collected data from the AD server will print on the screen. If empty [] brackets are printed, check the distinguished name and validate that it is correct.

**Example Output:**
```
The IP address for DADOH-DC.SmithHome.local is 192.168.10.5
completed page of AD Users. Total Users collected is 2
User0001 Last {'userAccountControl': '512', 'email': 'user0001@example.com', 'username': 'user0001'}
User0002 Last {'userAccountControl': '512', 'email': '[]', 'username': 'user0002'}
```

Using this output, you can check the User Account Control Number if disabled users are not being removed from XIQ. You can validate there is an email set for the user. And overall, check that information is being returned.