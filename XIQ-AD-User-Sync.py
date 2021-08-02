import json
import requests
import sys
import os
import logging
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE



# Global Variables - ADD CORRECT VALUES
server_name = "DADOH-DC.SmithHome.local"
domain_name = "SMITHHOME"
fqdn = "smithhome.local"
user_name = "administrator"
password = "Password123"
# add ad groups starting with the highest access in xiq and add a correlating xiq user role for each ad group
group_roles = [
    # AD Group Name, XIQ User Role
    ('WIFI_admins','USER_ROLE_ADMINISTRATOR'),
    ('WIFI_Support', 'USER_ROLE_HELP_DESK')
]

# userAccountControl codes used for disabled accounts
ldap_disable_codes = ['514','66050']

# admin accounts to preserve outside of AD 
admin_emails = [
    'timjsmith24@protonmail.com'
    ]
# generated xiq token with minimum "user" permissions
XIQ_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0aW1qc21pdGgyNEBwcm90b25tYWlsLmNvbSIsInNjb3BlcyI6WyJhdXRoIiwiYXV0aDpyIiwidXNlciIsInVzZXI6ciJdLCJ1c2VySWQiOjIxNzkyMzIxLCJyb2xlIjoiQWRtaW5pc3RyYXRvciIsImN1c3RvbWVySWQiOjIxNzkxOTcxLCJjdXN0b21lck1vZGUiOjAsImhpcUVuYWJsZWQiOmZhbHNlLCJvd25lcklkIjoxNzkxNjEsIm9yZ0lkIjowLCJkYXRhQ2VudGVyIjoiSUFfR0NQIiwiaXNzIjoiZXh0cmVtZWNsb3VkaXEuY29tIiwiaWF0IjoxNjI0Mzg5NTgxLCJleHAiOjQ3Nzc5ODk1ODF9.eYcoiCDbcid4Zkj4MjByEKP7jcUG59xXqvtxI5QZ9DM"


#-------------------------
# logging file and info
PATH = os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(
	filename='{}/XIQ-AD-USER-Sync.log'.format(PATH),
	filemode='a',
	level=os.environ.get("LOGLEVEL", "INFO"),
    format= '%(asctime)s: %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
)


URL = "https://api.extremecloudiq.com"
headers = {"Accept": "application/json", "Content-Type": "application/json", "Authorization": "Bearer " + XIQ_token}



def retrieveADUsers(ad_group):
    #Building search base from fqdn
    subdir_list = fqdn.split('.')
    tdl = subdir_list[-1]
    subdir_list = subdir_list[:-1]
    SearchBase = 'DC=' + ',DC='.join(subdir_list) + ',DC=' + tdl
    try:
        server = Server(server_name, get_info=ALL)
        conn = Connection(server, user='{}\\{}'.format(domain_name, user_name), password=password, authentication=NTLM, auto_bind=True)
        conn.search(
                search_base= SearchBase,
                search_filter='(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=cn={},cn=users,{}))'.format(ad_group, SearchBase),
                search_scope=SUBTREE,
                attributes = ['objectClass', 'userAccountControl', 'sAMAccountName', 'name', 'mail'])
        ad_result = conn.entries
        conn.unbind()
        return ad_result
    except:
        log_msg = f"Unable to reach server {server_name}"
        logging.error(log_msg)
        print(log_msg)
        print("script exiting....")
        raise SystemExit
    


def CreateXIQUser(name,mail,xiq_role):
    url = URL + "/users"
    payload = json.dumps({"login_name": mail ,"display_name": name,"idle_timeout": "30", "user_role": "{}".format(xiq_role)})
    response = requests.post(url, headers=headers, data=payload, verify=True)
    if response is None:
        log_msg = "Error adding User - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)

    elif response.status_code == 400:
        log_msg = f"Error adding User {name}- already exist in ExtremeCloudIQ"
        logging.error(log_msg)
        raise TypeError(log_msg)

    elif response.status_code != 201:
        log_msg = f"Error adding User {name} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)

    elif response.status_code ==201:
        logging.info(f"succesfully created User {name} with login {mail}")
        print(f"succesfully created User {name} with login {mail}")
    #print(response)



def retrieveXIQUsers(pageSize):
    page = 1
    XIQUsers = []
    while page < 1000:
        url = URL + "/users?page=" + str(page) + "&limit=" + str(pageSize)
        response = requests.get(url, headers=headers, verify = True)
        if response is None:
            log_msg = "Error retrieving PPSK users from XIQ - no response!"
            logging.error(log_msg)
            raise TypeError(log_msg)

        elif response.status_code != 200:
            log_msg = f"Error retrieving users from XIQ - HTTP Status Code: {str(response.status_code)}"
            logging.error(f"Error retrieving users from XIQ - HTTP Status Code: {str(response.status_code)}")
            logging.warning(f"\t\t{response}")
            raise TypeError(log_msg)

        rawList = response.json()['data']
        XIQUsers = XIQUsers + rawList

        if len(rawList) == 0:
            #print("Reached the final page - stopping to retrieve users ")
            break

        page += 1
    return XIQUsers



def deleteXIQuser(userId):
    url = URL + "/users/" + str(userId)
    #print("\nTrying to delete user using this URL and payload\n " + url)
    response = requests.delete(url, headers=headers, verify=True)
    if response is None:
        log_msg = f"Error deletin user {userId} - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 200:
        log_msg = f"Error deleting user {userId} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(response.text)
        raise TypeError(log_msg)
    elif response.status_code == 200:
        logging.info(f"succesfully deleted user {userId}")
        return 'Success'
    #print(response)


def main():
    try:
        xiq_users = retrieveXIQUsers(100)
    except TypeError as e:
        print(e)
        print("script exiting....")
        # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
        raise SystemExit
    except:
        log_msg = ("Unknown Error: Failed to retrieve users from XIQ")
        logging.error(log_msg)
        print(log_msg)
        print("script exiting....")
        # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
        raise SystemExit
    
    ldap_users = {}
    ldap_capture_success = True
    for ad_group, xiq_user_role in group_roles:
        ad_result = retrieveADUsers(ad_group)
        #print("\nParsing all users from LDAP:\n")

        for ldap_entry in ad_result:
            if str(ldap_entry.name) not in ldap_users:
                try:
                    ldap_users[str(ldap_entry.name)] = {
                        "userAccountControl": str(ldap_entry.userAccountControl),
                        "email": str(ldap_entry.mail),
                        "username": str(ldap_entry.sAMAccountName),
                        "xiq_role": xiq_user_role
                    }

                except:
                    log_msg = (f"Unexpected error: {sys.exc_info()[0]}")
                    logging.error(log_msg)
                    print(log_msg)
                    logging.warning("User info was not captured from Active Directory")
                    logging.warning(f"{ldap_entry}")
                    # not having ppsk will break later line - for name, details in ldap_users.items():
                    ldap_capture_success = False
                    continue

    log_msg = "Successfully parsed " + str(len(ldap_users)) + " LDAP users"
    logging.info(log_msg)
    print(f"\n{log_msg}\n")
    
    ldap_disabled = []
    for name, details in ldap_users.items():
        #print(name, details)
        if details['email'] == '[]':
            log_msg = (f"User {name} doesn't have a email set and will not be created in xiq")
            logging.warning(log_msg)
            print(log_msg)
            continue
        if not any(d['login_name'] == details['email'] for d in xiq_users) and not any(d == details['userAccountControl'] for d in ldap_disable_codes):
            #print(f"User {name} - {details['email']} not found in XIQ")
            try:
                CreateXIQUser(name, details["email"], details['xiq_role'])
            except TypeError as e:
                log_msg = f"failed to create {name}: {e}"
                logging.error(log_msg)
                print(log_msg)
            except:
                log_msg = f"Unknown Error: Failed to create user {name} - {details['email']}"
                logging.error(log_msg)
                print(log_msg)
        elif any(d == details['userAccountControl'] for d in ldap_disable_codes):
            ldap_disabled.append(name)
    
    for name in ldap_disabled:
        del ldap_users[name]
    if ldap_capture_success:
        for x in xiq_users:
            email = x['login_name']
            xiqid = x['id']
            name = x['display_name']
            if not any(d['email'] == email for d in ldap_users.values()):
                #print(f"User {email} not found in AD")
                if any(e == email for e in admin_emails):
                    print(f"skipping user {email}")
                    continue
                try:
                    result = deleteXIQuser(xiqid)
                except TypeError as e:
                    print(f"Failed to delete user {name} - {email}  with error {e}")
                    continue
                except:
                    log_msg = f"Unknown Error: Failed to create user {name} - {email} "
                    logging.error(log_msg)
                    print(log_msg)
                    continue
                if result == 'Success':
                    log_msg = f"User {name} - {email} was successfully deleted."
                    logging.info(log_msg)
                    print(log_msg)
    else:
        log_msg = "No users will be deleted from XIQ because of the error(s) in reading ldap users"
        logging.warning(log_msg)
        print(log_msg)

if __name__ == '__main__':
	main()