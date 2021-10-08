import json
import requests
import sys
import os
import logging
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE

# Global Variables - ADD CORRECT VALUES
server_name = "DADOH-DC.SmithHome.local"
domain_name = "SMITHHOME"
user_name = "Administrator"
password = "Password123"
usergroupID = "769490635824031"
ad_group = "Staff_User"
fqdn = "smithhome.local"

# ExtremeCloudIQ developer information
headers = {
           "ownerID" : "179161",
           "X-AH-API-CLIENT-SECRET" : "917f53f5eb85aa9e8f528305ce2c12e5",
           "X-AH-API-CLIENT-REDIRECT-URI" : "https://127.0.0.1:4000",
           "Authorization" : "bearer" + "oRo1lLG8m9i6nuf155MB4syC09bn4fu53ab06332",
           "X-AH-API-CLIENT-ID" : "3ab06332",
           "content-Type": "application/json"}

ownerID = "179161"
URL = "https://ia-gcp.extremecloudiq.com/"

#-------------------------
# logging
PATH = os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(
    filename='{}/XIQ-AD-PPSK-sync_APIv1.log'.format(PATH),
    filemode='a',
    level=os.environ.get("LOGLEVEL", "INFO"),
    format= '%(asctime)s: %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
)
# userAccountControl codes used for disabled accounts
ldap_disable_codes = ['514','66050']





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



def CreatePPSKuser(name,mail):
    url = URL + "xapi/v2/identity/credentials?ownerid=" + ownerID

    payload = json.dumps({"groupId": usergroupID,"firstName": name,"userName": name, "email": mail, "deliverMethod": "EMAIL", "policy": "PERSONAL"})

    #print("Trying to create user using this URL and payload " + url)
    response = requests.post(url, headers=headers, data=payload, verify=True)
    if response is None:
        log_msg = "Error adding PPSK user - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)

    elif response.status_code != 200:
        log_msg = f"Error adding PPSK user {name} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)

    elif response.status_code ==200:
        logging.info(f"succesfully created PPSK user {name}")
        print(f"succesfully created PPSK user {name}")
    #print(response)




def retrievePPSKusers():
    #print("Retrieve all PPSK users  from ExtremeCloudIQ")


    ppskusers = []

    url = URL + "xapi/v2/identity/credentials"

    # Get the next page of the ppsk users
    response = requests.get(url, headers=headers,verify=True)
    if response is None:
        log_msg = "Error retrieving PPSK users from XIQ - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)

    elif response.status_code != 200:
        log_msg = f"Error retrieving PPSK users from XIQ - HTTP Status Code: {str(response.status_code)}"
        logging.error(f"Error retrieving PPSK users from XIQ - HTTP Status Code: {str(response.status_code)}")
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)


    rawList = response.json()['data']
    ppskusers = ppskusers + rawList



    #print(ppskusers)
    return ppskusers




def deleteuser(userId):
    url = URL + "xapi/v2/identity/credentials?ownerid=" + "&ids=" + str(userId)
    #print("\nTrying to delete user using this URL and payload\n " + url)
    response = requests.delete(url, headers=headers, verify=True)
    if response is None:
        log_msg = f"Error deleting PPSK user {userId} - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 200:
        log_msg = f"Error deleting PPSK user {userId} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)
    elif response.status_code == 200:
        logging.info(f"succesfully deleted PPSK user {userId}")
        return 'Success'
    #print(response)

def main():
    try:
        ppsk_users = retrievePPSKusers()
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
    ad_result = retrieveADUsers(ad_group)
    #print("\nParsing all users from LDAP:\n")

    for ldap_entry in ad_result:
        if str(ldap_entry.name) not in ldap_users:
            try:
                ldap_users[str(ldap_entry.name)] = {
                    "userAccountControl": str(ldap_entry.userAccountControl),
                    "email": str(ldap_entry.mail)}

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
        if details['email'] == '[]':
            print(f"User {name} doesn't have a email set")
            continue
        if not any(d['userName'] == name for d in ppsk_users) and not any(d == details['userAccountControl'] for d in ldap_disable_codes):
            try:
                CreatePPSKuser(name, details["email"])
            except TypeError as e:
                log_msg = f"failed to create {name}: {e}"
                logging.error(log_msg)
                print(log_msg)
            except:
                log_msg = f"Unknown Error: Failed to create user {name}"
                logging.error(log_msg)
                print(log_msg)
        elif any(d == details['userAccountControl'] for d in ldap_disable_codes):
            ldap_disabled.append(name)

    if details["userAccountControl"] == '66050':
        userId=0
        for user in ppsk_users:
            if user['userName'] == name:
                userId=user['id']
                print("Found user id: " + str(userId) + " --> trying to delete this user")
                deletePPSKuser=deleteuser(userId)
                break

        if userId == 0:
            log_msg = (f"Failed to retrieve data on user by username {name}")
            logging.error(log_msg)
            print(log_msg)

test= retrieveADUsers("Domain Users")
print(test)

if __name__ == '__main__':
    main()