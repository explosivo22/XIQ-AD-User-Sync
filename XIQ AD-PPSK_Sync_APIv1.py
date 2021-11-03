import json
import requests
import sys
import os
import logging
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE

# Global Variables - ADD CORRECT VALUES
server_name = "enter the server name/ IP"
domain_name = "enter the domain name"
user_name = "enter AD username"
password = " enter AD password"
usergroupID = 'Enter XIQ usergroup ID'
#Distinguished name of the AD group
distinguished_name = "Enter Distinguished Name string"
fqdn = "Enter fqdn"

# ExtremeCloudIQ developer information
headers = {
           "ownerID" : "Enter ownerID",
           "X-AH-API-CLIENT-SECRET" : "enter here API client secret",
           "X-AH-API-CLIENT-REDIRECT-URI" : "Enter Redirect URL",
           "Authorization" : "bearer" + "enter access token ",
           "X-AH-API-CLIENT-ID" : "Enter client ID",
           "content-Type": "application/json"}

ownerID = "Enter owner ID again"
rdc = " Enter rdc"
URL = "https://{}.extremecloudiq.com/".format(rdc)



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
ldap_disable_codes = ['514','642','66050','66178']





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
            search_filter='(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:={}))'.format(ad_group),
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

    payload = json.dumps({"groupId": usergroupID,"firstName": name,"userName": mail, "email": mail, "deliverMethod": "EMAIL", "policy": "PERSONAL"})

    #print("Trying to create user using this URL and payload " + url)
    response = requests.post(url, headers=headers, data=payload, verify=True)
    if response is None:
        log_msg = "Failed adding PPSK user - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)

    elif response.status_code != 200:
        log_msg = f"Failed adding PPSK user {name} - HTTP Status Code: {str(response.status_code)}"
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

    url = URL + "xapi/v2/identity/credentials?ownerid=" + ownerID + "&userGroup=" + usergroupID
     # Get the next page of the ppsk users
    response = requests.get(url, headers=headers,verify=True)
    if response is None:
        log_msg = "Failed retrieving PPSK users from XIQ - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 200:
        log_msg = f"Failed retrieving PPSK users from XIQ - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)
    rawList = response.json()['data']
    ppskusers = ppskusers + rawList

    return ppskusers




def deleteuser(userId):
    url = URL + "xapi/v2/identity/credentials?ownerid=" + ownerID + "&ids=" + str(userId)
    #print("\nTrying to delete user using this URL and payload\n " + url)
    response = requests.delete(url, headers=headers, verify=True)
    if response is None:
        log_msg = f"Failed deleting PPSK user {userId} - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 200:
        log_msg = f"Failed deleting PPSK user {userId} - HTTP Status Code: {str(response.status_code)}"
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
        log_msg = ("Successfully parsed " + str(len(ppsk_users)) + " XIQ users in Group")
        logging.info(log_msg)
        print(f"\n{log_msg}\n")
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
    ad_result = retrieveADUsers(distinguished_name)
    #print("\nParsing all users from LDAP:\n")

    for ldap_entry in ad_result:
        if str(ldap_entry.name) not in ldap_users:
            try:
                ldap_users[str(ldap_entry.name)] = {
                    "userAccountControl": str(ldap_entry.userAccountControl),
                    "email": str(ldap_entry.mail),
                    "username": str(ldap_entry.sAMAccountName)
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
    print(f"{log_msg}\n")

    ldap_disabled = []
    for name, details in ldap_users.items():
        if details['email'] == '[]':
            log_msg = (f"User {name} doesn't have a email set and will not be created in xiq")
            logging.warning(log_msg)
            print(log_msg)
            continue
        if not any(d['userName'] == name for d in ppsk_users) and not any(d == details['userAccountControl'] for d in ldap_disable_codes):
            try:
                CreatePPSKuser(name, details["email"])
            except TypeError as e:
                log_msg = f"failed to create {name}: {e}"
                logging.error(log_msg)
                print(log_msg)
            except:
                log_msg = f"Unknown Error: Failed to create user {name} - {details['email']}"
                logging.error(log_msg)
                print(log_msg)
        elif any(d == details['userAccountControl'] for d in ldap_disable_codes):
            logging.info(f"User {name} is disabled in AD with code {details['userAccountControl']}")
            ldap_disabled.append(name)

    # Remove disabled accounts from ldap users
    for name in ldap_disabled:
        del ldap_users[name]
    if ldap_capture_success:
        for x in ppsk_users:
            email = x['email']
            xiqid = x['id']
            # check if any xiq user is not included in active ldap users
            if not any(d['email'] == email for d in ldap_users.values()):
                try:
                    result = deleteuser(xiqid)
                except TypeError as e:
                    logmsg = f"Failed to delete user {email}  with error {e}"
                    logging.error(logmsg)
                    print(logmsg)
                    continue
                except:
                    log_msg = f"Unknown Error: Failed to create user {email} "
                    logging.error(log_msg)
                    print(log_msg)
                    continue
                if result == 'Success':
                    log_msg = f"User {email} was successfully deleted."
                    logging.info(log_msg)
                    print(log_msg)  
    else:
        log_msg = "No users will be deleted from XIQ because of the error(s) in reading ldap users"
        logging.warning(log_msg)
        print(log_msg)




if __name__ == '__main__':
    main()