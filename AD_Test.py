import sys
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE

# Global Variables - ADD CORRECT VALUES
server_name = "DADOH-DC.SmithHome.local"
domain_name = "SMITHHOME"
user_name = "Administrator"
password = "Password123"
usergroupID = "769490635824031"
ad_group = "Staff_User"
fqdn = "smithhome.local"


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
        print(log_msg)
        print("script exiting....")
        raise SystemExit
    

def main():
    ldap_users = {}
    ldap_capture_success = True
    ad_result = retrieveADUsers(ad_group)
    for ldap_entry in ad_result:
        if str(ldap_entry.name) not in ldap_users:
            try:
                ldap_users[str(ldap_entry.name)] = {
                    "userAccountControl": str(ldap_entry.userAccountControl),
                    "email": str(ldap_entry.mail)}

            except:
                log_msg = (f"Unexpected error: {sys.exc_info()[0]}")
                print(log_msg)
                # not having ppsk will break later line - for name, details in ldap_users.items():
                ldap_capture_success = False
                continue

    for name, details in ldap_users.items():
        print(name, details)

if __name__ == '__main__':
    main()