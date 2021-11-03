import sys
import socket
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE

# Global Variables - ADD CORRECT VALUES
server_name = "enter the server name/ IP"
domain_name = "enter the domain name"
user_name = "enter AD username"
password = " enter AD password"
usergroupID = '*****'
ad_group = "Enter AD group ID"
fqdn = "Enter fqdn"


def retrieveADUsers(ad_group):
    #Building search base from fqdn
    subdir_list = fqdn.split('.')
    if len(subdir_list) > 1:
        tdl = subdir_list[-1]
        subdir_list = subdir_list[:-1]
        SearchBase = 'DC=' + ',DC='.join(subdir_list) + ',DC=' + tdl
    else:
        SearchBase = 'DC=' + fqdn
    print(SearchBase)
    #try:
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
    #except:
    #    log_msg = f"Unable to reach server {server_name}"
    #    print(log_msg)
    #    print("script exiting....")
    #    raise SystemExit
    

def main():
    a = server_name.split('.')
    if len(a) != 4:
        try:
            ip = socket.gethostbyname(server_name)
        except socket.gaierror:
            print ("cannot resolve hostname: ", server_name	)
            raise SystemExit
        print("The ip address for {} is {}".format(server_name, ip))	
    else:
        ip = server_name
        dns = socket.gethostbyaddr(ip)
        device = dns[0]
        print("DNS for {} is {}".format(ip, device))
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