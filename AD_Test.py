import sys
import socket
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE

# Global Variables - ADD CORRECT VALUES
server_name = "enter the server name/ IP"
domain_name = "enter the domain name"
user_name = "enter AD username"
password = " enter AD password"
distinguished_name = "Enter Distinguished Name string"


def retrieveADUsers(ad_group):
    #Building search base from domain_name
    subdir_list = domain_name.split('.')
    tdl = subdir_list[-1]
    subdir_list = subdir_list[:-1]
    SearchBase = 'DC=' + ',DC='.join(subdir_list) + ',DC=' + tdl
    #try:
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
    #except:
    #    log_msg = f"Unable to reach server {server_name}"
    #    logging.error(log_msg)
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
        try:
            dns = socket.gethostbyaddr(ip)
            device = dns[0]
            print("DNS for {} is {}".format(ip, device))
        except:
            print("The DNS for {} is an Unknown Host".format(ip))
            device = ip
        
    ldap_users = {}
    ldap_capture_success = True
    ad_result = retrieveADUsers(distinguished_name)
    #print(ad_result)
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
                print(log_msg)
                # not having ppsk will break later line - for name, details in ldap_users.items():
                ldap_capture_success = False
                continue
            
    for name, details in ldap_users.items():
        print(name, details)

if __name__ == '__main__':
    main()