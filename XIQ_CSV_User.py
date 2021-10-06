import json
import requests
import csv

# generated xiq token with minimum "user" permissions
XIQ_token = "***"

URL = "https://api.extremecloudiq.com"
headers = {"Accept": "application/json", "Content-Type": "application/json", "Authorization": "Bearer " + XIQ_token}


def csv_reader(filename):
    with open(filename, "r",encoding='utf-8-sig') as file:
        reader = csv.reader(file, delimiter=",")
        # remove header line from CSV and adds them for dictionary keys
        user_params = next(reader)
        new_users = []
        for row in reader:
            # user dictionary
            data = {}
            for x in range(len(user_params)):
                data[user_params[x]] = str(row[x])
            new_users.append(data)
        return new_users

def CreateXIQUser(name,mail,xiq_role,idle_timeout):
    url = URL + "/users"
    payload = json.dumps({"login_name": mail,"display_name": name,"idle_timeout": idle_timeout, "user_role": "{}".format(xiq_role)})
    response = requests.post(url, headers=headers, data=payload, verify=True)
    if response is None:
        log_msg = "Error adding User - no response!"
        raise TypeError(log_msg)

    elif response.status_code == 400:
        log_msg = f"Error adding User {name}- already exist in ExtremeCloudIQ"
        raise TypeError(log_msg)

    elif response.status_code != 201:
        log_msg = f"Error adding User {name} - HTTP Status Code: {str(response.status_code)}"
        print(f"\t\t{response}")
        raise TypeError(log_msg)

    elif response.status_code ==201:
        print(f"succesfully created User {name} with login {mail}")
    #print(response)        

filename = 'UserList_test.csv'

users = csv_reader(filename)

for user in users:
    xiq_role = 'USER_ROLE_' + user['Role'].replace(' ', '_').upper()
    #print(user['displayName'], user['Email'], xiq_role, user['IdleSessionTimeout'])
    
    try:
        CreateXIQUser(user['displayName'], user['Email'], xiq_role, user['IdleSessionTimeout'])
    except TypeError as e:
        print(e)
    except:
        log_msg = f"Unknown Error: Failed to create user {user['displayName']} - {user['Email']}"
        print(log_msg)


    