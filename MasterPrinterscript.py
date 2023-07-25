import requests
from bs4 import BeautifulSoup
import warnings
import csv
import tkinter as tk
from tkinter import filedialog


verify = False
# Disable all warnings
warnings.filterwarnings("ignore")
def BROget_payload_name(html):
    soup = BeautifulSoup(html, 'html.parser')
    # Find the input field with type="password"
    password_input = soup.find('input', {'type': 'password'})
    if password_input:
        # Extract the name attribute from the password input field
        name_attribute = password_input.get('name', '')
    else:
        print("name attribute not found")
        return "not found"
    return name_attribute

def BROget_sign_in_path(html):
    soup = BeautifulSoup(html, 'html.parser')
    # Find the input field with type="password"
    loginurl_input = soup.find('input', {'name': 'loginurl'})    
    if loginurl_input:
        loginurl_value = loginurl_input.get('value', '') if loginurl_input else ''
    else: 
        print("log in path not found")
        return "Not found"
    return loginurl_value


def get_device_name(html):
    soup = BeautifulSoup(html, 'html.parser')
    device_name = ''

    title_element = soup.find('title')
    if title_element:
        device_name = title_element.text.strip()
    else:
        device_name = 'Device name not found'

    return device_name

def check_javascript(html):
    javascript_content = 'Please enable JavaScript'
    return javascript_content in html

def check_frames(html):
    frames_content = 'Use a browser that supports frames.'
    return frames_content in html

def get_Bizhub_device_name(html):
    soup = BeautifulSoup(html, 'html.parser')
    device_name = ''

    device_name_element = soup.find('div', {'id': 'Header_DeviceName'})

    # Extract the device name if the element is found
    if device_name_element:
        device_name = device_name_element.text.strip()
    else:
        device_name = "Bizhub"

    return device_name

def HP_get_sign_in_path(html):
    soup = BeautifulSoup(html, 'html.parser')
    sign_in_link = soup.find('a', {'class': 'logoff'})

    if sign_in_link:
        sign_in_path = sign_in_link['href']
        return sign_in_path

    return None

def get_csrf_token(html):
    soup = BeautifulSoup(html, 'html.parser')
    token_input = soup.find('input', {'name': 'CSRFToken'})
    if token_input:
        return token_input['value']
    return None

def check(ip_address, department):
    url_https = f"https://{ip_address}"
    url_http = f"http://{ip_address}"
    url = ""

    session = requests.Session()

    try:
        response = session.get(url_https, verify=False, allow_redirects=True, timeout=10)
        url = url_https
    except (requests.exceptions.SSLError, requests.exceptions.RequestException):
        try:
            response = session.get(url_http, verify=False, allow_redirects=True, timeout=10)
            url = url_http
        except requests.exceptions.RequestException:
            response = None

    if response is None or response.status_code != 200:
        print(ip_address + " timeout")
        return [ip_address, department, "Timeout", "", "",""] # Return blank value
    
    if check_javascript(response.text):
        print(ip_address + "JS required")
        return [ip_address,department, "JS required","","",""]
    
    if check_frames(response.text):
        print(ip_address + "Frames required")
        return [ip_address,department, "Frames required","","",""]
    
    response.raise_for_status()
    #Bizhub
    if "/wcd/index.html" in response.text:
        response = session.get(url+'/wcd/spa_login.html', verify=False, allow_redirects=True, timeout=10)
        device_name = get_Bizhub_device_name(response.text)
        csrf_token = get_csrf_token(response.text)

        payload = {
            'func': 'PSL_LP1_LOG',
            'AuthType': 'None',
            'TrackType': '',
            'ExtSvType': '0',
            'PswcForm': '',
            'Mode': '',
            'publicuser': '',
            'username': '',
            'password': 'admin',
            'AuthorityType': '',
            'R_ADM': 'AdminAdmin',
            'ExtServ': '0',
            'ViewMode': '',
            'BrowserMode': '',
            'Lang': '',
            'trackname': '',
            'trackpassword': ''
        }

        response = session.post(url+"/wcd/login.cgi", data=payload, allow_redirects=True)
        if 'CommonLoginError' in response.text:
            print("Default password is not being used.")
            default_password_used = 'No'
        else:
            print("Default password is being used.")
            default_password_used = 'Yes'

        print([ip_address, department, device_name, "/wcd/index.html", csrf_token is not None, default_password_used])

        return [ip_address, department, device_name, "/wcd/index.html", csrf_token is not None, default_password_used]
    
    else:
        
        device_name = get_device_name(response.text)

        if 'HP' in device_name:

            csrf_token = get_csrf_token(response.text)
            sign_in_path = HP_get_sign_in_path(response.text)

            if sign_in_path is None:
                print("Sign-in path not found. No Password set")
                return [ip_address,department, device_name, "No Password Set", csrf_token is not None , "NA"]

            print("Sign-in Path: " + sign_in_path)

            url_signin = f"{url}{sign_in_path}"

            # Basic Auth 
            if "set_config_password.html" in sign_in_path:
                payload = {'username': 'admin', 'password': 'admin'}
                response = session.post(url_signin, data=payload, verify=False)
                
                if response.status_code != 200:
                    print("Failed to send payload.")
                    return [ip_address,department, device_name, sign_in_path,  csrf_token is not None , "No"]
            
            try:
                response = session.get(url_signin, verify=False, allow_redirects=True, timeout=10)
            except requests.exceptions.RequestException:
                response = None

            if response is None or response.status_code != 200:
                print(response)
                print(f"{ip_address} timeout sign in page")
                return [ip_address, department, device_name, sign_in_path, "timeout sign in"]  # Return blank value

            if not csrf_token:
                print("CSRF token not found. Proceeding without")
                
                payload = {
                    'agentIdSelect': 'hp_EmbeddedPin_v1',
                    'PinDropDown': 'AdminItem',
                    'PasswordTextBox': 'admin',
                    'signInOk': 'Sign In'
                }

            else: 
                print("CSRF Token: " + csrf_token)
                payload = {
                    'CSRFToken': csrf_token,
                    'agentIdSelect': 'hp_EmbeddedPin_v1',
                    'PinDropDown': 'AdminItem',
                    'PasswordTextBox': 'admin',
                    'signInOk': 'Sign In'
                }

            response = session.post(url_signin, data=payload, verify=False)
            if 'Sign-In failed' in response.text:
                print("Default password is not being used.")
                default_password_used = 'No'
            else:
                print("Default password is being used.")
                default_password_used = 'Yes'
            print([ip_address,department, device_name, sign_in_path, csrf_token is not None, default_password_used])
            return [ip_address,department, device_name, sign_in_path, csrf_token is not None, default_password_used]
        
        #Brother
        if "Brother" in device_name:
            csrf_token = get_csrf_token(response.text)

            if "Please&#32;configure&#32;the&#32;password" in response.text:
                print([ip_address,department, device_name, "", csrf_token is not None, "no password set"])
                return [ip_address,department, device_name, "", csrf_token is not None, "no password set"]
            
            sign_in_path = BROget_sign_in_path(response.text)
            name = BROget_payload_name(response.text)
            # print(response.text)
            if not name:
                return [ip_address,department, device_name,  " " , csrf_token is not None, default_password_used]

            if not csrf_token:
                print("CSRF token not found. Proceeding without")
                
                payload = {
                    name : 'admin',
                    'loginurl': sign_in_path
                }

            else: 
                print("CSRF Token: " + csrf_token)
                payload = {
                    'CSRFToken': csrf_token,
                    name : 'admin',
                    'loginurl': sign_in_path
                }
                
            response = session.post(response.url, data=payload, verify=False, allow_redirects=True)
            

            if 'Login&#32;Failure' in response.text:
                print("Default password is not being used.")
                default_password_used = 'No'
            else:
                print("Default password is being used.")
                default_password_used = 'Yes'
            print([ip_address, department,device_name, name + " " + sign_in_path, csrf_token is not None, default_password_used])
            return [ip_address,department, device_name, name + " " + sign_in_path, csrf_token is not None, default_password_used]

        if 'EpsonNet' in device_name:
            csrf_token = get_csrf_token(response.text)

            if 'Login' not in response.text:
                print([ip_address,department, device_name, "", csrf_token is not None, "Password not set"])

                return [ip_address,department, device_name, "", csrf_token is not None, "Password not set"]

            device_name = 'EpsonNet'
            payload = {
                'adminpass': 'admin',
                'submit': 'OK'
            }
            response = requests.post(url+"/admin.cgi", data=payload, allow_redirects=True)
            if 'Invalid Password' in response.text:
                print("Default password is not being used.")
                default_password_used = 'No'
            else:
                print("Default password is being used.")
                default_password_used = 'Yes'

       

     # print(response.text)
            print([ip_address,department, device_name, "/pass.html", csrf_token is not None, default_password_used])

            return [ip_address,department, device_name, "/pass.html", csrf_token is not None, default_password_used]


     # print(response.text)
        print([ip_address,department, device_name, "", "", ""])

        return [ip_address,department, device_name, "", "", ""]
def check_default_password_from_file(file_path):
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row
        results = []
        for row in reader:
            if len(row) == 2:  # Expecting IP and Department in each row
                ip_address, department = row
                ip_address = ip_address.strip()
                department = department.strip()

                if ip_address.startswith('http://'):
                    ip_address = ip_address[len('http://'):]
                elif ip_address.startswith('https://'):
                    ip_address = ip_address[len('https://'):]
                if ip_address.endswith('/'):
                    ip_address = ip_address[:len(ip_address)-1]

                if not department:
                    department = "N/A"
                result = check(ip_address, department)
                results.append(result)

            else:
                break  # Stop the loop if there are no more rows in the CSV file

    return results


# Create the GUI window
root = tk.Tk()
root.withdraw()

# Select the file containing the IP addresses and departments
file_path = filedialog.askopenfilename(title="Select IP Address List", filetypes=(("CSV files", "*.csv"),))

# Parse the input file
results = check_default_password_from_file(file_path)

# Create the CSV file
output_file = filedialog.asksaveasfilename(title="Save Output CSV", defaultextension=".csv", filetypes=(("CSV files", "*.csv"),))
header = ['IP Address', 'Department', 'Device Name', 'Sign-in Path', 'CSRF Token Present?', 'Default Password Used?']

with open(output_file, 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(results)

print(f"Results written to {output_file}.")
