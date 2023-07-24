import requests
from bs4 import BeautifulSoup
import warnings
import csv
import tkinter as tk
from tkinter import filedialog


verify = False
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS='ALL'
# Disable all warnings
warnings.filterwarnings("ignore")

def check_javascript(html):
    javascript_content = 'Please enable JavaScript'
    return javascript_content in html

def get_device_name(html):
    soup = BeautifulSoup(html, 'html.parser')

    # device_name_element = soup.find('p', {'class': 'device-name', 'id': 'HomeDeviceName'})
    # device_name = device_name_element.text.strip() if device_name_element else ''

    # if not device_name:
    #     user_id_element = soup.find('div', {'class': 'userId'})
    #     device_name = user_id_element.text.strip() if user_id_element else ''

    # if not device_name:
    #     product_element = soup.find('strong', {'class': 'product'})
    #     device_name = product_element.text.strip() if product_element else ''

    # if not device_name:
    title_element = soup.find('title')
    device_name = title_element.text.strip() if title_element else 'Device name not found'

    return device_name


def get_sign_in_path(html):
    soup = BeautifulSoup(html, 'html.parser')
    sign_in_link = soup.find('a', string='Sign In')

    if sign_in_link:
        sign_in_path = sign_in_link.get('href', '')

        if not sign_in_path.startswith('/'):
            sign_in_path = '/' + sign_in_path

        return sign_in_path

    return None



def get_csrf_token(html):
    soup = BeautifulSoup(html, 'html.parser')
    token_input = soup.find('input', {'name': 'CSRFToken'})
    if token_input:
        return token_input['value']
    return None

def check_default_password(ip_address):
    session = requests.Session()

    url = f"https://{ip_address}"
    try:
        response = session.get(url, verify=False, allow_redirects=True, timeout=10)
    except requests.exceptions.RequestException:
        url = f"http://{ip_address}"
        try:
            response = session.get(url, verify=False, allow_redirects=True, timeout=10)
        except requests.exceptions.RequestException:
            try:
                response = session.get(url, verify=False, allow_redirects=True, timeout=10)
            except (requests.exceptions.SSLError, requests.exceptions.RequestException) as e:
                print(f"Error occurred while connecting to {ip_address}: {e}")
                return [ip_address, "Error", "", ""]  # Return error message


    if response is None or response.status_code != 200:
        print(f"{ip_address} timeout initial")
        return [ip_address, "Timeout initial", "", ""]  # Return blank value

    if check_javascript(response.text):
        print(ip_address + " JS required")
        return [ip_address, "JS required", "", ""]
    
    device_name = get_device_name(response.text)
    if 'HP' in device_name:

        csrf_token = get_csrf_token(response.text)
        sign_in_path = get_sign_in_path(response.text)

        if sign_in_path is None:
            print("Sign-in path not found. No Password set")
            return [ip_address, device_name, "No Password Set", csrf_token is not None , "NA"]

        print("Sign-in Path: " + sign_in_path)

        url_signin = f"{url}{sign_in_path}"

        # Basic Auth 
        if "set_config_password.html" in sign_in_path:
            payload = {'username': 'admin', 'password': 'admin'}
            response = session.post(url_signin, data=payload, verify=False)
            
            if response.status_code != 200:
                print("Failed to send payload.")
                return [ip_address, device_name, sign_in_path,  csrf_token is not None , "No"]
        
        try:
            response = session.get(url_signin, verify=False, allow_redirects=True, timeout=10)
        except requests.exceptions.RequestException:
            response = None

        if response is None or response.status_code != 200:
            print(response)
            print(f"{ip_address} timeout sign in page")
            return [ip_address, "Timeout sign in page", "", ""]  # Return blank value

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
        print([ip_address, device_name, sign_in_path, csrf_token is not None, default_password_used])
        return [ip_address, device_name, sign_in_path, csrf_token is not None, default_password_used]
    else:
        print([ip_address, 'not HP', '', '',''])
        return [ip_address, 'not HP', '', '','']


def check_default_password_from_file(file_path):
    with open(file_path, 'r') as file:
        ip_addresses = file.readlines()

    results = []
    for ip_address in ip_addresses:
        ip_address = ip_address.strip()  # Remove leading/trailing whitespace and newlines

        if not ip_address:  # Skip empty lines
            continue

        if ip_address.startswith('http://'):
            ip_address = ip_address[len('http://'):]
        elif ip_address.startswith('https://'):
            ip_address = ip_address[len('https://'):]
        if ip_address.endswith('/'):
            ip_address = ip_address[:len(ip_address)-1]

        result = check_default_password(ip_address)
        results.append(result)

    return results



# Create the GUI window
root = tk.Tk()
root.withdraw()

# Select the file containing the IP addresses
file_path = filedialog.askopenfilename(title="Select IP Address List", filetypes=(("Text files", "*.txt"),))

# Parse the input file
results = check_default_password_from_file(file_path)

# Create the CSV file
output_file = filedialog.asksaveasfilename(title="Save Output CSV", defaultextension=".csv", filetypes=(("CSV files", "*.csv"),))
header = ['IP Address', 'Device Name', 'Sign-in Path', 'CSRF Token Present?', 'Default Password Used?']

with open(output_file, 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(results)

print(f"Results written to {output_file}.")