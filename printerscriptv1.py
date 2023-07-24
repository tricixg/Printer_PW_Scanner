import requests
from bs4 import BeautifulSoup
import warnings
import csv
import tkinter as tk
from tkinter import filedialog



verify = False
# Disable all warnings
warnings.filterwarnings("ignore")

def get_device_name(html):
    soup = BeautifulSoup(html, 'html.parser')
    device_name_element = soup.find('p', {'class': 'device-name', 'id': 'HomeDeviceName'})
    device_name = device_name_element.text if device_name_element else ''
    return device_name

def get_sign_in_path(ip_address):
    url = f"https://{ip_address}"
    session = requests.Session()

    # Disable SSL certificate verification
    session.verify = False

    response = session.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
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

def check_default_password(ip_address):
    sign_in_path = get_sign_in_path(ip_address)
    
    if sign_in_path is None:
        print("Sign-in path not found.")
        return (ip_address, "", "", "", "", "")

    print("Sign-in Path: " + sign_in_path)
    url = f"https://{ip_address}{sign_in_path}"
    session = requests.Session()

    # Disable SSL certificate verification
    session.verify = False

    response = session.get(url, verify=False)
    csrf_token = get_csrf_token(response.text)

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

    response = session.post(url, data=payload, verify=False)

    if 'Sign-In failed' in response.text:
        print("Default password is not being used.")
        default_password_used = 'No'
    else:
        print("Default password is being used.")
        default_password_used = 'Yes'

    device_name = get_device_name(response.text)

    return [ip_address, device_name, sign_in_path, csrf_token is not None, default_password_used]


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
