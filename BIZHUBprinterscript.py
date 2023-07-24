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
    device_name = ''

    title_element = soup.find('title')
    if title_element:
        device_name = title_element.text.strip()
    else:
        device_name = 'Device name not found'

    return device_name

def get_device_name(html):
    soup = BeautifulSoup(html, 'html.parser')
    device_name = ''

    device_name_element = soup.find('div', {'id': 'Header_DeviceName'})

    # Extract the device name if the element is found
    if device_name_element:
        device_name = device_name_element.text.strip()
    else:
        device_name = None

    return device_name

def get_sign_in_path(html):
    soup = BeautifulSoup(html, 'html.parser')
    sign_in_link = soup.find('a', {'class': 'logoff'})

    if sign_in_link:
        sign_in_path = sign_in_link['href']
        return sign_in_path

    return "Sign in path not found"

def get_csrf_token(html):
    soup = BeautifulSoup(html, 'html.parser')
    token_input = soup.find('input', {'name': 'CSRFToken'})
    if token_input:
        return token_input['value']
    return None


def check(ip_address):
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
        print(ip_address + "timeout")
        return [ip_address, "Timeout", "", ""] # Return blank value
    response.raise_for_status()
    if "/wcd/index.html" in response.text:
        response = session.get(url+'/wcd/spa_login.html', verify=False, allow_redirects=True, timeout=10)

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

        print([ip_address, "BizHub", "/wcd/index.html", csrf_token is not None, default_password_used])

        return [ip_address, "BizHub", "/wcd/index.html", csrf_token is not None, default_password_used]
    else:

        print([ip_address, "Not BizHub", "", "", ""])

        return [ip_address, "Not BizHub", "","", ""]


    


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

        result = check(ip_address)
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
header = ['IP Address', 'Device Name', 'Sign-in Path', 'CSRF Token Present?']

with open(output_file, 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(results)

print(f"Results written to {output_file}.")
