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

def is_epson_printer(device_name):
    print('EpsonNet' in device_name)
    return 'EpsonNet' in device_name

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
    
    csrf_token = get_csrf_token(response.text)
    device_name = get_device_name(response.text).strip()
    print(response.text)
    if 'Login' not in response.text:
        print([ip_address, device_name, "", csrf_token is not None, "Password not set"])

        return [ip_address, device_name, "", csrf_token is not None, "Password not set"]

    if is_epson_printer(device_name):
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
    print([ip_address, device_name, "/pass.html", csrf_token is not None, default_password_used])

    return [ip_address, device_name, "/pass.html", csrf_token is not None, default_password_used]

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
