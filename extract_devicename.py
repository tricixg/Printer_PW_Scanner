import requests
from bs4 import BeautifulSoup
import warnings
import csv
import tkinter as tk
from tkinter import filedialog


verify = False
# Disable all warnings
warnings.filterwarnings("ignore")

def check_javascript(html):
    javascript_content = 'Please enable JavaScript'
    return javascript_content in html

def check_frames(html):
    frames_content = 'Use a browser that supports frames.'
    return frames_content in html

def get_device_name(html):
    soup = BeautifulSoup(html, 'html.parser')
    device_name = ''

    # HP
    device_name_element = soup.find('p', {'class': 'device-name', 'id': 'HomeDeviceName'})
    if device_name_element:
        device_name = device_name_element.text.strip()
        print("HP")

    # BizHub
    if not device_name:
        device_name_element = soup.find('div', {'id': 'Header_DeviceName'})
        if device_name_element:
            device_name = device_name_element.text.strip()
            print("Bizhub")

    # Fuji Xerox
    if not device_name:
        device_name_element = soup.find('td', {'id': 'productName'})
        if device_name_element:
            device_name = device_name_element.text.strip()
            print("Fuji Xerox")

    # Konica Minolta
    if not device_name:
        device_name_element = soup.find('td', text='Device Name')
        if device_name_element:
            device_name = device_name_element.find_next('td').text.strip()
            print("Konica Minolta")

    # Brother & others
    if not device_name:
        title_element = soup.find('title')
        if title_element:
            device_name = title_element.text.strip()
            print("title")
        else:
            device_name = 'Device name not found'

    return device_name

def get_device_name(html):
    soup = BeautifulSoup(html, 'html.parser')
    device_name = ''

    title_element = soup.find('title')
    if title_element:
        device_name = title_element.text.strip()
    else:
        device_name = 'Device name not found'

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

    session = requests.Session()

    try:
        response = session.get(url_https, verify=False, allow_redirects=True, timeout=10)
    except (requests.exceptions.SSLError, requests.exceptions.RequestException):
        try:
            response = session.get(url_http, verify=False, allow_redirects=True, timeout=10)
        except requests.exceptions.RequestException:
            response = None

    if response is None or response.status_code != 200:
        print(ip_address + "timeout")
        return [ip_address, "Timeout", "", ""] # Return blank value

    response.raise_for_status()
    if check_javascript(response.text):
        print(ip_address + "JS required")
        return [ip_address, "JS required", "", ""]
    
    if check_frames(response.text):
        print(ip_address + "Frames required")
        return [ip_address, "Frames required", "", ""]

    sign_in_path = get_sign_in_path(response.text)
    csrf_token = get_csrf_token(response.text)
    device_name = get_device_name(response.text).strip()
    # print(response.text)
    print([ip_address, device_name, sign_in_path, csrf_token is not None])

    return [ip_address, device_name, sign_in_path, csrf_token is not None]


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
