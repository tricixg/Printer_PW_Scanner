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

def check(ip_address, dept):
    url_https = f"https://{ip_address}/"
    url_http = f"http://{ip_address}/"

    session = requests.Session()

    try:
        response = session.get(url_https, verify=False, allow_redirects=True, timeout=10)

    except (requests.exceptions.SSLError, requests.exceptions.RequestException):
        try:
            response = session.get(url_http, verify=False, allow_redirects=True, timeout=10)
        except requests.exceptions.RequestException as e:
            response = None
            print(f"Error occurred while connecting to {url_https}: {e}")

    if response is None or response.status_code != 200:
        print(ip_address + "timeout")
        return [ip_address, "", dept, response]  # Return blank value
    
    if response.status_code != 200:
        print(ip_address + "timeout" + response.status_code)
        return [ip_address, "", dept, response.status_code]  # Return blank value

    response.raise_for_status()
    if check_javascript(response.text):
        print(ip_address + "JS required")
        return [ip_address, "", dept, "JS required"]
    
    if check_frames(response.text):
        print(ip_address + "Frames required")
        return [ip_address, "", dept, "Frames required"]

    device_name = get_device_name(response.text).strip()
    print([ip_address, device_name, dept])
    return [ip_address, device_name, dept]

def check_printers_from_csv(file_path):
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip header row
        results = []
        for row in reader:
            if len(row) == 2:
                ip_address, dept = row
                ip_address = ip_address.strip()
                dept = dept.strip()
                if ip_address.startswith('http://'):
                    ip_address = ip_address[len('http://'):]
                elif ip_address.startswith('https://'):
                    ip_address = ip_address[len('https://'):]
                if ip_address.endswith('/'):
                    ip_address = ip_address[:len(ip_address)-1]
                result = check(ip_address, dept)
                results.append(result)

    return results

# Create the GUI window
root = tk.Tk()
root.withdraw()

# Select the file containing the IP addresses and Departments
file_path = filedialog.askopenfilename(title="Select IP Address List", filetypes=(("CSV files", "*.csv"),))

# Parse the input CSV file
results = check_printers_from_csv(file_path)

# Create the CSV file for the output
output_file = filedialog.asksaveasfilename(title="Save Output CSV", defaultextension=".csv", filetypes=(("CSV files", "*.csv"),))
header = ['IP Address', 'Device Name', 'Department']

with open(output_file, 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(results)

print(f"Results written to {output_file}.")
