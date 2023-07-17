import requests
from bs4 import BeautifulSoup
import warnings



verify = False
# Disable all warnings
warnings.filterwarnings("ignore")

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
    print("Sign-in Path: " + sign_in_path)
    if not sign_in_path:
        print("Sign-in path not found. Aborting.")
        return

    url = f"https://{ip_address}{sign_in_path}"
    session = requests.Session()

    # Disable SSL certificate verification
    session.verify = False

    response = session.get(url, verify=False)
    csrf_token = get_csrf_token(response.text)

    if not csrf_token:
        print("CSRF token not found. Proceednig without")
        
        payload = {
        'agentIdSelect': 'hp_EmbeddedPin_v1',
        'PinDropDown': 'AdminItem',
        'PasswordTextBox': 'admin',
        'signInOk': 'Sign In'
        }

    else: 
        print("CSRF Token:" + csrf_token)
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
    else:
        print("Default password is being used.")

# Example usage
ip_address = 'insert ip address here'
check_default_password(ip_address)
