import requests
import json
import base64


from key import phish_tank_key

headers = {
        'format': 'json',
        'app_key': phish_tank_key,
        }

def get_url_with_ip(URI):
    """Returns url with added URI for request"""
    url = "http://checkurl.phishtank.com/checkurl/"
    new_check_bytes = URI.encode()
    base64_bytes = base64.b64encode(new_check_bytes)
    base64_new_check = base64_bytes.decode('ascii')
    url += base64_new_check
    return url

def send_the_request_to_phish_tank(url, headers):
    """This function sends a request."""
    response = requests.request("POST", url=url, headers=headers)
    return response



new_check = 'https://atsdddatffsd.weebly.com/'

url = get_url_with_ip(new_check)
r = send_the_request_to_phish_tank(url, headers)

print(r.text)