""" this script is used to check for XSS vulenrabilities"""
"""
this vulenerability is triggered by injecting a javascript payload to an html tag
"""
from colorama import Fore, Back, Style
import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

# we need first to get all the forms in the http url
def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    # we are going to return the form tags < form> <form />
    return soup.find_all("form")

# next i should get the attributes of the form tag

def get_form_details(form):
    details = {}
    # above i created a dictionary that stores the attributes of a html tag as keys : action - method - input
    # send a get request and extract the action attribute
    action = form.attrs.get("action", "").lower()
    # send a get request and extract the method attributes (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # save the attribute inputs of the form in a list
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    """
this function is going to resubmit the forms with new input
this new input are malicious infected with js values
    """
    # joining the targeted url with the one from the action attributes in the forms
    target_url = urljoin(url, form_details["action"])
    # get the form inputs
    inputs = form_details["inputs"]
    # creating a dictionary to store the new values of the input_name
    data = {}
    for input in inputs:
        # changing the original data by the value inserted as argument in the function
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # filling the dictionary
            data[input_name] = input_value

    print(f"[+] Submitting malicious payload to {target_url}")
    # submitting the forms with the new altred data
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)


# now the function that is going to deploy the vulenerability
def scan_xss(url):
    """
    it takes a url
    Given a `url`, it prints all XSS vulnerable forms and
    returns True if any is vulnerable, False otherwise
    """
    # get all the form tags from the URL
    forms = get_all_forms(url)
    # number of forms in the URL
    print(f"[*] Detected {len(forms)} forms on {url}.")
    # the vulnerability trigger
    js_script = "<Script>alert('Problem Detected')</scripT>"
    # returning value
    is_vulnerable = False
    # run the malicious data on the forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        # we check if the vulnerability is displayed to the user
        # we are looking for a hi message on the screen
        print(Fore.LIGHTGREEN_EX + "[+]Checking For Low Risks")
        print(Style.RESET_ALL)
        print(Back.BLACK)
        Low_risk = submit_form(form_details, url, js_script)
        Low_risk = str(Low_risk)
        if js_script in content:
            print(f"[!] XSS Detected on {url}")
            print(f"[!] Form details:")
            pprint(form_details)
            is_vulnerable = True
            print("[!] A HIGH XSS RISK")
        if "400" in Low_risk:
            print(Fore.YELLOW + "[!] LOW RISK OF CODE INJECTION")
            print(Fore.YELLOW + "[!] DOESNT FILTER JS INJECTION ")
            print(Style.RESET_ALL)
            print(Back.BLACK)
    print(is_vulnerable)
    print("[±] No XSS detected")
    # This is basically checking for response errors from the window side
    return is_vulnerable

"""
 this part can be used to test separately 
print("testing for XSS")
url = "http://localhost:5000/Identity/Account/Login"
scan_xss(url)

print("the second")
url = "http://localhost:5000/Identity/Account/Register"
scan_xss(url)

print("the third")
url = "http://localhost:5000/Identity/Account/Login?ReturnUrl=%2FControl%2FControlRoom"
scan_xss(url)

print("the fourth")
url = "http://localhost:5000"
scan_xss(url)

print("the fifth")
url = "http://localhost:5000/Privacy"
scan_xss(url)

"""
