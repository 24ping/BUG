"""
this function is going to test for vulenrabilities within input
mainly checking if there is any input filter check or not
this is going to have the same structure of the as XSS
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
    # above i created a dictionnary that stores the attributes of an html tag as keys : action - method - input
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

def submit_form(form_details, url):
    """
this function is going to resubmit the forms with new input
this new input is malicious and random in order to trigger any errors
    """
    # this is going to save all the random variables
    value_type = ["-999","*********************;/../", -1, ";", ""]
    # joining the targeted url with the one from the action attributes in the forms
    target_url = urljoin(url, form_details["action"])
    # get the form inputs
    inputs = form_details["inputs"]
    # creating a dictionary to store the new values of the input_name
    data = {}
    response_get = []
    response_post =[]
    for value in value_type:
        for input in inputs:
            # changing  the original data by the value inserted as argument in the function
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                # filling the dictionary
                data[input_name] = input_value
        print(f"[+] Submitting malicious payload to {target_url}")
        # submitting the forms with the new altered data to check for any error
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
         return requests.get(target_url, params=data)

def scan_IRV(url):
    """
    it takes a url
    Given a `url`, with an input form it checks
    if it has no filter checking for inputs
    """
    # get all the form tags from the URL
    forms = get_all_forms(url)
    # number of forms in the URL
    print(f"[*] Detected {len(forms)} forms on {url}.")
    # the vulenrability trigger
    # returning value
    is_vulnerable = False
    # run the malicious data on the forms
    for form in forms:
        form_details = get_form_details(form)
        print(Fore.LIGHTGREEN_EX + "[+]Checking For Low Risks")
        print(Style.RESET_ALL)
        print(Back.BLACK)
        Low_risk = submit_form(form_details, url)
        Low_risk = str(Low_risk)
        if "400" in Low_risk:
            print(Fore.YELLOW + "[!] LOW RISK OF CODE INJECTION")
            print(Fore.YELLOW + "[!] DOESNT FILTER RANDOM INPUT ")
            is_vulnerable = True
            print(Style.RESET_ALL)
            print(Back.BLACK)
    print(is_vulnerable)
    print("[±] WEAK INPUT filtering!")
    return is_vulnerable


