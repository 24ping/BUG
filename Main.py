""" this is representing a simple drawing for the user beauty """
# this is used basically to  call the SQL injection  all the modules
import SqlInjection
import xss
import InputRandomVariable

from colorama import Fore, Back, Style
print(Fore.RED)
print(Back.BLACK)
print(Style.BRIGHT)
f = open('character.txt','r')
file_content = f.read()
print(file_content)
print(Style.RESET_ALL)
f.close()
print(Fore.GREEN)
print(Back.BLACK)
f = open('character2.txt','r')
file_content = f.read()
print(file_content)
f.close()
print(Back.BLACK)
print(Fore.LIGHTGREEN_EX)
print("Welcome!! BUG is scanning tool for endpoints!\n")
print("Be Careful \n")
print(Fore.WHITE)
print("press -h for more info")

task = input()
while task != "q":
    if task == "-h":
        print("\n")
        print(Fore.LIGHTGREEN_EX +"------------------------------------------------------------------")
        print(Fore.WHITE)
        print("BUG open source tool created to scan endpoints for vulnerubilities")
        print("-h: more inforamtion\n")
        print(Fore.LIGHTRED_EX)
        print("[command][endpoint]")
        print(Fore.WHITE)
        print("command:")
        print(Fore.LIGHTRED_EX)
        print("-s")
        print(Fore.WHITE + ":SQl Injection scan")
        print(Fore.LIGHTRED_EX)
        print("-x")
        print(Fore.WHITE + ":XSS scan")
        print(Fore.LIGHTRED_EX)
        print("-i")
        print(Fore.WHITE + ":Random input scan\n")
        print("q: exit the tool")
        print("-h: more inforamtion\n")
        task = input()
    elif task[:2] == "-s":
        print(Fore.LIGHTGREEN_EX +"[+]running SQL injection ")
        print(Fore.WHITE)
        url = task[3:]
        SqlInjection.scan_sql_injection(url)
        task = input()
    elif task[:2] == "-x":
        print(Fore.LIGHTGREEN_EX + "[+]running Cross Site Scripting")
        print(Fore.WHITE)
        url = task[3:]
        xss.scan_xss(url)
        task = input()
    elif task[:2] == "-i":
        print(Fore.LIGHTGREEN_EX + "[+]running Random input scan")
        print(Fore.WHITE)
        url = task[3:]
        InputRandomVariable.scan_IRV(url)
        task = input()


