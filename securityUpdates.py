"""

the purpose of this script is to query the euvd api (at  https://euvdservices.enisa.europa.eu/api/) for 
the latest security updates (last day), filter them and send them by mail. 

note to self: docs are found at https://euvd.enisa.europa.eu/apidoc

this program uses requests to query the api

Author's GitHub: https://github.com/Jami3k
""" 
# importing all the libararies needed

import requests
import datetime 
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import getpass
from colorama import Fore

# listing urls

last_url = "https://euvdservices.enisa.europa.eu/api/lastvulnerabilities"
critical_url = "https://euvdservices.enisa.europa.eu/api/criticalvulnerabilities"
exploited_url = "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities"
all_url = "https://euvdservices.enisa.europa.eu/api/vulnerabilities"

# initializing lists for filtering later on

url_list = [last_url, critical_url, exploited_url, all_url]
important_vendors = []
with open ("vendors.conf", "r") as file:
    for line in file:
        if not line.strip() or line.startswith("#"):                # skips comments in the vendors file
            continue
        else:
            important_vendors.append(line)
new_vulns = []
vuln_types = ["DoS", "Denial of Service", " RCE", "(RCE)", "XSS", "Cross-Site Scripting", "SQL injection", "CSRF", "SSRF", 
"Privilege Escalation", "elevate", "escalate", "Information Disclosure", 
"Buffer Overflow", "Traversal", "Command Injection", "Code execution", " authenticated", "fortnite"] # last entry for debugging only, I hate fortnite

# defining the date-cutoff function
with open ("timeframe.conf", "r") as file:
    for line in file:
        line = line.strip()
        if not line.startswith("#") and line:
            timeframe = int(line)
        else:
            continue
def is_yesterday(dateUpdated):                                                           # dateUpdates is being fed from the json for one vuln
    now = datetime.datetime.now()
    yesterday = now - datetime.timedelta(hours=timeframe)                                # used to be one-day cutoff benchmark (hence the name), now dynamic

    # converting dateUpdated from string to datetime object 
    # all times are currently in UTC format (CET = UTC + 1)
    dateUpdated = datetime.datetime.strptime(dateUpdated, "%b %d, %Y, %I:%M:%S %p")

    # checking if the dateUpdated is within the last 24 hours. If yes, continuing with formatting and sending

    if dateUpdated <= now and dateUpdated >= yesterday:
        if is_debug == True: 
            print(f"[DEBUG] date for this vuln is within the last {timeframe} hours.")
            print("[DEBUG] last updated:", dateUpdated)
        return True
    else:
        if is_debug == True:
            if url != all_url:
                print(f"[DEBUG] date for vuln not within the last {timeframe} hours. Vuln ID:", response[number]["id"])
            else: 
                print(f"[DEBUG] date for vuln not within the last {timeframe} hours. Vuln ID:", response["items"][number]["id"]) 
            print("[DEBUG] last updated:", dateUpdated)
            print("[DEBUG] that is about", (now - dateUpdated).days, "days ago.")
        return False

# defining the vulnerability identification function

def vuln_type(vuln_description):
    vulnerability_type = []
    for vt in vuln_types:
        if vt.lower() in vuln_description.lower():                      # checking the description for key words
            if vt.lower() == "escalate" or vt.lower() == "elevate":
                vulnerability_type.append("Privilege Escalation")       # converts different keywords to the same type
            elif vt.lower() == "rce" or vt.lower() == "(rce)" or vt.lower() == "command injection" or vt.lower() == "code execution":
                vulnerability_type.append("Remote Code Execution")
            elif vt.lower() == "denial of service" or vt.lower() == "dos":
                vulnerability_type.append("Denial of Service")
            elif vt.lower() == "traversal":
                vulnerability_type.append("Path Traversal")
            elif vt.lower() == "xss" or vt.lower() == "cross-site scripting":
                vulnerability_type.append("XSS")
            else:  
                vulnerability_type.append(vt)
    vulnerability_type = ", ".join(vulnerability_type)
    if vt.lower() == " authenticated" and "unauthenticated" not in vuln_description.lower():
            vulnerability_type = f"Authenticated{vulnerability_type}"
    if not vulnerability_type:
        vulnerability_type = "Other"
    print("[INFO] vuln type/s identified: ", vulnerability_type)
    vuln["vuln_type"] = vulnerability_type
    return vulnerability_type

# defining the exit message function
# prints a cute little exit message
def exit_message():
    print( Fore.GREEN + "\nAll done!", Fore.WHITE + "If you have the time, give some love to", Fore.MAGENTA + "Jami3k.", Fore.WHITE + "See you next time :) \n")
    exit(0)

# defining a debug function that enables you to query the different parameters for each vulnerability

def debug_print(vuln):
    while True:
        information = input(f"\n[DETAILS] for {vuln["id"]}: \n Please enter the information you want to print (Enter or 'next' = next vulnerability, 'options' for options, \n" \
        "'exit' to exit the entire script, 'all' for all the information on the vuln): "
        )
        if information.lower() in ["", "done", "next"]:
            break
        elif information.lower() == "exit":
            exit_message()
        elif information.lower() == "options":
            print("[INFO] available keys: ")
            for key in vuln.keys():
                print(key)
        elif information.lower() == "all":
            print("\n")
            for key in vuln.keys():
                print(key, ":", vuln[key], "\n")
            print("\n")
            continue
        else:
            try:
                print("\n")
                print (vuln[information])
            except KeyError:
                print("[ERROR] Key not found. Please try again.")
                continue

# initializing the debug kill switch
while True: 
    is_debug = input("Do you want to enable debug mode? (y/N): ")
    if is_debug.lower() in ["y", "yes", "yea", "sure", "why not"]:
       is_debug = True
       print("[INFO] debug mode enabled")
       break
    elif is_debug.lower() in ["", "n", "no", "nah", "hell no", "hell nah"]:
       is_debug = False
       print("[INFO] debug mode disabled")
       break
    else:
        print("Nice try!")

# MAIN LOGIC STARTS HERE
print(Fore.WHITE + "[STATUS] starting script...")
print("[STATUS] querying the API...")
for url in url_list:
    response_unformatted = requests.get(url, headers={"User-Agent": "Jami's query"}) # needs a user agent, otherwise it will return 403
    response = response_unformatted.json()  # this is now formatted in a list of dicts (list of vulns, each vuln is a dict with many different params)
    number = 0  # for assignment purposes

    for vuln in response:   
        if is_debug == True:                                        # iterating through vulns, checking if it was updated in the last 24 hours
            print(f"[DEBUG] vuln number {number} for url {url}")
        if url == all_url:
            date = response["items"][number]["dateUpdated"]         # the reason why this is here is because, and I'm not kidding, all other urls return a list of dicts, while all_url returns a dict with ["items"] (the list of dicts) and ["total"]
        else:                         
            date = response[number]["dateUpdated"]                                          
        if is_yesterday(date) == True:                              # this function returns true if the vuln is within 24 hours
            print(Fore.GREEN + "[+]", Fore.WHITE + "Vuln found")
            if url != all_url:
                new_vulns.append(vuln)
            else: 
                new_vulns.append(response["items"][number])
        number +=1
    if is_debug == True:
        print("\n[DEBUG] new_vulns: ")  
        for vuln in new_vulns:
            print("[DEBUG] vuln: ", vuln, "\n")
            print("[DEBUG] vuln type: ", type(vuln), "\n")  
print("\n[STATUS] found all new vulns in the last 24 hours.")
print("\n[STATUS] filtering vulnerability information...\n")                   
    
# yay 100 // well used to be line 100 lol

# Now that we have selected the new vulns, we have to select what information we want to send, and remove the rest
total_keys = ["aliases", "assigner", "baseScore", "baseScoreVector", "baseScoreVersion", "datePublished", "dateUpdated", 
"description", "enisaIdAdvisory", "enisaIdProduct", "enisaIdVendor", "enisaIdVulnerability", "epss", "id", "references"]
keys_to_remove = []
with open("keys.conf", "r") as file:
    keys_to_keep = [line.strip() for line in file if not line.strip().startswith("#") and line.strip()] 
if is_debug == True:
    print("[DEBUG] keys to keep: ", keys_to_keep)

# too lazy to change the function, so this:
for key in total_keys:
    if key not in keys_to_keep:
        keys_to_remove.append(key)
if is_debug == True:
    print("[DEBUG] keys to remove: ", keys_to_remove)

for vuln in new_vulns:
    if is_debug == True:
        print("[DEBUG] vuln before removing keys: ", vuln)
        print(type(vuln)) # should be dict
    for key in keys_to_remove:                                                                 # this removes the keys we don't need
        if key == "enisaIdVendor":
            try:
                vendor_entry = vuln["enisaIdVendor"][0]
                vuln["vendor"] = vendor_entry["vendor"]["name"]
            except IndexError as Exception:
                print(Fore.RED + "[ERROR]", str(Exception), Fore.WHITE + "")
                continue
            vuln.pop("enisaIdVendor", None)
        else:
            vuln.pop(key, None) 
print("[STATUS] Done!")
print("[STATUS] Identifying vulnerability type...\n")

# identifying the vulnerability type
for vuln in new_vulns:
    try:
        vuln_type(vuln["description"])
    except KeyError:
          print(Fore.RED + "[ERROR] vuln has no description.", Fore.WHITE + "Setting type to 'Other'.")
          vuln["vulnerability_type"] = "Other"
          continue
if is_debug == True:
    print("[DEBUG] new_vuln keys after removing keys: \n")
    for vuln in new_vulns:                                                              # this identifies the vulnerability type
        print(list(vuln.keys()), "\n")
        print("\n\n\n")
if is_debug == True:
    print("[DEBUG] new_vuln ID's after removing keys: \n")
    for vuln in new_vulns:
        vuln_id = vuln["id"]
        print(vuln_id, "\n")
print("\n[STATUS] Done!")
print("\n[STATUS] Sorting vulnerabilities by vendor...\n")

# sorting the vulns by critical vendor
important_vulns = []
not_important_vulns = []

for vuln in new_vulns:
    try:
        if vuln["vendor"].lower() in [important_vendor.lower() for important_vendor in important_vendors]: # no I also don't understand this line 
            important_vulns.append(vuln)                                                                   # don't ask me how it works but it does
        else:
            not_important_vulns.append(vuln)
    except KeyError:
        print(Fore.RED + "[ERROR] vuln has no vendor.", Fore.WHITE + "Setting type to n/a.")
        vuln["vendor"] = "n/a"
        not_important_vulns.append(vuln)
        continue
with open ("filter.conf", "r") as file:
    for line in file:
        line = line.strip()
        if not line.startswith("#") and line in total_keys:
            filter = line

reverse = False
if filter in ["baseScore", "epss", "dateUpdated" , "datePublished"]:
    reverse == True
else:
    reverse == False
important_vulns.sort(key=lambda x: x[filter], reverse=reverse)
not_important_vulns.sort(key=lambda x: x[filter], reverse=True)                # sorts the vulns by baseScore
                                                                                    # TODO: auslagern auf .conf Datei
new_vulns = important_vulns + not_important_vulns
if is_debug == True:
    print("[DEBUG] new_vulns sorted by vendor:\n")
    for vuln in new_vulns:
        print(vuln["id"], "\n")
print("[STATUS] Done!")
print("[STATUS] Reporting findings... \n")
if important_vulns:
    print (Fore.RED + "[CRITICAL] Critical vulns: ")
    for vuln in important_vulns:
        print(vuln["id"],"\n")
        print (vuln["description"], "\n")
        print (vuln["vendor"], Fore.WHITE + "\n")
else:
    print(Fore.GREEN + "[REPORT] No critical vulns found in the last 24 hours.\n")
    print(Fore.WHITE + "[REPORT] Total vulns found: ", len(new_vulns), "\n")



print("[STATUS] Sending information via email...\n")

# email sending logic

with open("smtp.conf", "r") as file:
    smtp_config = [line.strip() for line in file]
receivers = []
password = None
for line in smtp_config:
    if line.startswith("sender"):
        sender_email = line.split("=")[1].strip()
    elif line.startswith("receiver"):
        receivers += ([email.strip() for email in line.split("=")[1].split(",")])
    elif line.startswith("smtp_username"):
        sender_email = line.split("=")[1].strip()
    elif line.startswith("smtp_server"):
        smtp_server = line.split("=")[1].strip()
    elif line.startswith("smtp_port"):
        smtp_port = int(line.split("=")[1].strip())
    elif line.startswith("smtp_password"):
        password = line.split("=")[1].strip()

if not password:
    password = getpass.getpass("Input your custom smtp password here: ")
message = MIMEMultipart("alternative")
message["Subject"] = f"Security Updates {datetime.datetime.now().strftime('%Y-%m-%d')}" 
message["From"] = sender_email
html = """\
<html>
    <body>
        <p> Hey mate, <br>
            new <strong>security updates</strong> just dropped. Check them out!<br>"""

def print_results():
    global html
    for vuln in new_vulns:
        for key in vuln.keys():
            if key == "id":
                html += f"<hr><b>ID: </b> {vuln.get('id', '')}<br>"
            elif key == "description":
                html += f"<b>Description: </b> {vuln.get('description', '')}<br>"
            elif key == "baseScore":
                html += f"<b>CVSS Score: </b> {vuln.get('baseScore', '')}<br>"
            elif key == "baseScoreVector":
                html += f"<b>CVSS Vector: </b> {vuln.get('baseScoreVector', '')}<br>"
            elif key == "baseScoreVersion":
                html += f"<b>CVSS Version: </b> {vuln.get('baseScoreVersion', '')}<br>"
            elif key == "assigner":
                html += f"<b>Assigner: </b> {vuln.get('assigner', '')}<br>"
            elif key == "epss":
                html += f"<b>Exploit Prediction Scoring System Score: </b> {vuln.get('epss', '')}<br>"
            elif key == "vendor":
                if vuln.get("vendor", "") not in important_vendors:
                    html += f"<b>Affected vendor: </b> {vuln.get('vendor', '')}<br>"
                else:
                    html += f"<b>Affected vendor (critical!): </b> <strong>{vuln.get('vendor', '')}</strong><br>"
            elif key == "vuln_type":
                html += f"<b>Vulnerability type: </b> {vuln.get('vuln_type', '')}<br>"
            elif key == "references":
                html += f"<b>References: </b> <a href=\"{vuln.get('references', '')}\">{vuln.get('references', '')}</a><br>"
            elif key == "aliases":
                html += f"<b>Aliases: </b> {vuln.get('aliases', '')}<br>"
            elif key == "dateUpdated":
                html += f"<b>Date updated: </b> {vuln.get('dateUpdated', '')}<br>"
            elif key == "datePublished":
                html += f"<b>Date published: </b> {vuln.get('datePublished', '')}<br>"
            else:
                html += f"<b>{key}: </b> {vuln.get(key, '')}<br>"
        html += f"<br><br>"
    html += """
    </body>
</html>
    """

print_results()

# sending email

def send_emails():
    part1 = MIMEText(html, "html")
    message.attach(part1)
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            print("[STATUS] Connecting...")
            server.starttls(context=context)
            server.ehlo()
            print("[STATUS] Authenticating...")
            try:
                server.login(sender_email, password)
            except Exception as Exception:
                print(Fore.RED + "[CRITICAL] Authentication failed. Please check your credentials and try again")
                exit(1)
            print("[STATUS] Sending emails...\n")
            for receiver in receivers:
                message["To"] = receiver
                server.sendmail(sender_email, receiver, message.as_string())
                print(Fore.GREEN + "[SUCCESS] Email sent successfully to", receiver, Fore.WHITE + "")
    except Exception as Exception:
        print(Fore.RED + "[CRITICAL]", Fore.WHITE + "Couldn't send email to", receiver)
        print(Exception)

send_emails()
exit_message()