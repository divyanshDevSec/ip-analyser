import requests
import ipaddress
from tabulate import tabulate
import pandas as pd

#Definition to check if IP is private
def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_private #Checks and returns if Ip is private or not
    except ValueError:
        print("Invalid IP Address: {ip}")
        return False
    

#Geo Location of IP
def geolocation_ip(ip):
    try:
        response= requests.get(f"https://ipinfo.io/{ip}/json")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print("Error Fetching GeoLocation:",e,"\n")
        return None


#VirusTotal Check
def virustotal_check(ip, api_key):
    try:
        url= f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers={
            "x-apikey" : api_key
        }
        response = requests.get(url,headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print("Error fetching details from Virustotal for {ip}: ", e,"\n")
        return None
    
#AbuseIP check
def abuseIP_checkI(ip, api_key):
    try:
        url= f"https://api.abuseipdb.com/api/v2/check"
        params={
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        headers={
            "Accept": "application/json",
            "Key": api_key
        }
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print("Error fetching details from AbuseIpDB for {ip}: ",e,"\n")
        return None
    

#Display result in tabular format on console
def table_output_console(data):
    return tabulate([(key, value) for key, value in data.items()], headers=["Field", "Value"], tablefmt="grid")


#Save in excel
def save_to_excel(data, filename):
    df = pd.DataFrame(list(data.items()), columns=["Field", "Value"])
    df.to_excel(filename, index=False)
    print(f"Data saved to ${filename}")

#IP Analysis
def analyseip(ip, vtapi, abapi):
    if is_public(ip):
        print("Private IP Address")
        return
    
    print(f"Analyzing {ip}","\n")

    #geo location
    geoData = geolocation_ip(ip)
    if geoData:
        print("Geo Location Data: ", table_output_console(geoData),"\n")
    

    #vt
    vtData = virustotal_check(ip, vtapi)
    if vtData:
        print("Virus Total Check: ", table_output_console(vtData),"\n")
    
    #abuseip
    abuseipData = abuseIP_checkI(ip, abapi)
    if abuseipData:
        print("Abuse IP Check: ", table_output_console(abuseipData),"\n")

    
    #Ask user to save in excel
    save_choice = input("Do you want to save output in excel?(yes/no): ")
    if save_choice=="yes":
        combined_data={**geoData, **vtData, **abuseipData}
        save_to_excel(combined_data, f"{ip}_analysis.xlsx")


def main():
    vt_apikey="YOUR_API_KEY_HERE"
    abuseIP_apikey="YOUR_API_KEY_HERE"

    while True:
        ip = input("Enter IP Address: ")
        try:
            #validate ip address
            ipaddress.ip_address(ip)
            analyseip(ip=ip, vtapi=vt_apikey, abapi=abuseIP_apikey)
            break
        except ValueError:
            print("Invalid IP Address!")
            choice = input("Exit or enter a valid IP (enter/exit)").strip().lower()
            if choice=="exit":
                print("Aborting....")
                break
        
if __name__== "__main__":
    main()