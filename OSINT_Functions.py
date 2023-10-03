import requests
import re
import nmap
import urllib
import urllib.request
import time
from prettytable import PrettyTable,ALL

#insert your VT access token
vt_access_token = ''

#storing the extracted items
ext_domain_names = []
ext_ipaddress = []
ext_url = []
  

#storing the malicious items
mal_ip = []
mal_domain=[]
#storing whois info
whois_info = {}

#Function to flat a list
def flatten(l):
    fl=[]
    for i in l:
        if type(i) is list:
            for item in i:
                fl.append(item)
        else:
            fl.append(i)
    return fl

# function to extract ip address present in the sample.txt file
def extract_ip():
    ip_add = []
    lts = []
    fli = []
    with open('Input/sample.txt', 'r') as file:
        fi = file.readlines()
        re_ip = re.compile(r"""
            \b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))\b""", re.X)

    for line in fi:
        if '127.0.0.1' in line:
            continue
        ip = re.findall(re_ip,line)
        ip_add.append(ip)

    res = list(filter(None,ip_add))

    for i in res:
        if len(i) > 1:
            lts.append(i[0])
            lts.append(i[1])
        else:
            lts.append(i)

    for i in lts:
        if type(i) is str:
            fli.append(list(i.split(" ")))
        else:
            fli.append(i)

    b = flatten(fli)

    ext_ipaddress = list(set(b))
    
    return ext_ipaddress

# function to extract domain names present in the sample.txt file
def extract_domain():
    fqdn_list = []
    tmp_domain = []
    tmp = []

    resp = urllib.request.urlopen('http://data.iana.org/TLD/tlds-alpha-by-domain.txt')

    # Create a reverse sorted list of TLD ('.com' must be before '.co')
    tld = sorted([tld.strip().lower().decode('utf-8')
                    for tld in resp.readlines()[1:]], reverse=True)

    # Compile the regex pattern
    FQDN = re.compile(fr"([^\s]*\.(?:{'|'.join(tld)}))")

    # Find all fqdn
    with open('Input/sample.txt') as fp:
        for line in fp.readlines():
            line = line.strip().lower()
            # Remove comments and blank lines
            if (len(line) == 0) or line.startswith('#'):
                continue
            # Extract FQDN
            fqdn = FQDN.findall(line)
            if fqdn:
                fqdn_list.append(fqdn[0])
    
    for i in fqdn_list:
        if 'http' not in i and ':' not in i and ';' not in i and '==' not in i:
            if '=' in i : 
                tmp1 = i.split('=')
                if len(tmp1)>0:
                    tmp_domain.append(tmp1[1])
                else:
                    tmp_domain.append(tmp1)
            if '<' in i : 
                tmp1 = i.split('<')
                tmp_domain.append(tmp1[1])

            if '(' in i : 
                tmp1 = i.split('(')
                tmp_domain.append(tmp1[1])

            if 'http' not in i and ':' not in i and ';' not in i and '==' not in i and '<' not in i and '(' not in i and '=' not in i and '-' not in i and '/' not in i and '%' not in i and i not in tmp_domain and len(i) > 7:
                tmp_domain.append(i)
    
    for i in tmp_domain:
        if 'ppops' in i or 'google.com' in i or 'gmail.com' in i or 'yahoo.com' in i:
            continue
        if '@' in i:
            a = i.split('@')
            tmp.append(a[1])
        else:
            tmp.append(i)
    
    tmp = list(set(tmp))
    ext_domain_names = tmp

    return ext_domain_names

#function to extract URLs present in the sample.txt file
def extract_url():
    tmp = []
    with open("Input/sample.txt") as file:
            for line in file:
                if 'http' in line:
                    urls = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', line)
                    for i in urls:
                        if len(str(i)) > 12 and '.' in i:
                            tmp.append(str(i))
    tmp = list(set(tmp))
    ext_url = tmp
    return ext_url


#function to find malicious IP from the extracted IPs
def ip_info(lst):

    nmi = ['No IPs were found to be malicious']
    for k in lst:
        url = ("https://www.virustotal.com/api/v3/ip_addresses/%s" % k)
        headers = {
            "Accept": "application/json",
            "x-apikey": f"{vt_access_token}"
        }
        try:
            r = requests.get(url, headers=headers).json()
            dict_web = r['data']['attributes']['last_analysis_results']
            tot_engine_c=0
            tot_detect_c=0
            result_eng = []
            eng_name = []
            for i in dict_web:
                tot_engine_c = 1 + tot_engine_c
                if dict_web[i]['category'] == "malicious" or dict_web[i]['category'] == "suspicious":
                    result_eng.append(dict_web[i]["result"])
                    eng_name.append(dict_web[i]["engine_name"])
                    tot_detect_c = 1 + tot_detect_c
            res = []
            for i in result_eng:
                if i not in res:
                    res.append(i)
            result_eng = res

            if tot_detect_c > 0:
                mal_ip.append(k)
                whois_info[k] = r['data']['attributes']['whois']
            
        except Exception as e:
            print('An error occured, Error Type:',type(e))

    if len(mal_ip)>0:
        return mal_ip
    else:
        return nmi
    
#function to find malicious URL from the extracted URLs
def url_info(lst):
    malurl = []
    nmu = ['No URLs were found to be malicious']
    if len(lst)<1:
        return nmu
    count = 0
    print("Wait for 1 to 2 minutes...")
    print('\n') 
    time.sleep(60)
    for k in lst:
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': f'{vt_access_token}', 'resource':k }
            if count!=0 and count%4 == 0:
                time.sleep(62)
            count += 1
            try: 
                response = requests.get(url, params=params)
                r = response.json()
                if r['positives']>0:
                    malurl.append(k)
            
            except Exception as e:
                print('An error occured, Error Type:',type(e))
    
    if len(malurl)>0:
        return malurl
    else:
        return nmu

#function to find malicious domain from the extracted domains
def domain_info(lst):
    nmd = ['No domains were found to be malicious']
    count = 0
    print("Wait for 1 to 2 minutes...")
    print('\n') 
    time.sleep(60)
    for k in lst:
        if count!=0 and count%4 == 0:
            time.sleep(62)
        count += 1
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey': f'{vt_access_token}','domain':k}
        try:
            r = requests.get(url, params=params).json()
            try:
                if r.get('detected_urls')[0].get('positives') > 0:
                    mal_domain.append(k)
                    whois_info[k] = r['whois']
        
            except Exception as e:
                None
        
        except Exception as e:
            print('An error occured, Error Type:',type(e))
        
    if len(mal_domain)>0:
        return mal_domain
    else:
        return nmd

#function to find passivedns for the malicious IPs if exist
def ip_passivedns(lst):
    fli = {}
    nrf = ['No records found']
    nftb = ['No IPs were found to be malicious']
    errorinfo = ['Error Occured  or API Quota may have exceeded']
    if 'No IPs were found to be malicious' in lst:
        fli['']=nftb            
        return fli
    else:
        try:
            count = 0
            for k in lst:
                count += 1
                if count%4 == 0:
                    time.sleep(62)
                url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

                params = {'apikey': f'{vt_access_token}','ip':k}

                r = requests.get(url, params=params).json()

                j = r['resolutions']
                
                if len(j) < 1:
                    fli[k]=nrf
                else:
                    fli[k]=j
                
            return fli
        except:
            fli['']=errorinfo
            return fli

#Functions to print all the results in a table

def ipaddress_information():
    all_ip = extract_ip()
    t1 = PrettyTable(['Extracted IPs'])
    t1.hrules=ALL
    for i in all_ip:
        t1.add_row([i])
    print('\n')
    print(t1)
    print('\n')

    malip= ip_info(all_ip)
    t2 = PrettyTable(['Malicious IP'])
    t2.hrules=ALL
    for i in malip:
        t2.add_row([i])
    print(t2)

def domainname_information():
    all_domain = extract_domain()
    t1 = PrettyTable(['Extracted Domains'])
    t1.hrules=ALL
    for i in all_domain:
        t1.add_row([i])
    print('\n')
    print(t1)
    print('\n')

    maldomain = domain_info(all_domain)
    t2 = PrettyTable(['Malicious Domains'])
    t2.hrules=ALL
    for i in maldomain:
        t2.add_row([i])
    print(t2)

def url_information():
    all_url = extract_url()
    t1 = PrettyTable(['Extracted URLs'])
    t1.hrules=ALL
    for i in all_url:
        t1.add_row([i])
    print('\n')
    print(t1)
    print('\n')

    malurl = url_info(all_url)
    t2 = PrettyTable(['Malicious URLs'])
    t2.hrules=ALL
    for i in malurl:
        t2.add_row([i])
    print(t2)

def passivedns_infomration():
    passivedns = ip_passivedns(mal_ip)
    t1 = PrettyTable(['IP','Passive DNS Information'])
    t1.hrules=ALL
    print('\n')
    for i,j in passivedns.items():
        t1.add_row([i,j])
    print(t1)

def whois_information():
    t1 = PrettyTable(['IP or Domain','Whois Information'])
    t1.hrules=ALL
    print('\n')
    for i,j in whois_info.items():
        t1.add_row([i,j])
    print(t1)
