# EmailHeader-Analyzer with OSINT

This tool is a CLI version of EH[Email Header]-Analyzer with the integration of OSINT features.

## How To Install
```
pip3 install -r requirements.txt
```

## How To Run

Place Your 'TXT' or 'EML' file inside the current directory. Then create a folder named 'Input' and place a dummy file named 'sample.txt'

Create a VirusTotal account and use your own API key, you can do it [here](https://www.virustotal.com/gui/home/search)

Place your Virustotal API key inside the OSINT_Functions.py file [Assign it to vt_access_token variable]
```
python3 main.py 'file' 'argument'
```
Give any one of the following arguments

```
 -h                -> Help                    
 -Eh               -> Email header analysis   
 -Ipinfo           -> IP Information                      
 -Domaininfo       -> Domain Information      
 -URLinfo          -> URL Information   
 ```
 
 After Trying all of the above arguments, try out the below ones
 
 ```
 -IPpassive        -> Passive DNS Information
 -Whois            -> Whois Information
 ```
