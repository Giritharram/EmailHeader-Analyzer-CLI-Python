# EmailHeader-Analyzer with OSINT 📧🕵️‍♂️

Welcome to the Email Header Analyzer CLI tool which is written in Python that empowers you to dissect and analyze email headers. This CLI tool not only offers the ability to parse and interpret email headers but also integrates OSINT (Open-Source Intelligence) features to provide a deeper understanding of the email's context.


## 🛠️ How To Install
```
pip3 install -r requirements.txt
```

## 🚀 How To Run

Place Your 'TXT' or 'EML' file inside the current directory. Then create a folder named 'Input' and place a dummy file named 'sample.txt'

Create a VirusTotal account and use your own API key, you can do it [here](https://www.virustotal.com/gui/home/search)

Place your Virustotal API key inside the OSINT_Functions.py file [Assign it to vt_access_token variable]
```
python3 main.py 'sample.txt' 'argument'
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

## 🤝 Contributions

Contributions and suggestions are welcomed! Whether you'd like to enhance the existing features or add new functionalities, your involvement is highly appreciated. Feel free to submit issues, pull requests, or open discussions.
