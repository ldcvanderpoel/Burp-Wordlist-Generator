# Burp-Wordlist-Generator
This Burp extension extracts various data (path, parameter keys, parameter values, subdomains, etc.) from the sitemap. This data is used to create custom wordlists for directory/dns/parameter mining and brute-forcing.

Currently, the following types of data are collected:
- Paths
- Subdomains
- Parameter keys
- Parameter values
- Parameter key-value pairs (query)

Data is only collected from the following parameter types:
- URL
- Body
- JSON
- XML

Parameters from cookies, multipart forms, and XML attributes are ignored.

Furthermore, only in-scope data is collected.

# Installation
Inside Burp, go to Extender, select Add, set 'Extension type' to Python, and select the extension file.

# Usage
![image](https://user-images.githubusercontent.com/23482322/131515915-43f105e1-7f9f-47c0-b53c-8975eaa1b4d1.png)

Output can be seen by visiting the extension tab.

![image](https://user-images.githubusercontent.com/23482322/131516719-e33a90c9-6c5f-4157-a700-8cdd15de6b33.png)

The wordlists are written to: `<extension dir>/wordlists/<Burp project name>`.
