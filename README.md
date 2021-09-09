# Burp-Wordlist-Generator
Generates wordlists from the Burp sitemap.

Everyone in offensive cyber security (pentesting/bug bounty) uses the same wordlists (SecLists, WFuzz, Assetnode, etc.). Creating your own custom wordlists is necessary to differentiate yourself from hordes of automated scanners. This Burp extension extracts various kinds of data (path, parameter keys, parameter values, subdomains, etc.) from the Burp sitemap and stores this in respective wordlist files. These wordlists can then be used for directory/dns/parameter brute-forcing.


## Good to know

- Currently, the following types of data are collected:
  - Paths
  - Subdomains
  - Parameter keys
  - Parameter values
  - Parameter key-value pairs (query)

- Data is only collected from the following parameter types. Parameters from cookies, multipart forms, and XML attributes are ignored.
  - URL
  - Body
  - JSON
  - XML


- Only in-scope data is collected. 
- Only unique entries are stored (per project).
- Either select the entire sitemap, only process the selected endpoints.

## Installation
Inside Burp, go to Extender, select Add, set 'Extension type' to Python, and select the extension file.

## Usage

Go to the 'Target' tab and right-click the sitemap.

<img src="https://user-images.githubusercontent.com/23482322/131515915-43f105e1-7f9f-47c0-b53c-8975eaa1b4d1.png" height="400">


Output can be seen by visiting the extension tab.

<img src="https://user-images.githubusercontent.com/23482322/131701222-d89d33d1-23e2-4ebe-af39-06c51bd34fc3.png" height="350">

The wordlists are written to: `<extension dir>/wordlists/<Burp project name>`.

## Further processing

After creating different wordlists, they can be aggregated:
```
cat wordlists/*/paths.txt | sort | uniq
cat wordlists/*/keys.txt | sort | uniq
cat wordlists/*/values.txt | sort | uniq
cat wordlists/*/queries.txt | sort | uniq
cat wordlists/*/subdomains.txt | sort | uniq
```

At one point, an option for this may be added to the extension.

## A word of warning
The generated wordlists can contain sensitive data such as usernames, password, and tokens. Review the wordlist before launching it against other systems.

