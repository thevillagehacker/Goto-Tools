## **Reconnaissance**

| Tool            | Purpose                                     | GitHub                                                                       |
| --------------- | ------------------------------------------- | ---------------------------------------------------------------------------- |
| **Amass**       | Subdomain enumeration, DNS mapping          | [@OWASP/Amass](https://github.com/owasp/amass)                               |
| **Subfinder**   | Passive subdomain enumeration               | [@projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| **Assetfinder** | Subdomain discovery via APIs                | [@tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder)           |
| **httpx**       | Probing live hosts, HTTP metadata           | [@projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)         |
| **nmap**        | Network mapper and scanner                  | [@nmap/nmap](https://github.com/nmap/nmap)                                   |
| **dnsx**        | DNS resolver and bruteforcer                | [@projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx)           |
| **gau**         | Collect URLs from Wayback, AlienVault, etc. | [@lc/gau](https://github.com/lc/gau)                                         |
| **waybackurls** | Extract URLs from Wayback Machine           | [@tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls)           |
### Amass
**Basic Usage**
```sh
amass enum -d example.com
```
**Passive Only**
```sh
amass enum -passive -d example.com
```
**Output to file**
```sh
amass enum -d example.com -o subdomains.txt
```
### Subfinder
**Basic Usage**
```sh
subfinder -d example.com
```
**Use with configuration**
```sh
subfinder -d example.com -config ~/.config/subfinder/config.yaml
```
### Assetfinder
**Basic Usage**
```sh
assetfinder --subs-only example.com
```
### HTTPX
**Basic Usage**
```sh
cat subdomains.txt | httpx
```
**Probe with status code, title, content length**
```sh
cat subdomains.txt | httpx -sc -title -content-length -td -o output.txt
```
- -sc = status code
- -title = title of the application page
- -content-length = content length of the web page file
- -td = tech detect
- -o = output the results
### DNSX
```sh
cat subs.txt | dnsx -a -aaaa -cname -resp-only
```
### GAU
```sh
gau example.com > urls.txt
```
### Waybackurls
```sh
echo example.com | waybackurls > wayback.txt
```
## **Content Discovery / Enumeration**

| Tool            | Purpose                               | GitHub                                                           |
| --------------- | ------------------------------------- | ---------------------------------------------------------------- |
| **ffuf**        | Fast web fuzzer for content discovery | [@ffuf/ffuf](https://github.com/ffuf/ffuf)                       |
| **dirsearch**   | Brute-force directories and files     | [@maurosoria/dirsearch](https://github.com/maurosoria/dirsearch) |
| **feroxbuster** | Recursive content discovery           | [@epi052/feroxbuster](https://github.com/epi052/feroxbuster)     |
| **Arjun**       | Parameter discovery (GET/POST)        | [@s0md3v/Arjun](https://github.com/s0md3v/Arjun)                 |
### FFUF
**Basic Usage**
```sh
ffuf -u https://example.com/FUZZ -w /path/to/wordlist.txt
```
**Extension Brute force**
```sh
ffuf -u https://example.com/FUZZ -w common.txt -e .php,.html,.bak
```
### Dirsearch
```sh
python3 dirsearch.py -u https://example.com -e php,html -x 403,404
```
- -x = filter to exclude the requests with status code 403 and 404
- -e - extensions to search for
### Arjun
```sh
python3 arjun.py -u https://example.com/page.php
```
## **Vulnerability Scanners**

|Tool|Purpose|GitHub|
|---|---|---|
|**Nuclei**|Customizable vulnerability scanner|[@projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)|
|**Nikto**|Web server vulnerability scanner|[@sullo/nikto](https://github.com/sullo/nikto)|
|**dalfox**|XSS scanning & payload generation|[@hahwul/dalfox](https://github.com/hahwul/dalfox)|
|**XSStrike**|Advanced XSS detection|[@s0md3v/XSStrike](https://github.com/s0md3v/XSStrike)|
|**SQLMap**|Automated SQLi detection and exploitation|[@sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)|
|**CRLFuzz**|CRLF injection scanner|[@dwisiswant0/crlfuzz](https://github.com/dwisiswant0/crlfuzz)|
### Nuclei
**CVE Scan**
```sh
echo https://example.com | nuclei -t cves/ -o results.txt
```
**Full Scan by severity**
```sh
nuclei -l urls.txt -severity high,critical -o vulns.txt
```
**Full Scan with all the available templates**
```sh
nuclei -l urls.txt -t nuclei-templates/ -o vulns.txt
```
### Nikto
```sh
perl nikto.pl -h https://example.com
```
### Dalfox
**Basic Usage**
```sh
dalfox url https://example.com/page?param=val
```
**File Input**
```sh
dalfox file urls.txt
```
### XSStrike
```sh
python3 xsstrike.py -u "https://example.com/page?query="
```
### SQLMap
```sh
sqlmap -u "https://example.com/item.php?id=1" --batch --dbs --risk <1to3> --level <1to5> --random-agent --tamper=between,spacetocomment --dbms=<DB Name/type>
```
### CRLFuzz
```sh
echo "https://example.com" | crlfuzz -o crlf-results.txt
```
## **API-Specific Testing**

|Tool|Purpose|GitHub|
|---|---|---|
|**Kiterunner**|API endpoint bruteforcing via OpenAPI & wordlists|[@assetnote/kiterunner](https://github.com/assetnote/kiterunner)|
|**APICheck**|Full-featured API testing toolkit|[@dangertux/apicheck](https://github.com/dangertux/apicheck)|
|**OpenAPI Security Scanner**|Test Swagger/OpenAPI files for vulns|[@emmanouilgast/openapi-security-scan](https://github.com/emmanouilgast/openapi-security-scan)|
|**bypass-403**|Directory bypass testing|[@iamj0ker/bypass-403](https://github.com/iamj0ker/bypass-403)|
### Kiterunner
```sh
kr scan -u https://api.example.com -w routes-large.kite
```

> Use the same tools as web application, configure proxy and test the APIs specific to the workflows, business logics, cryptographic features, etc.
## **Exploitation Tools**

|Tool|Purpose|GitHub|
|---|---|---|
|**Commix**|Command Injection Exploitation|[@commixproject/commix](https://github.com/commixproject/commix)|
|**NoSQLMap**|NoSQL Injection detection|[@codingo/NoSQLMap](https://github.com/codingo/NoSQLMap)|
|**jwt_tool**|JWT attack automation|[@ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)|
|**paramspider**|Scrape parameters from URLs|[@devanshbatham/paramspider](https://github.com/devanshbatham/paramspider)|
### Commix
```sh
python3 commix.py --url="http://example.com/index.php?input=INJECT_HERE"
```
### JWT Tool
```sh
python3 jwt_tool.py <token>
```
### Paramspider
```sh
python3 paramspider.py --domain example.com
```
## **Authentication / JWT / Access Control**

|Tool|Purpose|GitHub|
|---|---|---|
|**JWT Cracker**|Brute-force weak secrets|[@brendan-rius/jwt-cracker](https://github.com/brendan-rius/jwt-cracker)|
|**Corsy**|Detect misconfigured CORS|[@s0md3v/Corsy](https://github.com/s0md3v/Corsy)|
|**Autorize**|Test IDOR and privilege issues|[@qeeqbox/autorize](https://github.com/qeeqbox/autorize)|
### JWT Cracker
```sh
python jwt-cracker.py <token> -w wordlist.txt
```
### CORSy
```sh
python3 corsy.py -u https://example.com
```
## **Wordlists & Payloads**

|Tool|Purpose|GitHub|
|---|---|---|
|**SecLists**|Massive wordlists (dirs, params, APIs, etc.)|[@danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)|
|**PayloadsAllTheThings**|Curated attack payloads|[@swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)|
## Burp Suite Extensions - [Bapp Store](https://portswigger.net/bappstore)
### [Authorize](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f)
- **Use**: Test for IDOR/Broken Access Control in Burp
- **Install**: Burp Extension Store    
- **Usage**:
    - Intercept request with admin token    
    - Autorize replays with low-priv token and logs bypasses
### [ATOR (Automatic Token Obtain and Replace)](https://portswigger.net/bappstore/51327b097b354243b307b4ed87ba39eb)


### [JSMiner](https://portswigger.net/bappstore/0ab7a94d8e11449daaf0fb387431225b)


### [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)



### [Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988)


### [JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)


### [Retire JS](https://portswigger.net/bappstore/36238b534a78494db9bf2d03f112265c)


### [Active Scan++](https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1acc4976)


### [JSON Web Tokens](https://portswigger.net/bappstore/f923cbf91698420890354c1d8958fee6)


### [Logger++](https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81)



### [403 Bypass](https://portswigger.net/bappstore/444407b96d9c4de0adb7aed89e826122)



### [JS Link Finder](https://portswigger.net/bappstore/0e61c786db0c4ac787a08c4516d52ccf)


### [InQL - GraphQL Scanner](https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f)


### [HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)


#### [Smuggler](https://github.com/defparam/smuggler)
## Example Usage
**Single Host:**
```
python3 smuggler.py -u <URL>
```
**List of hosts:**
```
cat list_of_hosts.txt | python3 smuggler.py
```
### [IIS Tilde Enumeration](https://portswigger.net/bappstore/523ae48da61745aaa520ef689e75033b)

