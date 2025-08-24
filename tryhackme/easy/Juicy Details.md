*A popular juice shop has been breached! Analyze the logs to see what had happened...*

**Difficulty:** Easy

You were hired as a SOC Analyst for one of the biggest Juice Shops in the world and an attacker has made their way into your network. 

Your tasks are:

- Figure out what techniques and tools the attacker used
- What endpoints were vulnerable
- What sensitive data was accessed and stolen from the environment

---
## Reconnaissance

Analyze the provided log files. Look carefully at:

- What tools the attacker used
- What endpoints the attacker tried to exploit
- What endpoints were vulnerable
#### Questions

**What tools did the attacker use? (Order by the occurrence in the log)**  
**Hint:** *Look at access.log. User-Agent headers are helpful*

Looking through `access.log` and the provided hint, I noticed the User-Agent field contained common recon tools like Nmap. I did some research on how to extract the segment of each log entry containing the User-Agent.

The command `awk -F\" '{print $(NF-1)}' access.log | uniq`, tells`awk` to split each line into fields at the `"` character and print the 2nd to last field. Although the User-Agent appears to be the last part of leach log entry, `awk` will create a blank field due to a space after the User-Agent. Limiting this output to only unique User-Agents showed me 5 different tools used by the attacker.

$ `awk -F\" '{print $(NF-1)}' access.log | uniq`

```
Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Mozilla/5.0 (Hydra)
Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
sqlmap/1.5.2#stable (http://sqlmap.org)
Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
curl/7.74.0
feroxbuster/2.2.1
Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
```

**What endpoint was vulnerable to a brute-force attack?**

Hydra is used for conducting brute force attacks. I used a similar command to get unique endpoint paths of each log containing "Hydra" in the User-Agent. This returned GET and POST requests to a single endpoint.

$ `cat access.log | grep "Hydra" | awk -F\" '{print $(NF - 5)}' | sort | uniq`

```
GET /rest/user/login HTTP/1.0
POST /rest/user/login HTTP/1.0
```

**What endpoint was vulnerable to SQL injection?**

Sqlmap is used to automate the process of performing SQL injection on vulnerable endpoints. I used a similar command, replacing "Hydra" with "sqlmap" and found attempts to exploit the endpoint: `/rest/products/search`

$ `cat access.log | grep "sqlmap" | awk -F\" '{print $(NF - 5)}' | sort | uniq`

```
GET /rest/products/search?q=1%3BSELECT%20DBMS_PIPE.RECEIVE_MESSAGE%28CHR%28110%29%7C%7CCHR%2869%29%7C%7CCHR%28113%29%7C%7CCHR%2872%29%2C5%29%20FROM%20DUAL-- HTTP/1.1
GET /rest/products/search?q=1%3BSELECT%20PG_SLEEP%285%29-- HTTP/1.1
GET /rest/products/search?q=1%3BWAITFOR%20DELAY%20%270%3A0%3A5%27-- HTTP/1.1
GET /rest/products/search?q=1.9xqhL HTTP/1.1
```

**What parameter was used for the SQL injection?**

From the requests returnedt, we can see portions of SQL queries injected into the "q" parameter.

`GET /rest/products/search?q=81%29%3BSELECT%20DBMS_PIPE.RECEIVE_MESSAGE%28CHR%28110%29%7C%7CCHR%2869%29%7C%7CCHR%28113%29%7C%7CCHR%2872%29%2C5%29%20FROM%20DUAL-- HTTP/1.1`

**What endpoint did the attacker try to use to retrieve files? (Include the /)**

I first thought to search for uses of curl, but that appeared to be only used in a SQL injection attempt. I looked at the unfiltered list of endpoints in `access.log` and noticed the below entries:

```
GET /ftp HTTP/1.1
GET /ftp/www-data.bak HTTP/1.1
```

Looking at the full entries to the `/ftp` endpoint, it shows a few specific files that were attempted to be accessed, one using feroxbuster, which automates web directory enumeration and file access.

$ `cat access.log | grep "ftp"`

```                               
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /ftp HTTP/1.1" 200 4852 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:40 +0000] "GET /ftp/www-data.bak HTTP/1.1" 403 300 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:43 +0000] "GET /ftp/coupons_2013.md.bak HTTP/1.1" 403 78965 "-" ""Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

---
## Stolen Data

Analyze the provided log files. Look carefully at:  

- The attacker's movement on the website
- Response codes
- Abnormal query strings
#### Questions

**What section of the website did the attacker use to scrape user email addresses?**
**Hint:** Where can customers usually comment on a shopping website?

I figured out this question after answering the following one, so I had the time the brute force attack was successful, meaning the attacker likely already had an email address they were trying to use to login. I looked at entries of `access.log` before that time and saw a lot of requests to product reviews, which made sense with the given hint that a user's email address might be shown on a product review. The command below can be used to see these log entries.

$ `cat access.log | grep "reviews"`

**Was their brute-force attack successful? If so, what is the timestamp of the successful login? (Yay/Nay, 11/Apr/2021:09:xx:xx +0000)**

I filtered `access.log` to show requests to the login page that were successful with a return code of 200. A couple were returned, but only one with the use of Hydra, which fit for this question asking about a successful brute force attack.

$ `cat access.log | grep "login" | grep "200"`

```
::ffff:192.168.10.5 - - [11/Apr/2021:09:15:03 +0000] "POST /rest/user/login HTTP/1.1" 200 857 "http://192.168.10.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:31 +0000] "POST /rest/user/login HTTP/1.0" 200 831 "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:20:43 +0000] "POST /rest/user/login HTTP/1.1" 200 831 "http://192.168.10.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /login HTTP/1.1" 200 1924 "-" "feroxbuster/2.2.1"
```

The specific log entry is below:

`::ffff:192.168.10.5 - - [11/Apr/2021:09:16:31 +0000] "POST /rest/user/login HTTP/1.0" 200 831 "-" "Mozilla/5.0 (Hydra)"`

**What user information was the attacker able to retrieve from the endpoint vulnerable to SQL injection?**

I noticed a section of SQL injection log entries in `access.log` where the User-Agent switches from a lot of failed requests using sqlmap, to Firefox, to curl.

```
"GET /rest/products/search?q=1%27%29%20ORDER%20BY%201--%20LbNt HTTP/1.1" 500 - "-" "sqlmap/1.5.2#stable (http://sqlmap.org)"

"GET /rest/products/search?q=1%27%20ORDER%20BY%201--%20ivGK HTTP/1.1" 500 - "-" "sqlmap/1.5.2#stable (http://sqlmap.org)"

"GET /rest/products/search?q=%27))%20UNION%20SELECT%20%271%27,%20%272%27,%20%273%27,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200 - "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"

"GET /rest/products/search?q=%27))%20UNION%20SELECT%20%271%27,%20%272%27,%20%273%27,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 304 - "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"

"GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200 - "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"

"GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200 3742 "-" "curl/7.74.0"
```

Researching, I learned this is a common pattern that appears during SQL innjections attacks, where sqlmap automation will discover a specific "UNION" SQL query, like in this example and the attacker will confirm this from their browser.

In the below two entries you can see the attacker confirmed an injection method found to work by sqlmap and then alters the query to retrieve emails and passwords.

```
"GET /rest/products/search?q=%27))%20UNION%20SELECT%20%271%27,%20%272%27,%20%273%27,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 304 - "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"

"GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200 - "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

After these the User-Agent changes, showing the final retrieval of emails and passwords using curl.

**What files did they try to download from the vulnerable endpoint? (endpoint from the previous task, question #5)**

We can repeat the command from the previous section to answer this question.

$ `cat access.log | grep "ftp"`

```
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /ftp HTTP/1.1" 200 4852 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:40 +0000] "GET /ftp/www-data.bak HTTP/1.1" 403 300 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:43 +0000] "GET /ftp/coupons_2013.md.bak HTTP/1.1" 403 78965 "-" ""Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

**What service and account name were used to retrieve files from the previous question? (service, username)**

In `vsftpd.log`, right before the two files are downloaded using FTP, the anonymous account is logged into.

```
Sun Apr 11 09:35:37 2021 [pid 8152] [ftp] OK LOGIN: Client "::ffff:192.168.10.5", anon password "?"
Sun Apr 11 09:35:45 2021 [pid 8154] [ftp] OK DOWNLOAD: Client "::ffff:192.168.10.5", "/www-data.bak", 2602 bytes, 544.81Kbyte/sec
Sun Apr 11 09:36:08 2021 [pid 8154] [ftp] OK DOWNLOAD: Client "::ffff:192.168.10.5", "/coupons_2013.md.bak", 131 bytes, 3.01Kbyte/sec  
```

**What service and username were used to gain shell access to the server? (service, username)**

Looking in `auth.log`, there are a lot of authentication errors for the user `www-data`, but eventually are followed by an "Accepted password for www-data" entry and one saying a session was spawned for the same user. The logs also show "sshd:session", meaning the service used to get a shell was SSH.

```
Apr 11 09:41:19 thunt sshd[8260]: Accepted password for www-data from 192.168.10.5 port 40112 ssh2
Apr 11 09:41:19 thunt sshd[8260]: pam_unix(sshd:session): session opened for user www-data by (uid=0) Apr 11 09:41:19 thunt systemd-logind[737]: New session 12 of user www-data.
```
