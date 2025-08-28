*Investigate lateral movement, credential theft, and additional adversary actions in a memory dump.*

**Difficulty:** Medium

### Prerequisites

- [Windows Memory & Processes](https://tryhackme.com/room/windowsmemoryandprocs)
- [Windows Memory & User Activity](https://tryhackme.com/room/windowsmemoryanduseractivity)
- [Windows Memory & Network](https://tryhackme.com/room/windowsmemoryandnetwork)

### Scenario

```
During the [initial stages of the investigation](https://tryhackme.com/room/windowsmemoryandprocs), it was confirmed that the TryHatMe CEO's host WIN-001 was compromised. The attacker successfully obtained credentials belonging to Cain Omoore, a Domain IT Administrators group member who remotely helped the CEO with the endpoint configuration and cached his credentials on the host.  
  
Given the privileges associated with Cain's account, the internal security team suspects that the attacker laterally moved to other systems within the environment or even to Cain's host - WIN-015.  
  
Since Cain stores access keys to the TryHatMe factory control system on his WIN-015, your first priority is to investigate his host for any lateral movement or data exfiltration traces. For this, you have been provided with a memory dump of WIN-015. Good luck!
```

### Hosts

`WIN-001`
- Belongs to CEO
- Confirmed to the compromised
- Contained cached credentials for `WIN-015`
`WIN-015`
- 192.168.1.195
- Belongs to Cain Omoore
- In Domain IT Administrators group

### Lateral Movement

**The IR team suspects that the threat actor may have performed lateral movement to this host. Which executed process provides evidence of this activity?**

I searched `pstree.txt` for files relevant to the lateral movement techniques discussed in this section: `psexesvc.exe`, `wmiprvse.exe` and `wsmprovhost.exe` and found evidence of `wmiprvse.exe` in the process tree.

analyst@tryhackme:~/memory/WIN-015$ `cat precooked/pstree.txt | grep wmiprvse.exe`

```
*** 2376        748     WmiPrvSE.exe    0x9e8753fef080  6       -       0     False    2025-05-22 11:12:28.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\wbem\WmiPrvSE.exe     C:\Windows\system32\wbem\wmiprvse.exe   C:\Windows\system32\wbem\wmiprvse.exe
```

**What is the MITRE technique ID associated with the lateral movement method used by the threat actor?**

I researched the use of `wmiprvse.exe` and found that it can be used for remote administration on Windows systems. I browsed the various MITRE ATT&CK Lateral Movement techniques and subtechniques. T1021.006 (**Remote Services: Windows Remote Management**) matches this description.

[T1021.006](https://attack.mitre.org/techniques/T1021/006/)

**Which other process was executed as part of the lateral movement activity to this host?**

By searching pstree for the PID of `wmiprse.exe` I was able to find "TeamsView.exe" spawned from it. Then with the PID of "TeamsView.exe" I was able construct a full, easy to view process tree.

```
analyst@tryhackme:~/memory/WIN-015$ cat precooked/pstree.txt | grep 2376
analyst@tryhackme:~/memory/WIN-015$ cat precooked/pstree.txt | grep 1672
```

```
PID         PPID     ImageFileName
* 600       460      services.exe
** 748      600        svchost.exe
*** 2376    748          wmiprvse.exe
**** 1672   2376           TeamsView.exe 
***** 6080  1672             systeminfo.exe
***** 7140  1672             ipconfig.exe
***** 7684  1672             whoami.exe
```

**What is the Security Identifier (SID) of the user account under which the process was executed on this host?**

With some research, I found the Volatility plugin "getsids" will extract an account's SID from a process. I created a files ssids.txt from this output and searched for "TeamsView", which returned cain.omoore's SID.

analyst@tryhackme:~/memory/WIN-015$ `vol -f WIN-015-20250522-111717.dmp windows.getsids > ssids.txt`

analyst@tryhackme:~/memory/WIN-015$ `cat ssids.txt | grep TeamsView`

```
1672    TeamsView.exe   S-1-5-21-3147497877-3647478928-1701467185-1008  cain.omoore
```

**What is the name of the domain-related security group the user account was a member of?**

I researched that the `getsids` Volatility plugin is getting the security token associated with a process, which contains the user SID and group SID that the account belongs too. Both of these showing up by searching for "TeamsView.exe" shows that cain.omoore was part of Domain Users.

```
1672    TeamsView.exe   S-1-5-21-3147497877-3647478928-1701467185-513   Domain Users
1672    TeamsView.exe   S-1-5-21-3147497877-3647478928-1701467185-1008  cain.omoore
```

**Which processes related to discovery activity were executed by the threat actor on this host? Format: In alphabetical order**

From the process tree already established, we know the processes spawned from TeamsView.exe all are related to discovery: `systeminfo.exe`, `ipconfig.exe`, `whoami.exe`. Searching the getsids file for cain.omoore's SID confirms they were all executed by this SID.

analyst@tryhackme:~/memory/WIN-015$ `cat ssids.txt | grep "S-1-5-21-3147497877-3647478928-1701467185-1008"`

```
4684    whoami.exe      S-1-5-21-3147497877-3647478928-1701467185-1008  cain.omoore
6080    systeminfo.exe  S-1-5-21-3147497877-3647478928-1701467185-1008  cain.omoore
7140    ipconfig.exe    S-1-5-21-3147497877-3647478928-1701467185-1008  cain.omoore
```

**What is the Command and Control IP address that the threat actor connected to from this host as a result of the previously executed actions? Format: IP Address:Port**

Searching `netscan.txt` for "TeamsView",  we can see the foreign address and port of the connection created by this executable are **32.244.169.133** and **1995**.

analyst@tryhackme:~/memory/WIN-015$ `cat precooked/netscan.txt | grep "TeamsView"`

```
0x9e875b6c8b80  TCPv4   192.168.1.195   49726   34.244.169.133  1995    ESTABLISHED    1672    TeamsView.exe   2025-05-22 11:14:56.000000 UTC
```

### Privilege Escalation and Credential Dumping

**Conduct a deeper investigation and identify another suspicious process on the host. Provide a full path to the process in your answer.**

analyst@tryhackme:~/memory/WIN-015$ `cat precooked/pstree.txt | grep pan.exe`

```
* 4840  3552    pan.exe 0x9e875aff1080  1       -       0       False   2025-05-22 11:15:37.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\Temp\pan.exe   C:\Windows\Temp\pan.exe privilege::debug sekurlsa::logonpasswords        C:\Windows\Temp\pan.exe
```

I discovered this process `pan.exe` by looking at `cmdline.txt`. I noticed this command has to do with privilege and that it was suspiciously placed in the Temp directory. I then checked pstree and saw it was spawned by `cmd.exe`. A method I will use in the future is searching pstree for "Temp" as malicious files are often placed there.

**Which account was used to execute this malicious process?**

analyst@tryhackme:~/memory/WIN-015$ `cat ssids.txt | grep 4840`

```
4840    pan.exe S-1-5-18        Local System
```

Local System is equivalent to `NT AUTHORITY\SYSTEM`, the highest privilege on a Windows host.

**What was the malicious command line executed by the process?**

analyst@tryhackme:~/memory/WIN-015$ `cat precooked/cmdline.txt | grep pan.exe`

```
4840    pan.exe C:\Windows\Temp\pan.exe privilege::debug sekurlsa::logonpasswords
```

**Given the command line from the previous question, which well-known hacker tool is most likely the malicious process?**

Googling the section of the command "privilege::debug", I found docs showing this is used in Mimikatz. The other part of the command is used to dump credentials: `sekurlsa::logonpasswords`

[The Hacker Tools](https://tools.thehacker.recipes/mimikatz/modules/privilege/debug)

**Which MITRE ATT&CK technique ID corresponds to the method the attacker employed to evade detection, as identified in the previous steps?**

[T1036 - Masquerading](https://attack.mitre.org/techniques/T1036)

The attacker disguised Mimikatz as an executable that might've been overlooked, calling it "pan.exe" to avoid suspison and detection by security tools.