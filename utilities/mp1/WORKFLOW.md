## Quickstart

### Background

First, we need to understand the general infrastructure layout and attack.

#### Infrastructure

* `c2`: attackers command and control server
* `dc`: domain network controller, used to find CFO's workstation
* `hrmanager` (`h1`): the workstation with the initial breach
* `bankfileserver`: look for targets, one of which is the CFO's workstation
* `cfo` (`h3`): the CFO's workstation to initiate bank transfers

#### Step 1 - Initial Breach

* The scenario begins with an initial breach, where a legitimate user opens a Word document and clicks on an embedded OLE object, causing an encoded Visual Basic script contained within the object to execute.
* On execution, this script decodes and writes two files to disk, `starter.vbs` and `TransBaseOdbcDriver.js`. 
* The script then executes `starter.vbs`, which in turn executes `TransBaseOdbcDriver.js`. `TransBaseOdbcDriver.js` is a RAT that establishes encrypted command and control with the attacker over HTTP/S (TCP 443).

#### Step 2 - Target Assessment

* The attacker executes several discovery scripts that are part of the RAT, which gather information such as device hostname, username, domain, CPU architecture , and currently running processes. 
* These scripts obtain this information by making `WMI queries` and querying `ActiveX` networking attributes.
* The attacker then uploads and executes a PowerShell script, which takes a screenshot of the user's desktop and writes the screenshot to disk. 
* The attacker then downloads the resulting screenshot over the existing C2 channel, and prepares a handler for the next C2 callback they will receive.

#### Step 3 - Deploy Toolkit

* The attacker prepares and deploys a second stage RAT on the victim. 
* First, they write obfuscated shellcode to the Windows Registry using `reg.exe`. 
* The attacker then uploads to disk and executes a PowerShell script called `LanCradDriver.ps1`. 
* This script reads the shellcode from the registry, decodes and decrypts it, and then finally injects the shellcode into the current PowerShell process, executing it via a call to CreateThread. 
* After execution, the attacker receives a callback over TCP port 8080.

#### Step 4 - Escalate Privileges

In this step, the attacker performs additional discovery before elevating privileges using a UAC bypass to dump credentials.

* First, they examine local files in <domain_admin>'s home directory. 
* The attacker then calls the Get-NetComputer function from the PowerView library, which queries Active Directory objects to return a list of hostnames in the current domain. 
* The attacker then executes Find-LocalAdminAccess, also from PowerView, to confirm that the attacker has administrator access on the current workstation.
* With this knowledge, the attacker uploads two files to perform credential dumping: `rad353F7.ps1` (UAC bypass) and `smrs.ex`e` (customized Mimikatz, called ATTACKKatz in this repository). 
* The attacker executes `rad353F7.ps1` via PowerShell, which in turn executes `smrs.exe` in high integrity. `smrs.exe` dumps plaintext credentials for the current user.


#### Step 5 - Expand Access

* The attacker uploads several tools to prepare for lateral movement, after which they use `plink.exe` to SSH into bankfileserver, where they list running processes and browse local files. 
  * The contents of two files they discover provide them with information needed to target the CFO's computer.
* They then execute nslookup to get the domain controller's IP address.
* With knowledge of the DC IP address, the attacker uses `PsExec.py`, providing a password hash for authentication, to gain a shell on the DC. 
* They then upload and execute a second stage payload, `Tiny.exe`, over this SMB channel to receive a more powerful shell.

#### Step 6 - Target Discovery

The attacker begins targeting the CFO user from the domain controller. 

* First, they execute Get-AdComputer from memory to get detailed information about the CFO user's computer, learning their username.
* The attacker then executes Get-NetUser from the PowerView library to gather information about the user.
* From bankdc, attacker gathers information about the cfo (CFO's computer) and CFO's user account.

#### Step 7 - Setup Persistence

... 

This is where the attack "starts" for the CFO station, which appears to be `h3`.

https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/carbanak/Emulation_Plan/Scenario_1/README.md#step-7---setup-persistence

...

### Where to begin with the H3 Attack?

So we basically need to recreate "Step 7 - Setup Persistence"...

The attack on h3, "starts" when the attackers move laterally from the Domain Network Controller to H3 using a reverse ssh connection:

```
Using the information gained in "Step 6 - Target Discovery", the attacker laterally moves to the CFO workstation. They upload plink.exe to the domain controller, and use it to setup a reverse SSH tunnel to the attacker platform. he attacker then connects to the DC through this SSH tunnel using RDP.
```

Adam Bates was labeling the the DNC reverse ssh tunnel as the "root cause", but I think this only captures when the attackers connected to the domain network controller (DNC or DC), not CFO's workstation (H3). 

*I think somethings amiss with the ground truth's machine column.*

It might be simpler to choose the label the "root cause" when the attacker RDPs from the domain network controller (DNC or DC) to the CFO's work station (H3):

```
Once on the DC, they execute qwinsta to confirm that the CFO user is not logged into their machine, after which they RDP into the CFO workstation using domain admin credentials. Lastly, the attacker establishes persistence on the CFO workstation by downloading a reverse shell, writing a starter file, and then adding a Registry Run Key to automatically execute the starter file.
```

Turns out that the `qwinsta` command on a domain controller allows you to view information about Remote Desktop Services sessions such as details about active and inactive Remote Desktop sessions on the domain controller including session IDs, usernames, session states, etc -- perfect for seeing who is currently logged in remotely to the domain controller.

The basic syntax is: `qwinsta [/server:servername]`

*The `Carbanak Attack Log.xlsx` probably has a typo where `Ran qeinsta /server:h3` should be `Ran qwinsta /server:h3`.*

Nevertheless, there's no IP addresses making it much more difficult to label a root cause. Fortunately, Adam Bates posted the IP addresses on Piazza:

```
Carbanak IP addresses:

dc: 130.126.136.46
fs: 130.126.136.248
h1: 10.195.75.103
h2: 10.192.101.45
h3: 10.195.78.253
h4: 10.192.90.48
```

So Adam Bates gave us this root cause:
```
110.195.179.70:22
```

However, I'm thinking some potential root causes are:

```
# Any incoming RDP connections
130.126.136.46:3389

# Basically trace through processes involved when receiving an RDP connection

# 1. Local Security Authority Subsystem Service - Handles the authentication process when the RDP client attempts to log in.
lsass.exe

# 2. Manages the logon process after authentication is successful.
winlogon.exe

# 3. Client Server Runtime Subsystem - Involved in creating the new user session.
csrss.exe

# 4. Starts services required for the RDP session.
services.exe

# 5. Launches the Windows shell for the remote user's session
explorer.exe

# 6. Manages clipboard functionality between the local and remote machines.
rdpclip.exe

# 7. Desktop Window Manager - Handles the compositing of the Windows desktop for the remote session.
dwm.exe

# 8. Displays the login user interface if network-level authentication is not used.
LogonUI.exe

# 9. A key component loaded by svchost.exe that implements much of the RDP server functionality.
termsrv.dll
```

Of all the potential root causes, the rdpclip.exe seems most promising

#### IF THE DUMPED VERTICES (mp1/h3_attack.csv) EXIST:

```shell
# 0. Main working directory
cd utilities

# 1. Manually update attack labels (root_cause, impact, benign) in mp1/h3_attack.csv

# 2. Run the trace thingy
python igraph-to-viz.py mp1/h3_attack.pickle.xz
python igraph-to-viz.py mp1/h3_attack_filtered.pickle.xz
```

#### ELSE IF STARTING FRESH:

```shell
# 0. Main working directory
cd utilities

# [Optional] Dump edges
python dump_edges.py mp1/h3_attack.pickle.xz > mp1/h3_attack_edges

# 1. Dump vertices (this will RESET attack labels)
python dump_vertices.py mp1/h3_attack.pickle.xz > mp1/h3_attack.csv

# 2. [Skip because not yet implemented] Pollinate
# python pollinate.py mp1/h3_attack.pickle.xz

# 3. Visualize
python igraph-to-viz.py mp1/h3_attack.pickle.xz


# Filtering the graph to a certain time window breaks things:
#
# python filter.py mp1/h3_attack.pickle.xz
# python dump_vertices.py mp1/h3_attack_filtered.pickle.xz > mp1/h3_attack_filtered.csv
# python igraph-to-viz.py mp1/h3_attack_filtered.pickle.xz
```

### Adam Bate's Lab Demo Logs September 26, 2024

Here's the logs from Adam Bate's lab demo September 26, 2024:

>[docs/console1.rtf](docs/console1.rtf) \
>[docs/console2.rtf](docs/console2.rtf)
