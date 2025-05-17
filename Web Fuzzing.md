whatweb caca.htb

nuclei -u google.com

JDumpspider
```
java -jar JDumpSpider-1.1-SNAPSHOT-full.jar <nombredelheapdump>
```
si nuclei detecta que puedes descargar heapdump

directorios
```shell-session
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://IP:PORT/FUZZ
```

archivos
```shell-session
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://IP:PORT/FUZZ.html -e .php,.html,.txt,.bak,.js -v 
```

recursive fuzzing
```shell-session
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://IP:PORT/FUZZ -e .html -recursion
```
```shell-session
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://IP:PORT/FUZZ -e .html -recursion -recursion-depth 2 -rate 500
```

parameter & value fuzzing GET
```shell-session
curl http://IP:PORT/get.php
```
```shell-session
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://IP:PORT/get.php?<parametro>=FUZZ"
```

POST
```shell-session
curl -d "" http://IP:PORT/post.php
```
```shell-session
ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "<parametro>=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v
```

virtual host fuzzing
```shell-session
gobuster vhost -u http://inlanefreight.htb:80 -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain
```

subdomain fuzzing
```shell-session
gobuster dns -d inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

filtering outputs

GOBUSTER 
modo dir
-s (incluir) para buscar redirects -s 301,302,207
-b (excluir) -b 404
--exclude-length 0,404

```shell-session
# Find directories with status codes 200 or 301, but exclude responses with a size of 0 (empty responses)

pstrn@htb[/htb]$ gobuster dir -u http://example.com/ -w wordlist.txt -s 200,301 --exclude-length 0
```

FFUF 
-mc (match code ) -mc 200
-fc (filter code ) -fc 404
-fs (filter size) -fs 100-200 excluye respuestas de 100 a 200 bytes
-ms (match size) -ms 23,50-100 incluye respustas de 23 bytes y de 50 a 100 bytes
-fw (filter out number of words in response) -fw 219
-mw (match words ) -mw 5 
-fl (filter lines)
-ml (match lines)
-mt (match time) time to fisrt byte (milisegundos) -mc >500

```shell-session
# Find directories with status code 200, based on the amount of words, and a response size greater than 500 bytes
pstrn@htb[/htb]$ ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200 -fw 427 -ms >500

# Filter out responses with status codes 404, 401, and 302
pstrn@htb[/htb]$ ffuf -u http://example.com/FUZZ -w wordlist.txt -fc 404,401,302

# Find backup files with the .bak extension and size between 10KB and 100KB
pstrn@htb[/htb]$ ffuf -u http://example.com/FUZZ.bak -w wordlist.txt -fs 0-10239 -ms 10240-102400

# Discover endpoints that take longer than 500ms to respond
pstrn@htb[/htb]$ ffuf -u http://example.com/FUZZ -w wordlist.txt -mt >500
```

WENUM
`--hc` (hide code)
`--sc` (show code)
`--hl` (hide length)
`--sl` (show length)
`--hw` (hide word)
`--sw` (show word)
`--hs` (hide size)
`--ss` (show size)
`--hr` (hide regex)|Exclude responses whose body matches the specified regular expression.|Filter out responses containing the "Internal Server Error" message. Use `--hr "Internal Server Error"`.
`--sr` (show regex)|Include only responses whose body matches the specified regular expression.Filter for responses containing the string "admin" using `--sr "admin"`.
|`--filter`/`--hard-filter`General-purpose filter to show/hide responses or prevent their post-processing using a regular expression.`--filter "Login"` will show only responses containing "Login", while `--hard-filter "Login"` will hide them and prevent any plugins from processing them.

FEROXBUSTER
--dont-scan /images
-S  o  --filter-size -S 1024 no muestra pag de 1 KB
-X  o  --filter-regex  -X "error"
-W  o  --filter-words   -W 0-10
-N  o --filter-lines   -N 50-  no muestra contenido con mas de 50 lineas
-C  o --filter-status  -C 404
`--filter-similar-to error.html`
-s --status-codes -s 200 mustra pag con codigos
```shell-session
# Find directories with status code 200, excluding responses larger than 10KB or containing the word "error"
pstrn@htb[/htb]$ feroxbuster --url http://example.com -w wordlist.txt -s 200 -S 10240 -X "error" 
```

verify findings 
```shell-session
curl -I http://IP:PORT/backup/password.txt
```


FEROXBUSTER
```
feroxbuster --url http://caca:80 --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```
tiene profundidad 4 por defecto y encuentra archivos por def
modificar profundidad `--depth`

WEB APIs
A `Web API`, or `Web Application Programming Interface`, is a set of rules and specifications that enable different software applications to communicate over the web. It functions as a universal language, allowing diverse software components to exchange data and services seamlessly, regardless of their underlying technologies or programming languages.

`REST APIs` are a popular architectural style for building web services. They use a stateless, client-server communication model where clients send requests to servers to access or manipulate resources. `REST APIs` utilize standard `HTTP methods` (`GET`, `POST`, `PUT`, `DELETE`) to perform `CRUD` (Create, Read, Update, Delete) operations on resources identified by unique URLs. They typically exchange data in lightweight formats like `JSON` or `XML`, making them easy to integrate with various applications and platforms.
ejemplo:
```http
GET /users/123
```

`SOAP APIs` follow a more formal and standardized protocol for exchanging structured information. They use `XML` to define messages, which are then encapsulated in `SOAP envelopes` and transmitted over network protocols like `HTTP` or `SMTP`. `SOAP APIs` often include built-in security, reliability, and transaction management features, making them suitable for enterprise-level applications requiring strict data integrity and error handling. ejemplo
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
   <soapenv:Header/>
   <soapenv:Body>
      <tem:GetStockPrice>
         <tem:StockName>AAPL</tem:StockName>
      </tem:GetStockPrice>
   </soapenv:Body>
</soapenv:Envelope>
```

`GraphQL` is a relatively new query language and runtime for `APIs`. Unlike `REST APIs`, which expose multiple endpoints for different resources, `GraphQL` provides a single endpoint where clients can request the data they need using a flexible query language. This eliminates the problem of over-fetching or under-fetching data, which is common in `REST APIs`. `GraphQL`'s strong typing and introspection capabilities make it easier to evolve `APIs` over time without breaking existing clients, making it a popular choice for modern web and mobile applications. ejemplo:
```graphql
query {
  user(id: 123) {
    name
    email
  }
}
```

API FUZZING
```shell-session
pstrn@htb[/htb]$ git clone https://github.com/PandaSt0rm/webfuzz_api.git
pstrn@htb[/htb]$ cd webfuzz_api
pstrn@htb[/htb]$ pip3 install -r requirements.txt
```
```shell-session
python3 api_fuzzer.py http://IP:PORT
```
muestra endpoints
tambien se puede hacer con cualquier otro fuzzer si solo seleccionas que se muestre el codigo 405

