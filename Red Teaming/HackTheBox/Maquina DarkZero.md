
## Resumen ejecutivo

Se realizó una evaluación de la máquina _DarkZero_ con el objetivo de identificar vectores de acceso inicial, movimientos laterales y técnicas de escalada dentro de un entorno Active Directory. Durante el ejercicio se encontró un servidor con servicios expuestos (entre ellos Microsoft SQL Server) que permitieron, mediante abuso de una relación de confianza y características de SQL Server, ejecutar código en un controlador de dominio remoto y finalmente obtener credenciales de dominio completas. Este informe resume los hallazgos, explica por qué cada vector funcionó y recoge recomendaciones de mitigación.


# Reconocimiento


Realizamos un escaneo de nmap a los puertos abiertos de la direccion ip 

```bash
Nmap 7.95 scan initiated Wed Jan 21 09:59:30 2026 as: /usr/lib/nmap/nmap --privileged -p53,88,135,139,389,445,464,593,636,1433,2179,3268,3269,5985,9389,49664,49667,49676,49677,49895,49921,63117,63127 -sC -sV -Pn --min-rate 4500 -oN exhaustivo 10.129.6.255
Nmap scan report for 10.129.6.255
Host is up (1.0s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-21 10:00:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
|_ssl-date: 2026-01-21T10:01:59+00:00; +27s from scanner time.
| ms-sql-info: 
|   10.129.6.255:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.6.255:1433: 
|     Target_Name: darkzero
|     NetBIOS_Domain_Name: darkzero
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: darkzero.htb
|     DNS_Computer_Name: DC01.darkzero.htb
|     DNS_Tree_Name: darkzero.htb
|_    Product_Version: 10.0.26100
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-01-21T09:57:17
|_Not valid after:  2056-01-21T09:57:17
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49895/tcp open  msrpc         Microsoft Windows RPC
49921/tcp open  msrpc         Microsoft Windows RPC
63117/tcp open  msrpc         Microsoft Windows RPC
63127/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-21T10:01:24
|_  start_date: N/A
|_clock-skew: mean: 26s, deviation: 0s, median: 26s

```

El escaneo reveló múltiples servicios Microsoft típicos en controladores de dominio y servidores (Kerberos, LDAP/LDAPS, SMB/RPC, MS-SQL, WinRM/HTTP). La presencia de LDAP/LDAPS y Kerberos confirma que se trata de un entorno Active Directory. La exposición del servicio Microsoft SQL Server resulta relevante porque, si está mal configurado, puede permitir que una cuenta con permisos SQL ejecute consultas remotas o acceda a recursos del dominio a través de _linked servers_.

- DNS (53)
- Kerberos (88)
- LDAP/LDAPS (389/636)
- SMB (445)
- WinRM (5985)
- MSSQL (1433)

# Acceso inicial y pivot vía SQL Server

## Acceso inicial a MSSQL

Dado que el puerto **1433 (MSSQL)** estaba expuesto, utilicé las credenciales proporcionadas por la máquina para conectarme al servicio.

Una vez dentro, realicé enumeración básica:

- Bases de datos
- Roles
- Permisos
- Configuración del servidor

![[Pasted image 20260213145533.png]]

No se encontró nada útil inicialmente, por lo que decidí enumerar un componente muy común y peligroso en SQL Server: **Linked Servers**.


## Enumeración de Linked Servers (hallazgo clave)

La enumeración reveló un **linked server** configurado hacia:

![[Pasted image 20260213145642.png]]

La enumeración reveló una relación de confianza entre el servidor comprometido y el controlador de dominio **DC02.darkzero.ext**:

Un _linked server_ en SQL Server permite ejecutar consultas y procedimientos en otro servidor desde el servidor SQL original. Si el linked server está configurado con `rpc_out = TRUE`, el servidor puede invocar procedimientos remotos en el servidor vinculado. En entornos donde el servidor vinculado apunta a un controlador de dominio (o a un host en el dominio de confianza) y la cuenta SQL usa credenciales con privilegios allí, esto abre la posibilidad de ejecutar acciones remotas en el controlador de dominio desde el servidor SQL comprometido.

![[Pasted image 20260213145938.png]]
## Validación de permisos en DC02

Luego de identificar el linked server, el siguiente paso fue verificar qué nivel de acceso tenía en DC02.


![[Pasted image 20260213150419.png]]

## Activación y abuso de `xp_cmdshell`

### ¿Qué es `xp_cmdshell`?

`xp_cmdshell` es una función de SQL Server que permite ejecutar comandos del sistema operativo directamente desde SQL Server.

Esto es peligroso porque, si un atacante logra habilitarlo:

> puede ejecutar comandos como si estuviera dentro del sistema operativo, logrando ejecución remota.

Para poder activarlo fue necesario habilitar primero:

- `show advanced options`

Luego se activó `xp_cmdshell`.

La prueba final fue ejecutar un comando simple como `whoami`, confirmando ejecución remota exitosa dentro de: `DC02.darkzero.ext`

![[Pasted image 20260213150735.png]]

## Obtención de Reverse Shell en DC02

Una vez confirmada la ejecución de comandos, procedí a obtener una sesión interactiva.

El método fue:

1. Generar un payload (reverse shell)
2. Hostearlo desde la máquina atacante usando un servidor HTTP simple
3. Descargarlo desde DC02 usando una herramienta nativa de Windows: **certutil**
4. Ejecutarlo mediante `xp_cmdshell`

![[Pasted image 20260213151219.png]]

Tras ejecutar el payload, recibí una sesión tipo **Meterpreter** desde DC02.

![[Pasted image 20260213151823.png]]

# Escalada de privilegios en DC02

Con una sesión establecida, el siguiente objetivo fue obtener privilegios elevados en el host.

![[Pasted image 20260213152027.png]]

Se realizó enumeración local y se utilizó el módulo:

`post/multi/recon/local_exploit_suggester`

Este módulo sugiere vulnerabilidades locales según:

- Versión de Windows
- Arquitectura
- Parches

![[Pasted image 20260217003648.png]]

Entre los vectores sugeridos, se explotó:

### **CVE-2024-30088**

**Explicación**

El error ocurre cuando el kernel maneja objetos `ACCESS_TOKEN`. Existe una función llamada `AuthzBasepCopyoutInternalSecurityAttributes` que copia atributos de seguridad de un token.

La vulnerabilidad permite que un programa malicioso manipule estos atributos para que el kernel los trate como un tipo de objeto diferente al que realmente son. Esta confusión permite al atacante leer o escribir en memoria del kernel que no debería poder tocar.

**El resultado de esa confusión:**  
Al manipular esa memoria, el atacante puede modificar su propio token de acceso y convertirlo en uno de **SYSTEM**, obteniendo así todos los privilegios.


![[Pasted image 20260217003747.png]]

El exploit fue exitoso y permitió obtener una sesión como:

**NT AUTHORITY\SYSTEM / Administrator**

![[Pasted image 20260217004015.png]]

# Enumeración del dominio y Forest Trust

Aunque ya tenía control sobre **DC02**, el objetivo final era comprometer **DC01.darkzero.htb**.

Luego de enumeración, decidí revisar las relaciones de confianza (trusts) entre dominios usando:

![[Pasted image 20260217004243.png]]

La salida mostró lo más importante del laboratorio:

- Dominio principal: `darkzero.htb`
- Dominio externo: `darkzero.ext`
- Trust: **Forest Trust transitive** y **bidireccional**

### ¿Por qué es importante el "Forest Trust"?

- **Es como un puente de autenticación**: Los usuarios de `darkzero.htb` pueden autenticarse en recursos de `darkzero.ext` y viceversa.
- **Es transitivo**: Si el Dominio A confía en B, y B confía en C, entonces A confía en C (aunque no directamente).
- **Permite el paso de tickets Kerberos**: Los tickets emitidos en un dominio pueden ser válidos (o convertidos) en el otro.

1.  **darkzero.htb** confía en **darkzero.ext** y viceversa. Es una calle de doble sentido. El atributo `foresttrans` indica que probablemente son dos bosques diferentes (por ejemplo, una empresa que compró a otra y unió los directorios con una confianza).
2.  **darkzero.ext** es la raíz de su propio bosque.

# Abuso de Kerberos: Captura de TGT con Rubeus

Con la confianza confirmada, el siguiente paso fue abusar del protocolo Kerberos.

Subí a DC02 las herramientas:

- **Rubeus**
- **Mimikatz**

![[Pasted image 20260217004732.png]]


Herramientas como Rubeus pueden monitorear y capturar tickets Kerberos en memoria o en tránsito cuando se generan peticiones susceptibles de filtrado (por ejemplo forzando a un servicio a solicitar autenticación).

### ¿Qué hace `monitor` en Rubeus?

Permite observar la creación de tickets Kerberos en tiempo real.

Si el host genera autenticación Kerberos (por ejemplo, al acceder a un recurso UNC), Rubeus puede capturar el ticket.

![[Pasted image 20260217004950.png]]

## Forzar autenticación con `xp_dirtree`

Para forzar que DC01 generara una autenticación, utilicé desde MSSQL el procedimiento:

`xp_dirtree`

apuntando hacia un recurso UNC inexistente en DC02:

![[Pasted image 20260217005203.png]]
### ¿Por qué funciona esto?

Cuando Windows intenta listar un recurso UNC:

1. Intenta autenticarse automáticamente vía Kerberos/NTLM
2. Genera tickets o intenta negociación
3. Eso puede ser capturado por herramientas como Rubeus

Esto permitió capturar exitosamente un ticket:


![[Pasted image 20260217005503.png]]

# Pass-The-Ticket (PTT)

Un Ticket-Granting Ticket (TGT) es el ticket que una entidad obtiene para solicitar otros tickets dentro del dominio; si un atacante obtiene un TGT válido de una cuenta de máquina (por ejemplo DC01$), puede "inyectarlo" (pass-the-ticket) en su sesión para actuar con la identidad de esa máquina y solicitar acceso a recursos protegidos.

Una vez capturado el TGT, lo importé en memoria con:

`.\Rubeus.exe ptt /ticket:___ `

![[Pasted image 20260217005654.png]]

Luego verifiqué que el ticket estaba cargado ejecutando el comando `klist`

![[Pasted image 20260217005756.png]]

La presencia del ticket confirmó que ahora mi sesión estaba actuando como:

**DC01$ (cuenta de máquina del Domain Controller)** 

## DCSync y extracción de hashes

DCSync es una técnica que utiliza las APIs de replicación de Active Directory para solicitar los hashes de los usuarios desde un controlador de dominio, exactamente como lo haría un controlador de dominio durante la replicación. Herramientas como Mimikatz pueden simular esta operación si la cuenta que se utiliza tiene los privilegios necesarios (por ejemplo Replicating Directory Changes All o privilegios equivalentes). Si se consigue ejecutar dcsync contra DC01, se pueden extraer hashes de usuarios de dominio (incluyendo Administrator), lo que facilita autenticación con pass-the-hash o la importación de credenciales en otros servicios.

Si una cuenta tiene permisos de replicación, puede solicitar:

- Hashes NTLM
- Kerberos keys
- Credenciales de usuarios (incluyendo Administrator y KRBTGT)

Con el ticket de DC01$ cargado, el siguiente paso fue ejecutar un ataque crítico:

En este caso, se ejecutó Mimikatz y se solicitó replicación para extraer la **base de datos de hashes NT  completa.

![[Pasted image 20260217005847.png]]
Confirmando la extracción exitosa.

# Acceso final a DC01 (Pass-The-Hash)

Con el hash NTLM de Administrator, aproveché que el host tenía abierto:

- **5985 (WinRM)**

Por lo que realicé autenticación mediante **Pass-The-Hash**.

![[Pasted image 20260217010125.png]]

El acceso fue exitoso, obteniendo una sesión administrativa directa en:

**DC01.darkzero.htb**

En este punto la máquina quedó completamente comprometida.

## Conclusión

La máquina **DarkZero** presenta un escenario realista de compromiso total en un entorno **Active Directory**, donde una mala configuración en servicios críticos permite escalar desde un acceso limitado hasta el control absoluto del dominio.

El ataque inició mediante la exposición del servicio **Microsoft SQL Server (MSSQL)**, al cual se pudo acceder con credenciales válidas. A partir de allí, el hallazgo más importante fue la existencia de un **Linked Server** apuntando hacia **DC02.darkzero.ext**, con la opción `rpc_out` habilitada, lo cual permitió ejecutar procedimientos remotos desde SQL Server. Esta configuración, combinada con permisos elevados en el servidor vinculado, facilitó la activación de `xp_cmdshell` y, en consecuencia, la ejecución de comandos directamente en **DC02**, logrando finalmente una **reverse shell** interactiva.

Posteriormente, se realizó una escalada local de privilegios mediante un exploit de **elevación de privilegios** (CVE-2024-30088), obteniendo acceso como administrador/SYSTEM en DC02. Una vez comprometido el controlador de dominio, el foco pasó a la infraestructura del dominio, donde se identificó una relación de confianza **Forest Trust bidireccional y transitiva** entre `darkzero.htb` y `darkzero.ext`.

Aprovechando este trust y el comportamiento de autenticación automática de Windows, se forzó una petición Kerberos mediante `xp_dirtree`, lo cual permitió capturar un **TGT** de la cuenta de máquina **DC01$** utilizando **Rubeus**. Con este ticket importado en memoria (Pass-The-Ticket), fue posible ejecutar **DCSync** con **Mimikatz**, extrayendo hashes críticos del dominio, incluyendo el del usuario **Administrator**. Finalmente, mediante **Pass-The-Hash** sobre **WinRM (5985)** se obtuvo acceso administrativo directo al controlador de dominio principal **DC01.darkzero.htb**, confirmando el compromiso total del dominio.

En conclusión, DarkZero demuestra cómo configuraciones inseguras en SQL Server (Linked Servers + `rpc_out` + `xp_cmdshell`) y una gestión débil de trusts pueden convertir un servidor expuesto en una ruta directa hacia el **control completo del Active Directory**, permitiendo extracción de credenciales, replicación del directorio y acceso total a los recursos del entorno.

# MITRE ATT&CK

| MITRE ID      |                                                                   Técnica (nombre) | Por qué aplica / evidencia                                                                                                                                                                               | Referencia   |
| ------------- | ---------------------------------------------------------------------------------: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| **T1078**     |                                                                     Valid Accounts | Inicio de sesión a MSSQL con credenciales proporcionadas (uso de cuentas válidas para acceder al servicio).                                                                                              | MITRE ATT&CK |
| **T1505.001** |          SQL Stored Procedures (Server Software Component → SQL Stored Procedures) | Abuso de funcionalidades de SQL Server (linked server, habilitación de `xp_cmdshell`, ejecución de comandos vía procedimientos/funciones) — uso de stored procedures / xp_cmdshell para ejecutar código. | MITRE ATT&CK |
| **T1210**     |                                                    Exploitation of Remote Services | Uso del linked server (`rpc_out = TRUE`) para invocar procedimientos remotos y moverse lateralmente hacia DC02 (explotación/post-compromiso de servicios remotos).                                       | MITRE ATT&CK |
| **T1059.003** |                Command and Scripting Interpreter — Windows Command Shell (cmd.exe) | `xp_cmdshell` invoca la shell de Windows (ej. `whoami`, descarga/ejecución de payload vía `certutil` y ejecución de binarios). Esto es abuso de la shell de Windows para ejecución.                      | MITRE ATT&CK |
| **T1218**     |                      Signed Binary Proxy Execution (System Binary Proxy Execution) | Uso de `certutil.exe` (binario legítimo de Windows) para descargar payload desde atacante — proxy execution / living-off-the-land.                                                                       | MITRE ATT&CK |
| **T1482**     |                                                             Domain Trust Discovery | Se ejecuto `nltest /domain_trusts /all_trusts` para identificar la trust forest entre `darkzero.htb` y `darkzero.ext` — descubrimiento de trusts de dominio.                                             | MITRE ATT&CK |
| **T1558**     | Steal or Forge Kerberos Tickets (sub-técnicas: Golden/Silver/Kerberoasting/ccache) | Uso de **Rubeus** para capturar TGT/TGS (monitor y captura de tickets Kerberos). Esto encaja con “steal/forge Kerberos tickets”.                                                                         | MITRE ATT&CK |
| **T1550.003** |                            Use Alternate Authentication Material — Pass the Ticket | Importación del TGT con `Rubeus ptt` y verificación con `klist` → Pass-The-Ticket para actuar como `DC01$`.                                                                                              | MITRE ATT&CK |
| **T1003.006** |                                                     OS Credential Dumping — DCSync | Abuso de APIs de replicación (DCSync via Mimikatz) para extraer hashes de dominio (Administrator, krbtgt, etc.).                                                                                         | MITRE ATT&CK |
| **T1550.002** |                              Use Alternate Authentication Material — Pass the Hash | Uso del hash NTLM del Administrator para autenticarse a través de WinRM (Pass-The-Hash) y obtener control de DC01.                                                                                       | MITRE ATT&CK |
