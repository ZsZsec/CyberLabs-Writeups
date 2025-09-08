---
tags:
  - CVE-2019-15107
  - RCE
  - Webmin
  - Nmap
  - web
  - metasploit
  - root
---

# Introduccion

En este ejercicio obtuvimos acceso raíz a la máquina objetivo explotando una vulnerabilidad crítica en `Webmin` (servicio `MiniServ`  escuchando por defecto en el puerto TCP **10000**). El objetivo del writeup es documentar de forma técnica y reproducible las fases de reconocimiento, identificación de la vulnerabilidad, explotación, y las acciones de post-explotación realizadas para fijar evidencias y explorar el sistema.

La vulnerabilidad aprovechada es `CVE-2019-15107`, una inyección de comandos en el endpoint `password_change.cgi` que permite ejecución remota de comandos sin autenticación en instalaciones afectadas de Webmin; por su naturaleza permite ejecución arbitraria en el contexto del proceso de Webmin (en muchas instalaciones ese proceso corre con privilegios elevados), por lo que la explotación resulta en ejecución como root o en la posibilidad de escalar a root inmediatamente.
## Reconocimiento y enumeración inicial

La enumeración de servicios se realizó con **nmap** empleando un escaneo amplio y rápido para descubrir puertos y versiones disponibles; el comando usado fue:

```bash
(zikuta㉿zikuta)-[~/Desktop/source]
└─$ nmap -sV -sS -Pn -p- -sC --min-rate 5000 10.201.116.36 -oN nmap.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-04 08:22 CDT
Nmap scan report for 10.201.116.36
Host is up (0.24s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b7:4c:d0:bd:e2:7b:1b:15:72:27:64:56:29:15:ea:23 (RSA)
|   256 b7:85:23:11:4f:44:fa:22:00:8e:40:77:5e:cf:28:7c (ECDSA)
|_  256 a9:fe:4b:82:bf:89:34:59:36:5b:ec:da:c2:d3:95:ce (ED25519)
10000/tcp open  http    MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`-sS` hace un SYN scan para descubrir puertos sin completar el handshake; `-sV` intenta identificar versiones de servicios; `-Pn` evita el ping previo (útil en entornos que bloquean ICMP); `-p-` escanea todos los puertos TCP; `-sC` ejecuta scripts NSE básicos; `--min-rate` acelera el escaneo; `-oN` guarda salida legible.

El resultado mostró, entre otros, **10000/tcp open http MiniServ 1.890 (Webmin)**, lo que señaló inmediatamente la presencia de Webmin en la máquina objetivo y justificó enfocar la investigación en vulnerabilidades públicas de esa aplicación. Esta salida y decisión de enfoque provienen del comportamiento registrado durante el ejercicio.



<img width="1911" height="800" alt="Image" src="https://github.com/user-attachments/assets/28270816-55fb-4fee-9ce0-730844955262" />

A partir de la detección de `Webmin`, se realizó búsqueda de vulnerabilidades públicas y exploits disponibles. `Webmin`  tuvo una serie de versiones afectadas por inyección de comandos en `password_change.cgi` (variantes alrededor de 1.882–1.921; la versión 1.890 es especialmente citada en la divulgación inicial), y documentación pública detalla que el parámetro vulnerable es `old` (y en algunos casos `expired`) permitiendo inyección al no filtrar adecuadamente entrada que termina ejecutándose en shell. Estas referencias públicas y análisis de la presencia de un backdoor en binarios distribuidos motivaron el intento de explotación.


## Explotación 

Dado que existía un módulo público en Metasploit y varios scripts PoC, se procedió con Metasploit para lanzar el exploit de manera rápida y reproducible. El flujo general usado fue:


<img width="1623" height="597" alt="Image" src="https://github.com/user-attachments/assets/68d9bea2-cec5-49a7-ae7d-d0cf0afb52f7" />

Cargar el módulo correspondiente (en Metasploit suele encontrarse como `linux/http/webmin_backdoor` o mediante el exploit publicado para Webmin 1.920/1.890). El módulo encapsula el payload que explota la inyección en `password_change.cgi` y establece un canal interactivo

<img width="1100" height="320" alt="Image" src="https://github.com/user-attachments/assets/27d8a091-39fc-4d43-a8da-bfd7e08ce3d4" />

Tras el exploit, se obtiene una shell remota proveída por el contexto en el que la vulnerabilidad ejecutó el comando; en la máquina objetivo se observó que el acceso resultante tenía permisos ampliados (root o equivalentes), lo que permitió moverse por el sistema y leer las flags del CTF. 

## Post-explotación: estabilizar la shell y técnicas usadas

Al recibir una shell básica de la explotación, es práctica estándar “mejorar la TTY” para tener un entorno interactivo utilizable (historial, señales, tab completion). En este caso se empleó el clásico comando Python para salto de pty:


<img width="477" height="88" alt="Image" src="https://github.com/user-attachments/assets/4e4cb04d-6308-4a1a-850d-ccacd4cabf94" />

`python -c 'import pty; pty.spawn("/bin/bash")'` 



## Explicación técnica extendida (cómo funciona la inyección y por qué es crítica)

La inyección de comandos en aplicaciones web ocurre cuando entrada del usuario se concatena o interpola en llamadas al sistema (por ejemplo, `system()`, backticks, `exec`) sin saneamiento. En el caso de `password_change.cgi`, la lógica de cambio de contraseña históricamente dependía de invocar utilidades del sistema para verificar o actualizar contraseñas; si la implementación construye la línea de comando con las variables HTTP recibidas sin escapar caracteres especiales como `;`, `&&` o `|`, un atacante puede cerrar la orden legítima y añadir la suya propia. Cuando el servicio que invoca esos comandos tiene privilegios elevados, esa orden maliciosa se ejecuta con los mismos privilegios — de ahí el riesgo extremo. Además, cuando el binario distribuido ya contiene código malicioso (backdoor) la superficie de ataque no depende siquiera de una configuración específica, por lo que la explotación es prácticamente directa. La literatura técnica y el análisis forense de los binarios de Webmin en 2019 documentaron exactamente esta situación: inyección en parámetros `old`/`expired` y presencia de código malicioso en algunas distribuciones oficiales, lo que obligó al proyecto a reconstruir y publicar nuevas versiones seguras


## Detección y mitigación recomendadas

Para detección inmediata tras el incidente:

- Revisar logs HTTP (accesos a `/password_change.cgi`, parámetros, user-agent y patrones de petición inusuales).
- Revisar `auth.log`, `syslog` y registros de Webmin para accesos y ejecuciones inusuales de comandos.
- Comprobar procesos y binarios de Webmin con sumas de verificación frente a versiones conocidas buenas, y detectar archivos con timestamps o firmas que no coincidan con la instalación esperada.


	Mitigación y acciones correctoras:

1. **Actualizar Webmin a la versión parcheada**: el proyecto publicó versiones seguras tras el incidente (la rama 1.930 se distribuyó para corregir los problemas causados por código malicioso añadido en binarios), por lo que actualizar a la versión más reciente y reconstruir desde código fuente confiable es mandatorio. Además, CISA listó esta vulnerabilidad entre las explotadas conocidas, por lo que aplica aplicar parches urgentemente.
2. **Reinstalar desde fuentes de confianza**: reconstruir desde el repositorio Git limpio en infraestructura de construcción controlada, y verificar firmas/sha256 de paquetes.
3. **Rotación de credenciales**: cambiar todas las contraseñas administrativas y rotar claves/credenciales que pudieran haberse visto comprometidas.
4. **Segmentación y endurecimiento**: restringir acceso al puerto 10000 mediante firewall (solo administradores / IPs permitidas), emplear VPN/ACLs y, si no es estrictamente necesario, deshabilitar Webmin.
5. **Monitoreo y alertas**: implementar reglas IDS/IPS para detectar patrones de explotación de `password_change.cgi` y firmas del exploit; auditar accesos recientes.


## Conclusión

La máquina _Source_ fue comprometida porque se exponía un servicio con una vulnerabilidad crítica en una ruta de administración (Webmin) que permitía inyección de comandos sin autenticación.

El proceso de explotación fue: enumeración con nmap → identificación de Webmin en puerto 10000 → uso de exploit público / módulo Metasploit para CVE-2019-15107 → obtención de shell → estabilización de TTY y lectura de flags. 

Desde el punto de vista defensivo, la lección clave es minimizar exposición de paneles administrativos, mantener el software actualizado, verificar la integridad de las distribuciones y monitorizar accesos a endpoints sensibles. Las referencias técnicas sobre la vulnerabilidad, su naturaleza de backdoor en binarios distribuidos y las acciones de mitigación están ampliamente documentadas en NVD, informes de investigación y la propia página de seguridad de Webmin
