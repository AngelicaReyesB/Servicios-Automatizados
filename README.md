# Consola de automatización de servicios (NP2 – Computación en la Nube 2026-2)

Aplicación web en Go que automatiza tareas de administración de una VM Debian 13
(VirtualBox) desde el host Windows. Antes de configurar SSH habla con la VM por
**Guest Additions** (`VBoxManage guestcontrol`); después, **solo por SSH con llave**.

## Estado

| Requisito | Estado |
|---|---|
| 3.1.1 Instalar / eliminar aplicaciones | ✅ implementado |
| 3.1.4 Nombre de host + `/etc/hosts` | ✅ implementado |
| 3.1.2 Llave SSH de root (+ cambio de canal a SSH) | ✅ implementado |
| 3.1.3 `/etc/issue` | ✅ |
| 3.2 Usuarios | ✅ |
| 3.3 systemd | ✅ |
| 3.4 HAProxy | ✅ |

## Primer arranque (Windows)

1. Instalar Go 1.24+ y VirtualBox. La VM debe estar encendida, con Guest Additions
   instaladas y en modo puente.
2. En la carpeta del proyecto:
   ```powershell
   go mod tidy                      # descarga golang.org/x/crypto y github.com/pkg/sftp
   copy config.example.json config.json
   ```
3. Editar `config.json`: nombre exacto de la VM en VirtualBox, su IP, contraseña de
   root (solo se usa para Guest Additions) y `authors` (sale en el pie de página).
   **No subir `config.json` a git** (ya está en `.gitignore`).
4. Prueba de humo del canal, antes de usar la app:
   ```powershell
   & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" guestcontrol "debian-main" run --username root --password TU_CLAVE --exe /bin/hostname --wait-stdout
   ```
   Debe imprimir el hostname de la VM. Si falla, la app también fallará: corrija eso primero.
5. Arrancar:
   ```powershell
   go run ./cmd/server
   ```
   y abrir <http://127.0.0.1:8080>.

## Cómo probar (y qué mostrar en los videos)

| Prueba | Antes (en la VM) | Después (en la VM) |
|---|---|---|
| Instalar `htop` | `dpkg -l htop` | `dpkg -l htop` / `which htop` |
| Eliminar `htop` | `which htop` | `which htop` (sin salida) |
| Paquete inexistente | — | mensaje claro en pantalla + detalle técnico |
| Nombre de host | `hostname; cat /etc/hosts` | `hostname; cat /etc/hosts` |

Cada operación también muestra "estado previo" y "verificación" en el *Detalle técnico*,
y queda en `data/logs/operaciones.jsonl` (comando, stdout, stderr, código de salida).

### Probar 3.4 (HAProxy)

Requisitos: el objetivo `haproxy` en `config.json` (VM con HAProxy instalado, clonada después de configurar la llave de root) y al menos un servidor web en otra VM (o en `debian`, p. ej. con `nginx`) para usar de back-end.

1. «Balanceador de carga»: si el canal dice Guest Additions, pulse **Conectar por SSH con la llave de root** (reutiliza la llave de «Preparación»).
2. Antes: en la VM del balanceador `cat /etc/haproxy/haproxy.cfg` (solo `global` y `defaults`).
3. Agregue `web1` con la IP y el puerto de un servidor. Después: el archivo tiene un bloque `# BEGIN consola-automatizacion … # END` con `frontend consola_front` (`*:80`) y `backend consola_back` con `server web1 IP:PUERTO check`; `systemctl status haproxy` activo y `ss -ltnp | grep :80` muestra haproxy.
4. Agregue un segundo servidor y abra `http://IP-del-balanceador` varias veces (o `curl`): las respuestas se alternan entre ambos.
5. Elimine un servidor: deja de recibir tráfico. Con el back-end vacío HAProxy responde 503.
6. Casos de error: un nombre o IP repetidos, una IP inválida (`999.1.1.1`) o `127.0.0.1` se rechazan antes de tocar la VM. Si el puerto 80 de la VM del balanceador lo ocupa otro programa (p. ej. nginx), la consola restaura la configuración anterior y lo explica. El original queda en `/etc/haproxy/haproxy.cfg.consola.bak`.

### Probar 3.3 (servicios systemd)

Prepare en Windows el binario del catálogo **para Linux** (`GOOS=linux GOARCH=amd64 go build -o catalogo .`; un `.exe` se rechaza con un mensaje claro) y, si la app necesita plantillas o estáticos, un `.zip` con ellos.

1. «Gestión de servicios» → nombre `catalogo-libros`, archivo ejecutable, (extras opcionales), tipo «Permanece en ejecución», argumentos si los necesita (p. ej. `-port 8080`) → **Desplegar**.
2. En la VM: `ls -l /opt/catalogo-libros`, `systemctl cat catalogo-libros`, `id catalogo-libros`. El servicio aparece en la tabla, detenido.
3. Botones: **start** (debe quedar `active`), **status** (muestra systemctl status y el journal), **restart**, **enable** (reinicie la VM: debe arrancar solo), **disable**, **stop**.
4. Si la app usa un puerto, pruébela desde el navegador de Windows: `http://IP:puerto`.
5. Script de fecha y hora (precondición e): despliegue `ejemplos/registro-fecha.sh` como tipo «Se ejecuta una vez y termina». Cada **start**/**restart** agrega una línea a `/opt/<nombre>/registro.txt` (`sudo cat` para verlo).
6. Redesplegar con el mismo nombre actualiza archivos y unidad (si estaba activo se reinicia). Un nombre que ya usa un servicio del sistema (p. ej. `ssh`) o un usuario ajeno se rechaza.
7. **Eliminar** con la casilla borra además `/opt/<nombre>` y el usuario.

### Probar 3.2 (usuarios)

1. Módulo «Gestión de usuarios» → crear `ana` con **sudo** y **llaves** marcadas. Debe salir «Operación completada» y un botón para descargar la llave privada.
2. En la VM: `id ana` (grupo sudo), `sudo cat /etc/sudoers.d/consola-ana`, `sudo ls -l /home/ana/.ssh/authorized_keys` (600) y `sudo passwd -S ana` (debe verse bloqueada/sin contraseña).
3. Desde Windows: `ssh -i id_ed25519_ana ana@IP` entra; luego `sudo whoami` → `root`. Sin la llave, o con contraseña, debe rechazar.
4. Crear `ana` otra vez → «Ya existe un usuario». Crear sin llave → mensaje de que aún no puede iniciar sesión.
5. Eliminar `ana` sin la casilla: el home `/home/ana` se conserva. Crear y eliminar `beto` con la casilla: el home desaparece y se borra su llave local. `root` está bloqueado.

### Probar 3.1.3 (/etc/issue)

1. En «Personalización del sistema» deje marcadas host, fecha, hora e IP, escriba un mensaje y pulse **Aplicar**.
2. La página muestra una *vista previa* real (generada con `agetty` en la VM) y el detalle técnico.
3. En la consola de la VM (VirtualBox) pulse Enter en el login o cierre sesión: verá el aviso. Por SSH: `cat /etc/issue`.
4. Prueba de escape: mensaje `C:\nuevo` debe verse literal. Mensaje con Enter/ESC o más de 200 caracteres → «Datos no válidos».
5. El original queda en `/etc/issue.consola.bak` (solo se crea la primera vez).

### Probar 3.1.2 (llaves SSH)

Tome un snapshot de la VM antes. En la VM, **antes**:

```bash
cat /root/.ssh/authorized_keys 2>&1        # puede no existir
ls /etc/ssh/sshd_config.d/
sshd -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication) '
```

En la web: **Generar y configurar llaves SSH**. Debe salir la caja verde con la huella, y la
barra superior debe pasar a **"canal: SSH (llave)"**. Luego, en la VM, **después**:

```bash
cat /root/.ssh/authorized_keys             # línea "ssh-ed25519 ... consola-root"
ls -ld /root/.ssh /root/.ssh/authorized_keys   # drwx------ y -rw-------
cat /etc/ssh/sshd_config.d/00-consola-keys.conf
sshd -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication) '
```

Desde Windows (PowerShell), con la llave descargada con el botón **Descargar**:

```powershell
# 1) Restrinja los permisos de la llave (ssh se niega a usarla si otros usuarios pueden leerla)
icacls .\id_ed25519_root /inheritance:r /grant:r "$($env:USERNAME):R"
# 2) Con la llave: debe entrar
ssh -i .\id_ed25519_root root@IP_DE_LA_VM
# 3) Con contraseña: debe ser RECHAZADO ("Permission denied (publickey)")
ssh -o PubkeyAuthentication=no root@IP_DE_LA_VM
```

Después de esto, cualquier operación (p. ej. instalar `htop`) debe registrarse en el log con
el canal **SSH (llave)**. Las pruebas de la VM por consola de VirtualBox siguen funcionando
con usuario y contraseña: el bloqueo es solo para SSH.

**Flujo (orden de seguridad):** se genera el par ed25519 en el host → por Guest Additions se
instala la pública y se deja root solo con llave → se entra por SSH con la llave nueva
**antes de bloquear nada** (si falla, se detiene y la contraseña no se toca) → la llave pasa a
ser la definitiva y el canal cambia a SSH → por SSH se desactiva la contraseña
(`/etc/ssh/sshd_config.d/00-consola-keys.conf`), validando con `sshd -t` y `sshd -T`, y se
restaura todo si algo no cuadra → se comprueba que un intento de entrar con contraseña es
rechazado.

## Decisiones de diseño

- **`Runner`**: interfaz única (`Run`, `RunInput`, `Upload`) con dos implementaciones
  (`GuestControl`, `SSH`). El `Manager` elige según el estado guardado en `data/state.json`.
- **Validación con listas blancas** (`internal/validate`) antes de construir cualquier comando.
- **Consola solo local**: escucha únicamente en 127.0.0.1, rechaza `Host` ajenos (anti
  DNS-rebinding) y exige token CSRF en todos los POST, porque ejecuta comandos como root.
- **Contraseña de Guest Additions** vía `--passwordfile` temporal, no en la línea de comandos.
- **Paquetes protegidos**: no se elimina `openssh-server`, `sudo` ni las Guest Additions.
- **Una operación a la vez por VM** (apt usa bloqueos) y no se cancela si se cierra el navegador.
- **Huella SSH**: trust-on-first-use en `data/known_hosts/`.
- **Llave de root**: ed25519 generada en el host (`internal/sshkey`, solo librería estándar,
  formato OpenSSH sin passphrase), guardada en `data/keys/` (0600). La privada nunca viaja a
  la VM ni aparece en los registros. Regenerarla reemplaza la anterior solo después de
  comprobar que la nueva funciona, y conserva otras llaves que ya hubiera en `authorized_keys`.
- **Drop-in `00-consola-keys.conf`**: en OpenSSH gana el primer valor de cada directiva, y
  `sshd_config.d` se lee antes que `sshd_config`; el prefijo `00-` hace que el bloqueo prevalezca.
- **Nombre de host**: el diseño de referencia muestra `app_web1`, pero el guion bajo no es
  válido en nombres de host (RFC 1123); la app lo rechaza y sugiere `app-web1`.

## Estructura

```
cmd/server/main.go            arranque
internal/config/              config.json
internal/runner/              Runner, GuestControl, SSH, Manager
internal/sshkey/              generación de llaves ed25519 (formato OpenSSH)
internal/sshtest/             servidor SSH en proceso, solo para pruebas
internal/validate/            validaciones
internal/oplog/               registro técnico
internal/modules/preparacion/ módulo 3.1
internal/web/                 servidor, plantillas, estáticos
```

`go test ./...` ejecuta las pruebas (no requieren VM). Las que ejecutan los scripts reales con
`bash` y simulan el flujo completo de 3.1.2 corren solo en Linux/macOS y se omiten en Windows.

## Para el documento final

Anotar desde ya las herramientas de IA usadas y para qué (el enunciado lo exige).
