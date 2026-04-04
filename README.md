# 🔍 Análisis Forense Digital — Especialización en Ciberseguridad

> Colección completa de prácticas y proyectos de **informática forense** desarrollados durante la asignatura de Análisis Forense en la especialización de Ciberseguridad. Cubre análisis de disco, volcados de RAM, forense en Linux, forense móvil, análisis en la nube, scripts de ataque y elaboración de informes periciales.

---

## 📁 Índice de proyectos

| # | Proyecto | Área |
|---|---|---|
| 1 | Introducción a Autopsy | Forense de disco |
| 2 | Caso Richard — Empleado sospechoso | Forense de disco Windows |
| 3 | Informe Pericial — Caso atentado político | Informe pericial forense |
| 4 | Análisis de inicios de sesión (Event Logs) | Forense Windows / PowerShell |
| 5 | UsnJrnl — Journaling NTFS y pagefile.sys | Forense NTFS |
| 6 | Análisis forense Linux | Forense Linux |
| 7 | Análisis de chats móviles | Forense móvil |
| 8 | Análisis forense en la nube | Forense cloud |
| 9 | Análisis forense IoT — Amazon Echo Show 8 | Forense IoT |
| 10 | Script de fuerza bruta sobre ZIP | Scripting / ataque por diccionario |
| 11 | Proyecto Final AFI — Volcado RAM y clonación de disco | Forense avanzado |

---

## 🗂️ 1. Introducción a Autopsy — UD4ACT1

Primera toma de contacto con **Autopsy** analizando una imagen de disco virtual (`UD4ACT1`).

**Preguntas respondidas:**

| Pregunta | Respuesta |
|---|---|
| Extensiones de archivos en el disco | `.jpg`, `.ini`, `.dat` (entre otras) — 44 archivos en total |
| Sistema de archivos | NTFS / exFAT |
| Número total de archivos | 44 archivos |

**Herramientas:** Autopsy

---

## 👨‍💼 2. Caso Richard — Empleado sospechoso

Análisis forense del disco de un empleado que abandonó la empresa tras una discusión y se sospecha que ha exfiltrado datos a la competencia.

**Verificación de integridad de la evidencia:**
```
MD5:     dfdfba2231e3fa409676b1b737474288
SHA-1:   f476a81089a10f9d5393aa8c2f8bbccdb87f7d3d
SHA-256: 66d6ee7a61ea7a986e8f6bb54b9986f79d95b5a0278bef86678ed42ace320d98
```

**Hallazgos principales:**

| Pregunta | Hallazgo |
|---|---|
| Usuario en el equipo | Sí, con último acceso el **22-02-2023** |
| Nombre del equipo y SO | `LADRONERA` · Windows 10 Pro Education N (10.0.19045) |
| Uso de USB no autorizado | Kingston conectado el **22-02-2023 a las 01:27:42** |
| Película vista online | *Trabajo Basura* (1999) — vista desde **CUEVANA.HD** |
| Destino tras irse | Vuelos a **Las Palmas de Gran Canaria** (buscados en Vueling) |
| Navegador no Microsoft al inicio | **Opera** (encontrado en el Escritorio del usuario) |
| Exfiltración de datos | Correo encontrado con conversación sobre "material" y contrato con empresa competidora |

**Herramientas:** Autopsy, Windows Registry Recovery, SQLite3 (historial Opera)

---

## ⚖️ 3. Informe Pericial — Caso de sospecha de atentado contra un político
`Código: INF-2025-001 · Fecha: 10/03/2025`

Informe pericial forense elaborado siguiendo los estándares **UNE 197010:2015** y **UNE 71506:2013**, dirigido al Juzgado de Instrucción Nº 5 de Dénia (Diligencias Previas 123/2025).

**Hallazgos principales:**

| Pregunta | Hallazgo |
|---|---|
| Usuario del equipo | `Pacopepe` (OS Accounts de Autopsy) |
| Objetivo del atentado | Feijoo y Alfonso Rueda |
| Lugar planeado | Palacio de la Moncloa, Madrid |
| Alojamientos investigados | Hostal Condestable, Hostal Alaska, Hotel Riu Plaza España |
| Motivación ideológica | Canal de YouTube *«los minutos del odio»* |
| Recurso técnico | *El libro de cocina del anarquista* — descargado desde pdfcookie.com |
| Armerías visitadas | Armería Estradense y Armería Barreiro (con precios anotados) |
| Metadatos EXIF | 3 imágenes encontradas, sin relevancia para el caso |

**Cronología del caso:**
```
05/04/2022 14:26 → Creación del usuario "Pacopepe"
26/04/2022 00:04 → Visualización de "los minutos del odio" en YouTube
29/04/2022 17:55 → Búsquedas de Feijoo y Alfonso Rueda
06/05/2022 19:12 → Búsqueda de hostales en Madrid
06/05/2022 19:13 → Búsqueda del Palacio de la Moncloa
     Mayo 2022   → Visitas a armerías gallegas
18/05/2022 19:17 → Descarga de "El libro de cocina del anarquista"
```

**Integridad de la evidencia:**
```
SHA256: 8edd15a99a39f50c6212a9dff47c03a7211b6d12a4377cae27a5bb6ea6c8eebe
MD5:    737def84cf9a77415a613a8a162ce8ae
```

**Herramientas:** Autopsy, DB Browser for SQLite, sha256sum/md5sum

---

## 📋 4. Análisis de inicios de sesión — UD4ACT5

Extracción y análisis de eventos de inicio de sesión del sistema operativo mediante **PowerShell** y los archivos de eventos de Windows (`.evtx`).

**Tareas realizadas:**

- Extracción de inicios de sesión desde `Security.evtx` (evento ID 4624).
- Exportación a CSV con hora, usuario, SID e IP de origen.
- Detección de conexiones remotas mediante análisis de IP de origen.
- Cálculo del tiempo que estuvo encendido el equipo en la última sesión usando `System.evtx` (eventos ID 12, 13, 41, 6006).
- Script PowerShell para generar CSV de sesiones con hora de inicio, hora de apagado y duración.
- Detección de usuarios creados de forma remota mediante evento ID 4720.

**Comandos clave:**
```powershell
# Inicios de sesión con usuario, SID e IP origen
Get-WinEvent -Path ".\Security.evtx" | Where-Object {$_.Id -eq 4624} |
ForEach-Object { [PSCustomObject]@{
    HoraInicioSesion = $_.TimeCreated
    Usuario          = $_.Properties[5].Value
    SID              = $_.Properties[4].Value
    Origen           = $_.Properties[18].Value
}} | Export-Csv -Path ".\IniciosDeSesion.csv" -NoTypeInformation -Encoding UTF8

# Sesiones del sistema (inicio / apagado / duración)
Get-WinEvent -Path ".\System.evtx" | Where-Object { $_.Id -eq 12 -or $_.Id -in @(13,41,6006) }
```

**Archivos analizados:** `Security.evtx`, `System.evtx`

---

## 📂 5. UsnJrnl — Journaling NTFS y archivo de paginación — UD4ACT6

Análisis del fichero de journaling `$UsnJrnl` de NTFS para rastrear operaciones sobre archivos, y análisis del archivo de paginación de memoria (`pagefile.sys`).

**Hallazgos del journaling (imagen UD4ACT4 — usuario Pacopepe):**

Los dos últimos archivos con los que interactuó el usuario fueron archivos `.lnk` (accesos directos):
- `Descargas.lnk`
- `pdfcookie.com_el-libro-de-cocina-del-anarquista-william-powell.lnk`

Estos archivos LNK evidencian los últimos ficheros abiertos por el usuario.

**Operaciones sobre archivos propios:**

| Archivo | Operaciones registradas |
|---|---|
| `jmonchosupr.txt` | File Create → RenameNewName → permanece en papelera |
| `jmonchoshiftsupr.txt` | File Create → RenameNewName → **FileDelete** (eliminado permanentemente con Shift+Supr) |

**Archivo de paginación (`pagefile.sys`):**
- Capturado con **FTK Imager**.
- Analizado con el comando `strings` para recuperar texto escrito en Notepad que el sistema operativo pagina a disco.
- Se verificó que el contenido del `.txt` aparecía en el archivo de paginación.

**Herramientas:** Autopsy, MFTECmd, FTK Imager, strings

---

## 🐧 6. Análisis forense Linux — U5ACT1

Análisis de un sistema Linux comprometido el **10 de junio de 2021**, con el objetivo de determinar el vector de entrada, las acciones del atacante y si consiguió escalar privilegios.

**Hallazgos principales:**

| Pregunta | Hallazgo |
|---|---|
| IP del atacante | `10.1.0.7` |
| Usuario comprometido por SSH | `han_solo` — conexión exitosa el **10/06 a las 22:22** |
| Servicio atacado por fuerza bruta | **FTP (puerto 21)** — a las 22:22:18 |
| Modificación de usuario | Contraseña de `han_solo` cambiada a las **22:32:03** |
| Ataque path traversal | Detectado en logs web a las **22:23:25** (respuestas 404) |
| Webshell instalada | Clonación de `wwwolf-php-webshell` desde GitHub a las **22:33:57** |
| Vector principal de entrada | Inyección SQL en `payroll_app.php` |
| Escalada de privilegios | Script compilado localmente — CVE relacionado con Apache 2.4.7 / PHP 5.4.5 |

**Resumen ejecutivo de la línea temporal:**
```
22:22:18 → Ataque por fuerza bruta FTP desde 10.1.0.7
22:23:25 → Ataque path traversal sobre servidor web
22:30:xx → Explotación de payroll_app.php mediante inyección SQL
22:32:03 → Cambio de contraseña del usuario han_solo
22:33:57 → Instalación de webshell (wwwolf-php-webshell) vía GitHub
```

**Herramientas:** Volatility 2 (perfil Linux), `linux_bash`, `cat auth.log`, `avml`

---

## 📱 7. Análisis de chats móviles — Forense móvil

Investigación forense sobre tres teléfonos móviles confiscados a miembros de una banda criminal implicada en un asesinato.

**Personajes:** Capo (jefe), Matón (ejecutor), Mulero (víctima).

**Hallazgos — Capo:**
- Instrucciones a Mulero para recoger un coche en **Chamartín, junto a la Cruz de la Horca** (WhatsApp).
- Mensaje de voz de bronca recuperado del 6 de octubre.
- Últimos mensajes apuntan a **Mateo** como autor del asesinato.

**Hallazgos — Mulero:**
- Fotos de su fiesta de cumpleaños con metadatos EXIF: ubicación en el **puerto de A Coruña**.
- Historial de navegación Firefox (`places.sqlite`): búsquedas de criptomonedas (*"regueton dinero facil bitxoin"*).

**Hallazgos — Matón:**
- Mensajes de Telegram con Capo sobre una "chivatada": localización enviada en **Rúa do Castelo Ramiro, Ourense** (extraída de `cache4.db`).
- Confirmación del asesinato de Mulero el **16 de octubre de 2023**.
- Coordenadas del lugar del crimen: `43°30'21.42" N, 8°12'18.39" W` (Galicia, costa atlántica).

**Herramientas:** Autopsy, DB Browser for SQLite, análisis de metadatos EXIF, script Python sobre `cache4.db`

---

## ☁️ 8. Análisis forense en la nube — UD7ACT1

Análisis de un **Google Takeout** y datos de redes sociales obtenidos mediante orden judicial para los tres miembros de la banda criminal.

**Hallazgos — Capo:**
- Nombre real: **Ernesto Capote** · Email: `ernestocapote2@gmail.com` (extraído de `Perfil.json`)
- Publicación en **Twitter** el 3/10/2023 buscando conductor para "ganar dinero rápido".
- Ubicación de oficina de correos compartida en Google Maps el **5/10/2023 a las 21:25:18**.
- Correo recibido de Matón el **13/10/2023** con factura del "material".
- Coordenadas de la foto de la factura: `43°32'21.63" N, 8°11'36.22" W`.

**Hallazgos — Mulero:**
- Foto de fiesta en Instagram publicada el **9/10/2023** — tomada el **8/10 a las 19:02:56** con producto comprometedor visible.
- Nombre de usuario en Instagram: `mulligandous`.
- El día de su asesinato preguntó a **Alexa** cómo llegar a un **Carrefour**.

**Hallazgos — Matón:**
- Nombre real: **Mateo García** · Email: `mg2067958@gmail.com`
- Dispositivo: **Xiaomi Redmi 2201117TY** con Android.
- Destino final tras deshacerse del coche: **Berna**.
- Número de teléfono extraído de Instagram: **672921162**.

**Fuentes analizadas:** Google Takeout, Instagram, Twitter/X, Amazon Alexa, Gmail (`.mbox`)

---

## 📡 9. Análisis forense IoT — Amazon Echo Show 8 — UD8ACT1

Análisis forense de un dispositivo **Amazon Echo Show 8** cuya memoria fue adquirida mediante la técnica **Chip-off** (desoldado físico del chip de memoria).

**Hash de la imagen:**
```
MD5: b58fa04967161c158723c7b00a636533
```

**Particiones analizadas:**
- `loop0p21` (3 GB) — partición del sistema
- `loop0p23` (3,5 GB) — partición de datos del usuario

**Montaje:**
```bash
# Montar partición del sistema
sudo mount /dev/loop0p21 /mnt/echoshow8

# Montar partición de datos (con noload si está inconsistente)
sudo mount -o noload /dev/loop0p23 /mnt/echoshow8_data
```

**Hallazgos — Partición del sistema (`system/build.prop`):**

| Campo | Valor |
|---|---|
| Versión del SO | `ro.build.version.release` |
| Marca | `ro.product.brand` |
| Dispositivo | `ro.product.device` |
| Versión FireOS | `ro.build.version.fireos` / `ro.build.version.name` |

Listado de aplicaciones instaladas extraído del directorio `system/app`.

**Hallazgos — Partición de datos del usuario:**

| Dato | Fuente | Valor |
|---|---|---|
| Nombre del equipo | `data/com.android.settings/shared_prefs/deviceNameSharedPref.xml` | — |
| Número de serie | `com.amazon.settings.DNSVR_STORE.xml` | `G6G1GG10141403SD` |
| Corroboración serie + nombre | `data/amazon.speech.sim/files/device_capabilities_api.amazonalexa.com` | — |
| ID de perfil, usuario y clave de cifrado | `data/com.amazon.imp/databases/map_data.storage_v2.db` (tablas `accounts` y `encryption_data`) | — |
| IDs de usuario | `system/users/userlist.xml` y `sorteduserlist.xml` | — |
| Último inicio de sesión | `system/users/0.xml` → campo `lastLoggedIn` convertido con `date -u -d@valor` | — |
| Aplicaciones recientes | `system_ce/0/recent_tasks` + capturas en `system_ce/0/snapshots` | — |
| Redes WiFi (SSID + PSK) | `misc/wifi/WifiConfigStore.xml` | 2 redes encontradas |
| Dispositivos Bluetooth emparejados | `user_de/0/com.android.bluetooth/shared_prefs/Bt_Metrics_Remote_Device_Uuids.xml` | — |
| Historial de navegación | `data/com.amazon.cloud9/app_amazon_webview/amazon_webview/History` (tabla `visits`, SQLite) | — |

**Herramientas:** Kali Linux, `mmls`, `mount`, `sqlite3`, `date`

---

## 🔐 10. Script de fuerza bruta sobre fichero ZIP

Script Python que realiza un ataque de diccionario sobre archivos ZIP protegidos con contraseña.

```python
import argparse
import zipfile

def crack_zip(zip_file, dictionary_file):
    try:
        with zipfile.ZipFile(zip_file, 'r') as zf:
            with open(dictionary_file, 'r') as df:
                for line in df:
                    password = line.strip()
                    try:
                        zf.extractall(pwd=password.encode('utf-8'))
                        print(f"[+] Contraseña encontrada: {password}")
                        return True
                    except (RuntimeError, zipfile.BadZipFile):
                        continue
        print("[-] No se encontró la contraseña en el diccionario.")
    except FileNotFoundError:
        print(f"Archivo no encontrado: {zip_file} o {dictionary_file}")
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("zipfile")
    parser.add_argument("dictionary")
    args = parser.parse_args()
    crack_zip(args.zipfile, args.dictionary)
```

**Uso:**
```bash
zip -er carpeta.zip TOPSECRET
echo -e "password\n123456\ncontra123\nadmin" > diccionario.txt
python3 scriptfuerzabruta.py carpeta.zip diccionario.txt
# [+] Contraseña encontrada: contra123
```

---

## 💻 11. Proyecto Final AFI — Volcado de RAM y clonación de disco

Simulación de un ataque informático completo en laboratorio controlado (VirtualBox) con posterior análisis forense mediante Volatility 3 y Autopsy.

**Entorno del laboratorio:**

| Máquina | SO | IP | Rol |
|---|---|---|---|
| Atacante | Windows 10 | 192.168.1.144 | Servidor QuasarRAT |
| Víctima | Windows 10 | 192.168.1.145 | Sistema comprometido |

**Simulación del ataque:**
1. Desactivación de Windows Defender.
2. Edición del archivo `hosts` para redirigir `pokemongratis.com` → IP atacante.
3. Distribución de `PokemonV4.exe` (cliente QuasarRAT) mediante servidor web Python.
4. Ejecución del troyano por la víctima → control remoto total.
5. Creación y posterior eliminación de `abreme.txt` como evidencia oculta.

**Análisis con Volatility 3:**

| Plugin | Hallazgo |
|---|---|
| `windows.pslist` | `PokemonV4.exe` (PID 9188) — proceso padre ausente |
| `windows.netscan` | Conexión TCP establecida → `192.168.1.144:4785` |
| `windows.malfind` | Regiones `PAGE_EXECUTE_READWRITE` en PID 9188 |
| `windows.envars` | Usuario `Joan`, rutas APPDATA/TEMP accesibles por el malware |
| `windows.privileges` | `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeLoadDriverPrivilege` |

**Análisis con Autopsy:**

| Módulo | Hallazgo |
|---|---|
| Web Downloads | `PokemonV4.exe` desde `pokemongratis.com:8022` a las 20:17:48 |
| Deleted Files | `abreme.txt` recuperado del Escritorio |
| Web Search | "qué hacer si me han hackeado", "como denunciar un ciberataque" |

**Cadena de custodia:**
```
RAM — DOS-20250523-182648.dmp
  SHA256: 03699A0666C6E14E97AB9BD5F0838C50D5457806AE86CDB2C4912DC2784B453B

Disco — Windows30.raw
  SHA256: 9920A2D56740431250227F37E9AFA9A108F99F14256BC22FC298684650C23136
```

---

## 🛠️ Herramientas utilizadas

| Herramienta | Uso principal |
|---|---|
| **Autopsy** | Análisis de disco, historial web, archivos eliminados, metadatos EXIF |
| **Volatility 2/3** | Análisis forense de volcados de RAM (Windows y Linux) |
| **FTK Imager** | Captura de `pagefile.sys` y adquisición de evidencias |
| **MFTECmd** | Análisis del journaling NTFS (`$UsnJrnl`) |
| **DumpIt** | Volcado de memoria RAM en Windows |
| **VBoxManage** | Clonación de disco duro en formato RAW |
| **QuasarRAT** | Troyano RAT usado en simulación de ataque (entorno controlado) |
| **DB Browser for SQLite** | Análisis de bases de datos de navegadores y apps móviles |
| **PowerShell** | Extracción y análisis de eventos de Windows (`.evtx`) |
| **mmls / mount** | Montaje de imágenes IoT y análisis de particiones |
| **Python 3** | Script de fuerza bruta sobre ZIP |

---

## ⚠️ Aviso legal

Todos los proyectos de este repositorio fueron desarrollados en **entornos controlados y aislados** con fines exclusivamente académicos, en el marco de la especialización de Ciberseguridad. Ninguna técnica mostrada fue aplicada sobre sistemas reales ni con fines maliciosos.

---

## 📚 Contexto académico

Proyectos desarrollados durante la asignatura de **Análisis Forense** en el ciclo de especialización de **Ciberseguridad**.

Normativa de referencia: **UNE 197010:2015** · **UNE 71506:2013** · **Ley de Enjuiciamiento Civil (Art. 335.2)**

---

## 👤 Autor

**Joan Moncho Vinaroz**  
[LinkedIn](https://www.linkedin.com/in/joan-moncho-vinaroz-413212240/) · [GitHub](https://github.com/JoanMoncho2002)
