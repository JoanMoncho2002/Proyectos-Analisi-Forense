# 🔍 Análisis Forense Digital — Especialización en Ciberseguridad

> Colección completa de prácticas y proyectos de **informática forense** desarrollados durante la asignatura de Análisis Forense en la especialización de Ciberseguridad. Cubre análisis de disco, volcados de RAM, forense en Linux, forense móvil, análisis en la nube, scripts de ataque y elaboración de informes periciales.

---

## 📁 Índice de proyectos

| # | Proyecto | Área |
|---|---|---|
| 1 | Informe Pericial — Caso atentado político | Informe pericial forense |
| 2 | Script de fuerza bruta sobre ZIP | Scripting / ataque por diccionario |
| 3 | Proyecto Final AFI — Volcado RAM y clonación de disco | Forense avanzado |

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
