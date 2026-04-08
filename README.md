# 🔍 Análisis Forense Digital — Especialización en Ciberseguridad

> Colección de prácticas y proyectos de **informática forense** desarrollados durante la asignatura de Análisis Forense en la especialización de Ciberseguridad. Cubre análisis de disco, volcados de RAM y scripts de ataque.

---

## 📁 Índice de proyectos

| # | Proyecto | Área |
|---|---|---|
| 1 | Script de fuerza bruta sobre ZIP | Scripting / ataque por diccionario |
| 2 | Proyecto Final AFI — Volcado RAM y clonación de disco | Forense avanzado |

---

## 🔐 1. Script de fuerza bruta sobre fichero ZIP

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

## 💻 2. Proyecto Final AFI — Volcado de RAM y clonación de disco

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

## 🛠️ Herramientas utilizadas en el curso

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
