# 🔍 Análisis Forense Digital — Especialización en Ciberseguridad

> Colección de prácticas y proyectos de **informática forense** desarrollados durante la asignatura de Análisis Forense en la especialización de Ciberseguridad. Incluye análisis de imágenes de disco, volcados de RAM, scripts de ataque por diccionario e informes periciales completos.

---

## 📁 Proyectos incluidos

---

### 🗂️ 1. Informe Pericial — Caso de sospecha de atentado contra un político
`Código: INF-2025-001 · Fecha: 10/03/2025`

Informe pericial forense elaborado siguiendo los estándares **UNE 197010:2015** y **UNE 71506:2013**, dirigido al Juzgado de Instrucción Nº 5 de Dénia en el marco del procedimiento Diligencias Previas 123/2025.

#### Objetivo
Analizar la imagen forense del disco duro de un equipo incautado a un sospechoso de planificar un atentado contra un político, respondiendo a 8 cuestiones planteadas por el tribunal.

#### Hallazgos principales

| Pregunta | Hallazgo |
|---|---|
| Usuario del equipo | `Pacopepe` (confirmado en OS Accounts de Autopsy) |
| Objetivo del atentado | Feijoo y Alfonso Rueda (búsquedas en Web Search) |
| Lugar planeado | Palacio de la Moncloa, Madrid (Google Maps) |
| Alojamientos investigados | Hostal Condestable, Hostal Alaska, Hotel Riu Plaza España |
| Motivación ideológica | Canal de YouTube «los minutos del odio» |
| Recurso técnico descargado | *El libro de cocina del anarquista* (pdfcookie.com) |
| Armerías visitadas | Armería Estradense, Armería Barreiro, entre otras |
| Metadatos EXIF | No se encontraron imágenes con metadatos relevantes |

#### Cronología del caso

```
05/04/2022 14:26 → Creación del usuario "Pacopepe" en el equipo
26/04/2022 00:04 → Visualización del canal "los minutos del odio" en YouTube
29/04/2022 17:55 → Búsquedas de Feijoo y Alfonso Rueda en Google
06/05/2022 19:12 → Búsqueda de hostales en Madrid (Google Maps)
06/05/2022 19:13 → Búsqueda del Palacio de la Moncloa
  Mayo 2022       → Visitas a armerías gallegas con consulta de precios
18/05/2022 19:17 → Descarga de "El libro de cocina del anarquista"
```

#### Herramientas utilizadas
- **Autopsy** — análisis de Web History, Web Downloads, Web Search, OS Accounts
- **DB Browser for SQLite** — consultas SQL directas sobre `places.sqlite`
- **sha256sum / md5sum** — verificación de integridad de la imagen forense

#### Integridad de la evidencia
```
SHA256: 8edd15a99a39f50c6212a9dff47c03a7211b6d12a4377cae27a5bb6ea6c8eebe
MD5:    737def84cf9a77415a613a8a162ce8ae
```

---

### 🔐 2. Script de Fuerza Bruta sobre Fichero ZIP
`scriptfuerzabruta.py`

Script en Python que realiza un ataque de diccionario sobre archivos ZIP protegidos con contraseña, demostrando la debilidad de contraseñas predecibles frente a ataques automatizados.

#### Flujo de la práctica

1. Crear un archivo ZIP protegido con contraseña mediante `zip -er`.
2. Generar un diccionario de contraseñas candidatas.
3. Ejecutar el script para iterar el diccionario hasta encontrar la contraseña correcta.

#### Código
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
    parser = argparse.ArgumentParser(description="Crack ZIP con fuerza bruta por diccionario.")
    parser.add_argument("zipfile", help="Ruta del archivo ZIP protegido.")
    parser.add_argument("dictionary", help="Ruta del diccionario de contraseñas.")
    args = parser.parse_args()
    crack_zip(args.zipfile, args.dictionary)
```

#### Uso
```bash
# Crear ZIP protegido
zip -er carpeta.zip TOPSECRET

# Generar diccionario
echo -e "password\n123456\nqwerty\ncontra123\nadmin\nletmein\n1234\npassword1\n12345\npassword123" > diccionario.txt

# Ejecutar el script
python3 scriptfuerzabruta.py carpeta.zip diccionario.txt
# [+] Contraseña encontrada: contra123
```

#### Resultado de la demo
La contraseña `contra123` fue encontrada correctamente en el diccionario.

---

### 💻 3. Proyecto Final AFI — Análisis Forense: Volcado de RAM y Clonación de Disco
`Proyecto Final AFI · Mayo 2025`

Proyecto final de la asignatura que simula un ataque informático completo en un laboratorio controlado con VirtualBox, seguido de un análisis forense exhaustivo sobre las evidencias obtenidas.

#### Entorno del laboratorio

| Máquina | SO | IP | Rol |
|---|---|---|---|
| Atacante | Windows 10 | 192.168.1.144 | Servidor QuasarRAT + servidor web |
| Víctima | Windows 10 | 192.168.1.145 | Sistema comprometido |

#### Simulación del ataque

1. Se desactivó Windows Defender en la máquina atacante.
2. Se editó el archivo `hosts` de la víctima para redirigir `pokemongratis.com` → `192.168.1.144`.
3. Se levantó un servidor web Python en el atacante sirviendo `PokemonV4.exe` (cliente QuasarRAT).
4. La víctima descargó y ejecutó el archivo creyendo que era un juego gratuito.
5. El atacante obtuvo control total: escritorio remoto, shell remota, gestor de archivos, registro del sistema.
6. Se dejó el archivo `abreme.txt` en el escritorio de la víctima (luego eliminado como evidencia oculta).

#### Evidencias recogidas

- **Volcado de RAM** con `DumpIt` → `DOS-20250523-182648.dmp`
- **Clonación del disco** con `VBoxManage clonemedium` → `Windows30.raw`

#### Análisis forense — Volatility 3

| Plugin | Hallazgo |
|---|---|
| `windows.pslist` | Proceso `PokemonV4.exe` (PID 9188, PPID 1596 — padre ausente) |
| `windows.netscan` | Conexión TCP establecida → `192.168.1.144:4785` |
| `windows.malfind` | Regiones `PAGE_EXECUTE_READWRITE` en PID 9188 |
| `windows.envars` | Usuario `Joan`, rutas APPDATA y TEMP accesibles por el malware |
| `windows.privileges` | `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeLoadDriverPrivilege`... |
| `memdump` + `strings` + `grep` | Referencias a QuasarRAT y servidor C2 en texto claro |

#### Análisis forense — Autopsy

| Módulo | Hallazgo |
|---|---|
| Web Downloads | `PokemonV4.exe` descargado desde `pokemongratis.com:8022` a las 20:17:48 |
| Web History | Visita a `pokemongratis.com` + búsquedas post-infección |
| Deleted Files | `abreme.txt` recuperado del Escritorio con mensaje del atacante |
| Web Search | "qué hacer si me han hackeado", "como denunciar un ciberataque" |

#### Cadena de custodia

```
Volcado RAM — DOS-20250523-182648.dmp
  SHA256: 03699A0666C6E14E97AB9BD5F0838C50D5457806AE86CDB2C4912DC2784B453B
  SHA512: DBEEC6C47CAC8E5CA21C23730FC8606A464E1A2190043490CE03831461D1C74D335...

Disco clonado — Windows30.raw
  SHA256: 9920A2D56740431250227F37E9AFA9A108F99F14256BC22FC298684650C23136
  SHA512: A2BA1709B38E6E67E7892C03FCF5FA46047449B2A04AC78550C75B35F961B46D7F1...
```

---

## 🛠️ Herramientas utilizadas en el repositorio

| Herramienta | Versión | Uso |
|---|---|---|
| **Autopsy** | 4.22.1 | Análisis de disco, historial web, archivos eliminados |
| **Volatility 3** | 2.11.0 | Análisis forense de volcados de memoria RAM |
| **DumpIt** | v20230117 | Volcado de memoria RAM en entorno Windows |
| **VBoxManage** | — | Clonación de disco duro en formato RAW |
| **QuasarRAT** | v1.4.1 | Troyano RAT utilizado en simulación de ataque (entorno controlado) |
| **VirtualBox** | 7.0.14 | Entorno de virtualización del laboratorio |
| **DB Browser for SQLite** | — | Consultas SQL sobre bases de datos del navegador |
| **Python 3** | — | Script de fuerza bruta sobre ZIP |

---

## ⚠️ Aviso legal

Todos los proyectos de este repositorio fueron desarrollados en **entornos controlados y aislados** con fines exclusivamente académicos, en el marco de la especialización de Ciberseguridad. Ninguna técnica mostrada fue aplicada sobre sistemas reales ni con fines maliciosos.

---

## 📚 Contexto académico

Proyectos desarrollados durante la asignatura de **Análisis Forense** en el ciclo de especialización de **Ciberseguridad**, como parte de la formación de grado superior en la rama de informática.

Normativa de referencia: **UNE 197010:2015** · **UNE 71506:2013** · **Ley de Enjuiciamiento Civil (Art. 335.2)**

---

## 👤 Autor

**Joan Moncho Vinaroz**  
[LinkedIn](https://www.linkedin.com/in/joan-moncho-vinaroz-413212240/) · [GitHub](https://github.com/JoanMoncho2002)
