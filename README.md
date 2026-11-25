<p align="center">
  <img src="data/marauder3L.jpg" alt="Pwnterrey Badge" width="400">
</p>

<h1 align="center">⚡ Pwnterrey Badge</h1>

<p align="center">
  <b>El badge oficial de Pwnterrey — WiFi, BLE, NFC, GPS y más en un solo dispositivo</b><br>
  Basado en ESP32 Marauder · Chip ESP32-C5 · Firmware v2.0
</p>

<p align="center">
  <a href="#-instalación-método-fácil-desde-el-navegador">🌐 Instalar desde el navegador</a> ·
  <a href="#-instalación-desde-terminal">💻 Instalar desde terminal</a> ·
  <a href="#-primer-uso">🚀 Primer uso</a> ·
  <a href="#-compilar-desde-el-código-fuente">🔧 Compilar desde código</a>
</p>

---

## 🎯 ¿Qué es el Pwnterrey Badge?

Es una herramienta de seguridad ofensiva portátil diseñada para aprender hacking ético y pentesting de redes inalámbricas. Viene precargada con firmware personalizado que te permite hacer pruebas de seguridad WiFi, Bluetooth, NFC y más.

---

## ✨ Características

| Categoría | Funciones |
|-----------|-----------|
| **📡 WiFi** | Scanner de redes, deauth, beacon spam, probe flood, rickroll, evil twin con templates personalizables, captura de handshakes, sniffer de paquetes |
| **📱 BLE Spam** | Spam de notificaciones para Apple (AirPods), Google (Fast Pair), Samsung (SmartTag), Windows (Swift Pair) |
| **💳 NFC** | Lectura y escritura de tags NFC |
| **🛰️ GPS + Wardriving** | GPS integrado, wardrive con mapa en tiempo real, almacenamiento de puntos de acceso |
| **🔑 WPS** | Ataque WPS PIN, Pixie Dust, generador de PINs, lista de vulnerabilidades conocidas |
| **🖥️ Terminal** | Más de 40 comandos disponibles por serial |
| **🌐 Panel Web** | Interfaz web responsive mobile-first con tema oscuro/claro, accesible desde el celular |
| **🎭 Evil Portal** | Portales cautivos personalizables con templates incluidos |

---

## 📦 ¿Qué hay en este repositorio?

```
pwnterrey-badge/
├── src/                  ← Código fuente del firmware (.cpp, .h, .ino)
├── data/                 ← Archivos del panel web (portal.html, app.js, etc.)
├── release/              ← Binarios listos para flashear
│   ├── badge-full.bin           ← Imagen completa (4 MB) — USA ESTE
│   ├── esp32_marauder.ino.bin   ← Solo firmware de la app
│   ├── spiffs.bin               ← Solo sistema de archivos SPIFFS
│   ├── esp32_marauder.ino.bootloader.bin  ← Bootloader
│   ├── esp32_marauder.ino.partitions.bin  ← Tabla de particiones
│   ├── manifest.json            ← Manifiesto para ESP Web Tools
│   └── flash.html               ← Página web para flashear desde el navegador
├── libraries/            ← Librerías necesarias (referencia)
├── LICENSE               ← Licencia MIT
└── README.md             ← Este archivo
```

---

## 🌐 Instalación: Método Fácil (desde el navegador)

> **Este es el método más fácil. No necesitas instalar nada. Funciona en Windows, Mac, Linux y ChromeOS.**

### Requisitos

- Google Chrome o Microsoft Edge (otros navegadores NO funcionan)
- Un cable USB para conectar el badge
- Tu Pwnterrey Badge

### Pasos

1. **Conecta tu badge** al computador con el cable USB

2. **Abre el flasher web** en tu navegador:

   👉 Abre el archivo `release/flash.html` directamente, o si el repositorio está en GitHub Pages:

   ```
   https://wiinsad.github.io/pwnterrey-badge/release/flash.html
   ```

   > También puedes abrir el archivo `release/flash.html` localmente: descarga este repositorio, navega a la carpeta `release/` y abre `flash.html` con Chrome.

3. **Haz clic en el botón "INSTALL"**

4. **Selecciona el puerto** de tu badge cuando el navegador te lo pida

5. **Espera** a que termine de flashear (~2 minutos)

6. **¡Listo!** Tu badge ya tiene el firmware instalado

### ¿No aparece el botón o el puerto?

- Asegúrate de usar **Chrome o Edge** (Firefox y Safari no soportan Web Serial)
- Revisa que el cable USB sea de **datos** (no solo de carga)
- En **Linux**, puede que necesites permisos:
  ```bash
  sudo usermod -a -G dialout $USER
  ```
  Después cierra sesión y vuelve a entrar

---

## 💻 Instalación desde Terminal

> **Para los que prefieren la línea de comandos.** Es el mismo resultado que el método web.

### Requisitos (todos los sistemas)

- Python 3 instalado
- Cable USB de datos
- Tu Pwnterrey Badge

### Paso 1: Instalar esptool

Abre tu terminal y ejecuta:

```bash
pip install esptool
```

> Si te da error de permisos, prueba con:
> ```bash
> pip install --user esptool
> ```
> O en algunas distribuciones de Linux:
> ```bash
> pip3 install esptool
> ```

### Paso 2: Descargar el firmware

Descarga el archivo `badge-full.bin` de la carpeta `release/` de este repositorio.

Puedes clonar el repo completo:
```bash
git clone https://github.com/Wiinsad/pwnterrey-badge.git
cd pwnterrey-badge/release/
```

O descargar solo el binario directamente:
```bash
curl -L -o badge-full.bin https://github.com/Wiinsad/pwnterrey-badge/raw/main/release/badge-full.bin
```

### Paso 3: Conectar el badge y encontrar el puerto

Conecta tu badge por USB y sigue las instrucciones según tu sistema operativo:

---

### 🐧 Linux

**Encontrar el puerto:**
```bash
ls /dev/ttyACM*
```

Normalmente será `/dev/ttyACM0`. Si no aparece nada, prueba:
```bash
ls /dev/ttyUSB*
```

**Dar permisos al puerto (solo la primera vez):**
```bash
sudo usermod -a -G dialout $USER
```
> Después de este comando, **cierra sesión y vuelve a entrar** para que tome efecto.

**Flashear el firmware:**
```bash
esptool.py --chip esp32c5 --port /dev/ttyACM0 --baud 460800 write_flash --flash-mode dio --flash-freq 80m --flash-size 4MB 0x0 badge-full.bin
```

> Si `esptool.py` no se encuentra, prueba con `python -m esptool` en lugar de `esptool.py`

---

### 🪟 Windows

**Encontrar el puerto COM:**

1. Abre el **Administrador de dispositivos** (clic derecho en Inicio → Administrador de dispositivos)
2. Busca la sección **"Puertos (COM y LPT)"**
3. Busca algo como `USB Serial Device (COM3)` — el número puede variar
4. Anota el puerto (ejemplo: `COM3`)

> **¿No aparece el puerto?** Puede que necesites instalar drivers. Busca "CP2102 driver" o "CH340 driver" y descarga el que corresponda a tu badge.

**Flashear el firmware:**

Abre **CMD** o **PowerShell** y ejecuta:
```bash
esptool.py --chip esp32c5 --port COM3 --baud 460800 write_flash --flash-mode dio --flash-freq 80m --flash-size 4MB 0x0 badge-full.bin
```

> Cambia `COM3` por el puerto que encontraste en el paso anterior.

> Si `esptool.py` no se encuentra, prueba con:
> ```bash
> python -m esptool --chip esp32c5 --port COM3 --baud 460800 write_flash --flash-mode dio --flash-freq 80m --flash-size 4MB 0x0 badge-full.bin
> ```

---

### 🍎 macOS

**Encontrar el puerto:**
```bash
ls /dev/cu.usb*
```

Normalmente será algo como `/dev/cu.usbmodem14101` o `/dev/cu.usbserial-0001`.

**Flashear el firmware:**
```bash
esptool.py --chip esp32c5 --port /dev/cu.usbmodem14101 --baud 460800 write_flash --flash-mode dio --flash-freq 80m --flash-size 4MB 0x0 badge-full.bin
```

> Cambia `/dev/cu.usbmodem14101` por el puerto que encontraste.

> Si `esptool.py` no se encuentra, prueba con `python3 -m esptool` en lugar de `esptool.py`

---

### ✅ ¿Cómo sé que funcionó?

Después de flashear verás algo así en la terminal:

```
Connecting...
Chip is ESP32-C5
Uploading stub...
Writing at 0x00000000... (0 %)
Writing at 0x00010000... (1 %)
...
Writing at 0x003f0000... (99 %)
Wrote 4194304 bytes (...)
Hash of data verified.

Leaving...
Hard resetting via RTS pin...
```

**Si ves "Hash of data verified"**, ¡todo salió bien! 🎉

---

## 🚀 Primer Uso

Una vez flasheado, tu badge creará una red WiFi propia. Sigue estos pasos:

1. **Busca la red WiFi** llamada `PWNTERREY-XXXX` (las X son caracteres únicos de tu badge)

2. **Conéctate** con la contraseña:
   ```
   pwnterrey2026
   ```

3. **Abre tu navegador** y ve a:
   ```
   http://192.168.4.1
   ```

4. **¡Listo!** Ya estás en el panel de control del badge. Desde ahí puedes:
   - Escanear redes WiFi
   - Lanzar ataques de prueba
   - Configurar evil portals
   - Capturar handshakes
   - Hacer wardriving con GPS
   - Spammear BLE
   - Y mucho más...

> **Tip:** El panel web funciona desde el celular. Conéctate al WiFi del badge desde tu teléfono y abre 192.168.4.1 en el navegador.

---

## 🔧 Compilar desde el Código Fuente

> **Solo si quieres modificar el firmware.** Si solo quieres usarlo, usa los métodos de instalación de arriba.

### Requisitos

- [arduino-cli](https://arduino.github.io/arduino-cli/installation/) instalado
- Git

### Paso 1: Clonar el repositorio

```bash
git clone https://github.com/Wiinsad/pwnterrey-badge.git
cd pwnterrey-badge
```

### Paso 2: Instalar el core de ESP32

```bash
arduino-cli config init
arduino-cli config add board_manager.additional_urls https://espressif.github.io/arduino-esp32/package_esp32_index.json
arduino-cli core update-index
arduino-cli core install esp32:esp32
```

### Paso 3: Instalar librerías

```bash
arduino-cli lib install "ArduinoJson"
arduino-cli lib install "Adafruit NeoPixel"
arduino-cli lib install "NimBLE-Arduino"
arduino-cli lib install "LinkedList"
arduino-cli lib install "JPEGDecoder"
arduino-cli lib install "TFT_eSPI"
```

### Paso 4: Compilar el firmware

```bash
arduino-cli compile --fqbn esp32:esp32:esp32c5 \
  --build-property "build.partitions=min_spiffs" \
  --build-property "upload.maximum_size=4194304" \
  src/esp32_marauder.ino
```

### Paso 5: Construir la imagen SPIFFS

```bash
# Instalar mkspiffs si no lo tienes
# En la carpeta del ESP32 core suele estar incluido

mkspiffs -c data -b 4096 -p 256 -s 917504 spiffs.bin
```

### Paso 6: Crear el binario completo (merge)

```bash
esptool.py --chip esp32c5 merge_bin \
  --flash-mode dio \
  --flash-freq 80m \
  --flash-size 4MB \
  -o badge-full.bin \
  0x0 build/esp32.esp32.esp32c5/esp32_marauder.ino.bootloader.bin \
  0x8000 build/esp32.esp32.esp32c5/esp32_marauder.ino.partitions.bin \
  0x10000 build/esp32.esp32.esp32c5/esp32_marauder.ino.bin \
  0x310000 spiffs.bin
```

---

## 📁 Binarios Individuales

Si necesitas flashear los binarios por separado (usuarios avanzados):

| Archivo | Offset | Descripción |
|---------|--------|-------------|
| `esp32_marauder.ino.bootloader.bin` | `0x0` | Bootloader |
| `esp32_marauder.ino.partitions.bin` | `0x8000` | Tabla de particiones |
| `esp32_marauder.ino.bin` | `0x10000` | Firmware de la aplicación |
| `spiffs.bin` | `0x310000` | Sistema de archivos (panel web) |

```bash
esptool.py --chip esp32c5 --port PUERTO --baud 460800 write_flash \
  --flash-mode dio --flash-freq 80m --flash-size 4MB \
  0x0 esp32_marauder.ino.bootloader.bin \
  0x8000 esp32_marauder.ino.partitions.bin \
  0x10000 esp32_marauder.ino.bin \
  0x310000 spiffs.bin
```

---

## ❓ Solución de Problemas

<details>
<summary><b>El badge no es detectado por USB</b></summary>

- Prueba otro cable USB (asegúrate que sea de **datos**, no solo de carga)
- Prueba otro puerto USB de tu computadora
- En Windows, instala los drivers CP2102 o CH340
- En Linux, agrega tu usuario al grupo dialout: `sudo usermod -a -G dialout $USER`
</details>

<details>
<summary><b>esptool.py no se encuentra</b></summary>

- Verifica que Python esté instalado: `python --version`
- Prueba: `python -m esptool` o `python3 -m esptool`
- En Windows, revisa que Python esté en el PATH
</details>

<details>
<summary><b>Error: "Failed to connect"</b></summary>

- Desconecta y reconecta el badge
- Mantén presionado el botón BOOT del badge mientras conectas
- Cierra cualquier otro programa que use el puerto serial (Arduino IDE, PuTTY, etc.)
</details>

<details>
<summary><b>El flasheo se completó pero el badge no funciona</b></summary>

- Desconecta y reconecta el badge
- Espera 10 segundos después de flashear
- Intenta flashear de nuevo
</details>

<details>
<summary><b>No puedo conectarme al WiFi del badge</b></summary>

- Busca una red que empiece con `PWNTERREY-`
- La contraseña es `pwnterrey2026`
- Si no aparece la red, flashea de nuevo el firmware
</details>

---

## 🙏 Créditos

- **Pwnterrey Team** — Diseño del badge y personalización del firmware
- **[justcallmekoko](https://github.com/justcallmekoko)** — Creador de [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder), el firmware base
- **Comunidad Pwnterrey** — Pruebas, feedback y mejoras

---

## 📄 Licencia

Este proyecto está bajo la [Licencia MIT](LICENSE).

---

<p align="center">
  Hecho con ❤️ por el equipo de <b>Pwnterrey</b>
</p>
