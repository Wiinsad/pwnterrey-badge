<p align="center">
  <img src="assets/logo.png" alt="Pwnterrey Badge" width="400">
</p>

<h1 align="center">Pwnterrey Badge</h1>
<p align="center">
  <strong>Firmware v2.1</strong> · ESP32-C5 · Pwnterrey 2026<br>
  <em>Badge oficial de la comunidad Pwnterrey — basado en ESP32 Marauder</em>
</p>

<p align="center">
  <a href="https://wiinsad.github.io/pwnterrey-badge/">⚡ Web Flasher</a> ·
  <a href="https://instagram.com/pwnterrey">Instagram</a> ·
  <a href="https://chat.whatsapp.com/CnUJOXwgPs94dOgPqq2Rxd">WhatsApp</a>
</p>

---

## ✨ Características

- 📡 **Evil Twin / Evil Portal** — Captura de credenciales con portal cautivo personalizado
- 📶 **WiFi Scanner** — Escaneo de redes, deauth, beacon spam
- 📱 **BLE Spam** — Spam de paquetes BLE (iOS, Android, Windows, Samsung)
- 🗺️ **Wardrive** — Mapeo de redes WiFi con GPS
- 🔑 **WPS Attack** — Fuerza bruta y Pixie Dust para WPS
- 🌐 **Web Interface** — Panel de control en `192.168.4.1`
- 💾 **SD Card** — Almacenamiento de capturas y logs
- 🔋 **Monitor de batería** — Estado en tiempo real

---

## 🚀 Instalación

### Método 1: Web Flasher (Recomendado)

La forma más fácil. Solo necesitas Chrome o Edge.

👉 **[https://wiinsad.github.io/pwnterrey-badge/](https://wiinsad.github.io/pwnterrey-badge/)**

1. Conecta tu badge por USB-C
2. Haz clic en **"Instalar Firmware"**
3. Selecciona el puerto serial
4. Espera ~60 segundos

### Método 2: Terminal con esptool

Instala `esptool` si no lo tienes:

```bash
pip install esptool
```

Descarga `badge-full.bin` de la carpeta [`release/`](release/) y ejecuta:

```bash
esptool.py --chip esp32c5 --port PUERTO --baud 460800 \
  write_flash --flash_mode dio --flash_freq 80m --flash_size 4MB \
  0x0 badge-full.bin
```

**Puertos según tu sistema operativo:**

| Sistema | Puerto |
|---------|--------|
| 🐧 Linux | `/dev/ttyACM0` |
| 🪟 Windows | `COM3` |
| 🍎 macOS | `/dev/cu.usbmodem*` |

> **Tip:** En Linux, si no detecta el puerto, agrega tu usuario al grupo dialout:
> ```bash
> sudo usermod -aG dialout $USER
> ```

### Método 3: Flash individual (binarios separados)

Si necesitas flashear cada partición por separado:

```bash
esptool.py --chip esp32c5 --port PUERTO --baud 460800 \
  write_flash --flash_mode dio --flash_freq 80m --flash_size 4MB \
  0x0 esp32_marauder.ino.bootloader.bin \
  0x8000 esp32_marauder.ino.partitions.bin \
  0x10000 esp32_marauder.ino.bin \
  0x310000 spiffs.bin
```

---

## 📲 Primer uso

1. **Enciende el badge** — Verás el logo en la pantalla
2. **Conéctate al WiFi:**
   - **Red:** `PWNTERREY-XXXX`
   - **Contraseña:** `pwnterrey2026`
3. **Abre el panel:** Navega a `http://192.168.4.1` en tu navegador
4. **Explora:** Usa el menú para seleccionar ataques y herramientas

---

## 🔧 Compilar desde código fuente

### Requisitos

- [arduino-cli](https://arduino.github.io/arduino-cli/)
- Board: `esp32:esp32:esp32c5`

### Pasos

```bash
# Instalar el core de ESP32
arduino-cli core install esp32:esp32

# Clonar este repo
git clone https://github.com/Wiinsad/pwnterrey-badge.git
cd pwnterrey-badge

# Compilar
arduino-cli compile --fqbn esp32:esp32:esp32c5 src/esp32_marauder.ino

# Flashear
arduino-cli upload --fqbn esp32:esp32:esp32c5 --port /dev/ttyACM0 src/esp32_marauder.ino
```

### Generar SPIFFS

```bash
# Crear imagen SPIFFS con los archivos de data/
mkspiffs -c data/ -b 4096 -p 256 -s 0x160000 spiffs.bin

# Flashear SPIFFS
esptool.py --chip esp32c5 --port /dev/ttyACM0 --baud 460800 \
  write_flash 0x310000 spiffs.bin
```

---

## 📁 Estructura del proyecto

```
pwnterrey-badge/
├── src/              # Código fuente del firmware
│   ├── esp32_marauder.ino
│   ├── WiFiScan.cpp/h
│   ├── EvilPortal.cpp/h
│   ├── CommandLine.cpp/h
│   └── ...
├── data/             # Archivos SPIFFS (portal web)
│   ├── portal.html
│   ├── app.js
│   └── ...
├── release/          # Binarios pre-compilados
│   ├── badge-full.bin
│   ├── manifest.json
│   └── flash.html
├── assets/           # Logo y recursos
├── index.html        # Web flasher (GitHub Pages)
├── README.md
└── LICENSE
```

---

## ❓ Solución de problemas

### El badge no es detectado por USB

- Asegúrate de usar un cable **USB-C con datos** (no solo carga)
- En Linux: `sudo dmesg | tail` para ver si el dispositivo aparece
- Instala drivers CH340/CP2102 si es necesario

### Error "Failed to connect" al flashear

- Mantén presionado el botón **BOOT** mientras conectas el USB
- Suelta el botón después de que inicie la descarga
- Reduce la velocidad: cambia `460800` por `115200`

### El Web Flasher no muestra el botón

- Usa **Google Chrome** o **Microsoft Edge** (Firefox no soporta Web Serial)
- Asegúrate de acceder por **HTTPS** (no HTTP)

### No puedo conectarme al WiFi del badge

- Busca la red `PWNTERREY-XXXX` (las X son caracteres únicos del badge)
- Contraseña: `pwnterrey2026`
- Si no aparece, reinicia el badge

### El portal web no carga

- Verifica que el SPIFFS se flasheó correctamente
- Intenta borrar la flash completa primero:
  ```bash
  esptool.py --chip esp32c5 --port PUERTO erase_flash
  ```
  Y luego flashea de nuevo con `badge-full.bin`

---

## 🏆 Créditos

- **[Electronic Cats](https://github.com/ElectronicCats)** — Diseño de hardware
- **Pwnterrey Team** — Personalización del firmware y diseño del badge
- **[justcallmekoko](https://github.com/justcallmekoko)** — Creador de [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)

### 🔗 Enlaces

- 📱 [Instagram @pwnterrey](https://instagram.com/pwnterrey)
- 💬 [Comunidad WhatsApp](https://chat.whatsapp.com/CnUJOXwgPs94dOgPqq2Rxd)
- ⚡ [Web Flasher](https://wiinsad.github.io/pwnterrey-badge/)

---

## 📄 Licencia

Este proyecto está bajo la [Licencia MIT](LICENSE).

---

<p align="center">
  <strong>Hecho con 🦆 por la comunidad Pwnterrey</strong><br>
  <em>Monterrey, México · 2026</em>
</p>
