<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/UI-CustomTkinter-1f6feb?style=flat-square" alt="CustomTkinter"/>
  <img src="https://img.shields.io/badge/Encryption-AES--256-2ea44f?style=flat-square" alt="Encryption"/>
</p>

<h1 align="center">Stealth Messenger</h1>

<p align="center">
  A steganography tool for embedding secret text or files into images<br/>
  with optional AES-256 encryption and compression.
</p>



<p align="center">
  <img src="UI.png" alt="Stealth Messenger UI" width="650"/>
</p>



## Features

- **Dual Embedding Modes** - Hide text messages or entire files within PNG images
- **AES-256 Encryption** - Optional password protection with PBKDF2 key derivation (480k iterations)
- **Smart Compression** - Zlib compression to maximize storage capacity
- **Auto-Detection** - Extraction automatically detects bit depth, compression, and encryption settings
- **Adjustable Bit Depth** - Trade-off between capacity (1-8 bits per channel) and detection resistance
- **Real-time Capacity Display** - See available space as you compose your message
- **Resolution Adaptive** - UI scales automatically to different screen sizes

---

## Installation

```bash
pip install customtkinter pillow

# Optional: Enable encryption support
pip install cryptography
```

## Usage

```bash
python SteganographyApp_final2.py
```

**Encoding:** Select a cover image → Enter message or choose file → Configure options → Embed → Save

**Decoding:** Select encoded image → Enter password (if encrypted) → Extract → Save

---

## Technical Specifications

### Capacity vs. Stealth

| Bit Depth | Relative Capacity | Detection Risk |
|-----------|-------------------|----------------|
| 1-2 bits  | Low-Medium        | Minimal        |
| 3-4 bits  | High              | Low            |
| 5-8 bits  | Maximum           | Moderate-High  |

### Data Format

```
[Signature: 7B] [Header: 4B] [Payload: Variable] [Terminator: 4B]

Header: Version | Bit Depth | Flags | Type
Flags:  Bit 0 = Compressed, Bit 1 = Encrypted
Type:   0x00 = Text, 0x01 = File
```

### Storage Capacity

A 1920×1080 image at 2-bit depth provides approximately **1.5 MB** of usable storage.

---

## Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| customtkinter | UI framework | Yes |
| pillow | Image processing | Yes |
| cryptography | AES encryption | Optional |

---

## Notes

- **Always save as PNG** - JPEG compression destroys embedded data
- **Encrypted data cannot be recovered** without the correct password
- Temporary files are automatically cleaned up on application exit

---

<p align="center">
  <sub>Semester Project - Advanced Steganography Implementation</sub>
  <br>
  <sub>5th January 2025</sub>
</p>



