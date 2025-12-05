<p align="center">
  <img src="https://github.com/user-attachments/assets/daac756e-344a-4208-a1a9-552cc4c7d0a3" alt="InnoSleuth Logo" width="400"/>
</p>

# 🛡️ InnoSleuth
## **Advanced InnoDB Forensics, Threat Intelligence & IOC Analysis Framework**  
✨ **Developed By:** Anwar Yousef  

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.9%2B-blue.svg" alt="Python Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status"></a>
</p>

---

## 📑 Table of Contents
- [📌 Overview](#-overview)  
- [📦 Dependencies](#-dependencies)  
- [📂 Project Structure](#-project-structure)  
- [📸 Screenshots](#-screenshots)  
- [🚀 Key Features](#-key-features)  
- [🔥 Usage](#-usage)  
- [⚡ Quick Start](#-quick-start)  
- [⚙️ Requirements](#️-requirements)  
- [📝 License](#-license)  
- [⚠️ Warning](#️-warning)  

---

## 📌 Overview
InnoSleuth is an advanced forensic analysis platform designed to analyze **InnoDB tablespaces, UNDO pages, REDO logs, BLOB pages, and compressed records**, while integrating **IOC hunting, Threat Intelligence correlation, AI anomaly detection, and YARA rule scanning**.

It is designed for:  
- Digital Forensic Analysts  
- Incident Responders  
- Threat Intelligence Teams  
- Law Enforcement  
- Researchers  
- Malware & Fraud Investigators  

With InnoSleuth, you can:  
- Investigate compromised MySQL systems  
- Extract deleted records  
- Identify malicious indicators  
- Detect suspicious communication  
- Produce full forensic PDF reports  

---

## 📦 Dependencies
- `numpy`  
- `pandas`  
- `pyqt6`  
- `matplotlib`  
- `networkx`  
- `python-dateutil`  
- `cryptography`  
- `fpdf`  
- `zlib`  
- `yara-python`  
- `cupy`  

---

## 📂 Project Structure
InnoSleuth_Final/
├── main.py # Application entry point
├── config.py # Configuration
├── innodb_core.py # Core engine (all classes)
├── requirements.txt # Dependencies
│
├── core/ # InnoDB parsing wrappers
├── analysis/ # Forensic analysis wrappers
├── threat_intel/ # IOC enrichment wrappers
├── gui/ # PyQt6 interface wrappers
└── utils/ # Utility wrappers


---

## 📸 Screenshots

### 🖥️ Main Interface
<img src="https://github.com/user-attachments/assets/3375ab04-1cf9-4873-b179-005314eb1aa1" alt="Main Interface" width="800"/>  

### 📊 Analysis View
<img src="https://github.com/user-attachments/assets/7b6738c4-a05f-4956-b53e-da299ac88c40" alt="Analysis View" width="800"/>  

### 🕸️ Link Analysis
<img width="3070" height="1760" alt="image" src="https://github.com/user-attachments/assets/99b99835-813c-42c9-9ad2-699e8c1d6eb3" />


### 🌡️ Heatmap
<img width="3068" height="1690" alt="image" src="https://github.com/user-attachments/assets/5901776c-faae-4099-8017-a8e27df53513" />

### 🛡️ IOC Hits
<img src="https://github.com/user-attachments/assets/98769305-7ead-4f5d-b1f0-2d11ad1186aa" alt="IOC Hits" width="800"/>  

### 📄 Report
<img width="1433" height="1670" alt="Screenshot 2025-12-05 120736" src="https://github.com/user-attachments/assets/cbf0aa16-7e28-464b-af6a-5ed512532637" />

<img width="2153" height="1589" alt="image" src="https://github.com/user-attachments/assets/8c1a2d15-4e3f-4c6b-9a80-ea650eca94cf" />


---

## 🚀 Key Features

### 🔍 InnoDB Deep Forensics
- Parse InnoDB 16KB pages  
- Extract active & deleted records  
- UNDO/REDO log parsing  
- BLOB/ZBLOB decompression (zlib)  
- UTF-8/UTF-16 text carving  
- Heuristic record reconstruction  
- In-page artifact recovery  

### 🧠 AI Detection Engine
- Naive Bayes–based suspicious content classifier  
- Detects Fraud, Malware-related text, Illegal activity, Suspicious communication patterns  
- Text normalization + risk scoring  

### 🛡️ IOC & Threat Intelligence Engine
- Detects over 20 indicator types: IPs, URLs, Domains, Emails, Bitcoin/crypto wallets, File hashes, Phone numbers, Malware keywords, Command patterns  
- Includes ThreatScore rating, Indicator mapping per artifact, IOC → YARA → AI fusion results, Automatic flagging of high-risk pages  

### 🧬 Carving Engine
- Extracts embedded files: PDF, ZIP, PNG, JPG, Raw binary blobs  

### 📦 Message Reconstruction Engine
- Rebuilds communication fragments from WhatsApp-like BLOBs, Telegram fragments, Splitted text segments, Base64 encoded blocks  

### 📊 Visual Analytics
- Timeline of recovered messages  
- Encrypted/High-entropy heatmap  
- Network graph of related entities  
- IOC–Artifact relation graph  

### 📄 Professional PDF Reporting
- Full forensic reports: Case metadata, Indicators, Extracted messages, IOC hits, Suspicious content, Artifacts table, Bookmarks, Risk coloration  

---

## 🔥 Usage
1. **Create Case** - Start new forensic case  
2. **Load File** - Select InnoDB `.ibd` file or logs (`ib_logfile0/ib_logfile1`)  
3. **Analyze** - Automatic parsing (Pages, Records, UNDO/REDO, BLOBs, Entropy, AI detection, IOC scanning)  
4. **Review** - Examine results  
5. **Export** - Generate PDF report (GUI → File → Export PDF)  

---

## ⚡ Quick Start

![Quick Start GIF](https://via.placeholder.com/800x400?text=Quick+Start+GIF)  
*Quick overview of using InnoSleuth*

**Step-by-Step Quick Start:**  
1. Launch **InnoSleuth** application  
2. Click **Create Case** to start a new forensic investigation  
3. Load an **InnoDB .ibd file** or log files  
4. Click **Analyze** → wait for parsing and AI/IOC scanning  
5. Review the results: Timeline, Heatmap, IOC hits  
6. Export a full **PDF report** (GUI → File → Export PDF)  

💡 Tip: Replace the placeholder GIF with an actual short video or GIF demonstrating the workflow.

---

## ⚙️ Requirements
- Python 3.9+  
- PyQt6  
- See `requirements.txt`  

---

## 📝 License
MIT License - Free for forensic investigations  

---

## ⚠️ Warning
For legitimate forensic use only. Ensure proper authorization before analyzing any database files.

