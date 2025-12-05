# 🛡️ InnoSleuth  
**Advanced InnoDB Forensics, Threat Intelligence & IOC Analysis Framework**  

A comprehensive forensic analysis tool for MySQL/MariaDB InnoDB databases with integrated threat intelligence enrichment and indicator of compromise detection.

---

## 📌 Overview
InnoSleuth is an advanced forensic analysis platform designed to analyze **InnoDB tablespaces, UNDO pages, REDO logs, BLOB pages, and compressed records**, while integrating powerful **IOC hunting, Threat Intelligence correlation, AI anomaly detection, and YARA rule scanning**.

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
- Detects: Fraud, Malware-related text, Illegal activity, Suspicious communication patterns  
- Text normalization + risk scoring  

### 🛡️ IOC & Threat Intelligence Engine
- Detects over 20 indicator types, including:  
  - IP addresses, URLs, Domains, Emails  
  - Bitcoin/crypto wallets  
  - File hashes (MD5/SHA1/SHA256)  
  - Phone numbers, Malware keywords, Command patterns  
- Includes:  
  - ThreatScore rating  
  - Indicator mapping per artifact  
  - IOC → YARA → AI fusion results  
  - Automatic flagging of high-risk pages  

### 🧬 Carving Engine
- Extracts embedded files from database pages:  
  - PDF, ZIP, PNG, JPG, Raw binary blobs  

### 📦 Message Reconstruction Engine
- Rebuilds communication fragments from:  
  - WhatsApp-like BLOBs  
  - Telegram fragments  
  - Splitted text segments  
  - Base64 encoded blocks  

### 📊 Visual Analytics
- Timeline of recovered messages  
- Encrypted/High-entropy heatmap  
- Network graph of related entities  
- IOC–Artifact relation graph  

### 📄 Professional PDF Reporting
- Generates full forensic reports including:  
  - Case metadata  
  - All indicators  
  - Extracted messages  
  - IOC hits  
  - Suspicious content  
  - Artifacts table  
  - Bookmarks  
  - Risk coloration  

---

**InnoSleuth** empowers investigators with deep database forensics, actionable intelligence, and professional reporting in a single integrated platform.  


🛠️ Installation

```bash
# Clone or extract
cd InnoSleuth_Final

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```
📦 Dependencies
numpy
pandas
pyqt6
matplotlib
networkx
python-dateutil
cryptography
fpdf
zlib
yara-python
cupy


📂 Project Structure

```
InnoSleuth_Final/
├── main.py              # Application entry point
├── config.py            # Configuration
├── innodb_core.py       # Core engine (all classes)
├── requirements.txt     # Dependencies
│
├── core/                # InnoDB parsing wrappers
├── analysis/            # Forensic analysis wrappers
├── threat_intel/        # IOC enrichment wrappers
├── gui/                 # PyQt6 interface wrappers
└── utils/               # Utility wrappers
```
📸 Screenshots
Main Interface
<img width="3072" height="1815" alt="image" src="https://github.com/user-attachments/assets/3375ab04-1cf9-4873-b179-005314eb1aa1" />

Analysis View
<img width="3072" height="1767" alt="image" src="https://github.com/user-attachments/assets/7b6738c4-a05f-4956-b53e-da299ac88c40" />

Timeline

Heatmap

IOC hits
<img width="2981" height="1596" alt="image" src="https://github.com/user-attachments/assets/98769305-7ead-4f5d-b1f0-2d11ad1186aa" />


Report

🔥 Usage
Load Files

.ibd

ib_logfile0 / ib_logfile1

Any InnoDB tablespace

Start Analysis

The engine parses:

Pages

Records

UNDO/REDO

BLOB data

Entropy

AI detection

IOC scanning

Export PDF Report

From GUI → File → Export PDF


## Usage

1. **Create Case** - Start new forensic case
2. **Load File** - Select InnoDB .ibd file
3. **Analyze** - Automatic parsing
4. **Review** - Examine results
5. **Export** - Generate PDF report

## Requirements

- Python 3.9+
- PyQt6
- See requirements.txt

## License

MIT License - Free for forensic investigations

## Warning

For **legitimate forensic use only**. Ensure proper authorization before analyzing any database files.

---
👤 Credits

InnoSleuth
Developed By: Anwar Yousef


**Made for Digital Forensics Community**
