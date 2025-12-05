# InnoSleuth 🔍

**InnoDB Forensic Analysis Tool** for MySQL/MariaDB database forensics.

## Features

- 🔬 **InnoDB Page Analysis** - Parse and analyze InnoDB tablespace files (.ibd)
- 🔄 **Data Recovery** - Extract deleted records and reconstruct messages
- 🧬 **Schema Detection** - Automatic table schema identification
- 🔐 **TDE Decryption** - Transparent Data Encryption support
- 📊 **Entropy Analysis** - Detect encrypted/compressed data
- 🌐 **Threat Intelligence** - VirusTotal, AlienVault OTX, AbuseIPDB integration
- 📑 **PDF Reports** - Professional forensic reports with chain of custody

## Installation

```bash
# Clone or extract
cd InnoSleuth_Final

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

## Project Structure

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

**Made for Digital Forensics Community**
