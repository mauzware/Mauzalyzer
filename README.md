# 🧪 Mauzalyzer v1.0

![Mauzalyzer Logo](https://github.com/mauzware/Mauzalyzer/blob/main/MAUZALYZER%20BACKGROUND.png)

**Ultimate Data Duplication & Similarity Analyzer — built for developers, analysts, and data engineers who need quick insights from messy, large, or structured data files.**

> **Created by [mauzware](https://github.com/mauzware)**  
> Works on Linux 🐧 and Windows 🪟  
> Fast, powerful, and customizable via CLI ⚙️

---

## 📦 Features

- 🔁 Detects exact duplicates across rows and columns
- 🔍 Finds similar values using fuzzy matching
- 🧠 Automatically categorizes values: Numeric, Textual, Mixed, Unknown
- 📊 Outputs detailed summaries and top frequent values
- 💾 Exports reports in JSON, TXT, or XML
- 📁 Supports both CSV and XLSX files
- ⚡ Modes: Fast, Standard, and Detailed
- 🧼 Experimental support for messy CSVs (`--messy`)
- 🌈 Colorful CLI with optional logging and quiet/debug modes

---

## 🛠️ Installation

Make sure you have **Python 3.9+** installed (tested on 3.13+).

**Windows**

```bash
git clone https://github.com/mauzware/Mauzalyzer.git
cd Mauzalyzer
pip install -r requirements.txt
python mauzalyzer.py --help
```

**Linux Debian/Ubuntu**

```bash
git clone https://github.com/mauzware/Mauzalyzer.git
cd Mauzalyzer
pip install -r requirements.txt
python mauzalyzer.py --help
```

**Kali Linux**

In Kali all required modules are already pre-installed
```bash
git clone https://github.com/mauzware/Mauzalyzer.git
cd Mauzalyzer
python mauzalyzer.py --help
```

---

## 🖥️ Usage

```bash
python mauzalyzer.py [OPTIONS] source
```

---

## 🔧 Basic Options

| Option             | Description                                                  |
|--------------------|--------------------------------------------------------------|
| `--fast`           | Fast scanning (basic checks only)                            |
| `--detailed`       | Detailed scanning with deep similarity analysis              |
| `--type csv/xlsx`  | Manually set the file type                                   |
| `--chunksize`      | Set custom chunk size for large files                        |
| `--messy`          | Preprocess messy CSV files                                   |
| `-o`, `--output`   | Custom output file name                                      |
| `--output-format`  | Output format: `json`, `txt`, `xml`                          |

## 🛡️ Utility Flags

| Flag               | Description                                                  |
|--------------------|--------------------------------------------------------------|
| `--version`        | Display version and author info                              |
| `--help`           | Show help screen                                             |
| `--debug`          | Enable full debug traceback                                  |
| `--quiet`          | Suppress all output                                          |
| `-v`, `--verbose`  | Show verbose output                                          |

---

## 📸 Screenshots

💡 **Help menu on Linux:**

<img src="https://github.com/mauzware/Mauzalyzer/blob/main/kali.png" />

💡 **Help menu on Windows:**

<img src="https://github.com/mauzware/Mauzalyzer/blob/main/windows.png" />

💡 **In action:**

<img src="" width=50% /> <img src="" width=50% />

---

## 📂 Output Example

```json
{
  "analysis_date": "2025-04-17T17:03:33",
  "data_source": "Your_Input_File.xlsx",
  "findings": [...],
  "summary": {...}
}
```

Reports are saved to the **data_report/** folder and include a timestamp + hash for uniqueness. <br>
**data_report/** folder will be automatically created after first usage.

---

## 🚧 Future Plans: Mauzalyzer v2.0 (coming soon...)

Mauzalyzer Engineers are already cooking up new features for v2.0. Stay tuned! 👾

- 👁️ Better schema detection for extremely messy files

- 🗂️ Support for more formats: JSON, XML, TXT (as inputs)

- 🎛️ GUI mode (TBD)

- 🔧 Interactive mode for manual value inspection

- ⚙️ Additional CLI support

---

## 👨‍💻 Author

**mauzware** <br>
**GitHub: github.com/mauzware**

---

**All kuddos go to my professor who taught me everything I know, I think she will be proud of me using this many emojis.** 😅
<br>
**To all my friends who supported me on this wonderful journey — I haven't forgotten you, folks. Big thanks and much love to all of you!** ❤️









