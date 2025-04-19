# 🧪 Mauzalyzer v1.0

![Mauzalyzer Logo](https://github.com/mauzware/Mauzalyzer-assets/blob/main/MAUZALYZER%20BACKGROUND.png)

**Ultimate Data Duplication & Similarity Analyzer — built for developers, analysts, and data engineers who need quick insights from messy, large, or structured data files.**

> **Created by [mauzware](https://github.com/mauzware)**  
> Works on Linux 🐧 and Windows 🧩  
> Fast, powerful, and customizable via CLI ⚙️

---

## 📦 <i>Features</i>

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

## 🛠️ <i>Installation</i>

Make sure you have **Python 3.9+** installed (tested on 3.13+). <br>
You can use either **pip** or **pip3**, whichever works on your system depending on your Python version.

<i>**Windows**</i>

```bash
git clone https://github.com/mauzware/Mauzalyzer.git
cd Mauzalyzer
pip install -r requirements.txt
python mauzalyzer.py --help
```

<i>**Linux Debian/Ubuntu**</i>

```bash
git clone https://github.com/mauzware/Mauzalyzer.git
cd Mauzalyzer
pip install -r requirements.txt
python mauzalyzer.py --help
```

<i>**Kali Linux**</i>

In Kali, all required modules are already pre-installed. <br>

```bash
git clone https://github.com/mauzware/Mauzalyzer.git
cd Mauzalyzer
python mauzalyzer.py --help
```

If you are missing some modules by any chance, you can install them with: <br>
1) Create a virtual environment and use: **pip3 install -r requirements.txt** <br>
2) Install them manually with apt: **sudo apt install python3-[module_name]**

---

## 🖥️ <i>Usage</i>

You can use either **python** or **python3**, whichever works on your system depending on your Python version.

```bash
python mauzalyzer.py [OPTIONS] source
python3 mauzalyzer.py [OPTIONS] source
```
**Examples:**

```bash
python3 mauzalyzer.py Your_File.csv #Basic scan
python mauzalyzer.py Your_File.xlsx #Basic scan
python3 mauzalyzer.py Your_File.csv --detailed #Detailed scan
python mauzalyzer.py --fast Your_File.xlsx #Fast scan
python3 mauzalyzer.py Your_File.csv -o Report_Name --output-format=txt #Saving output in TXT format
python mauzalyzer.py Your_File.xlsx -o Report_Name --output-format=xml #Saving output in XML format
```

---

## 🔧 <i>Basic Options</i>

| Option             | Description                                                  |
|--------------------|--------------------------------------------------------------|
| `--fast`           | Fast scanning (basic checks only)                            |
| `--detailed`       | Detailed scanning with deep similarity analysis              |
| `--type csv/xlsx`  | Manually set the file type                                   |
| `--chunksize`      | Set custom chunk size for large files                        |
| `--messy`          | Preprocess messy CSV files                                   |
| `-o`, `--output`   | Custom output file name                                      |
| `--output-format`  | Output format: `json`, `txt`, `xml`                          |

## 🛡️ <i>Utility Flags</i>

| Flag               | Description                                                  |
|--------------------|--------------------------------------------------------------|
| `--version`        | Display version and author info                              |
| `--help`           | Show help screen                                             |
| `--debug`          | Enable full debug traceback                                  |
| `--quiet`          | Suppress all output                                          |
| `-v`, `--verbose`  | Show verbose output                                          |

---

## 📸 <i>Screenshots</i>

💡 <i>**Help menu on Linux:**</i>

![Linux Help](https://github.com/mauzware/Mauzalyzer-assets/blob/main/kali.png)

💡 <i>**Help menu on Windows:**</i>

![Windows Help](https://github.com/mauzware/Mauzalyzer-assets/blob/main/windows.png)

💡 <i>**Mauzalyzer in action:**</i>

![Linux in action](https://github.com/mauzware/Mauzalyzer-assets/blob/main/kali%20snippet.png)
![Windows in action](https://github.com/mauzware/Mauzalyzer-assets/blob/main/action.png)

---

## 📂 <i>Output Example</i>

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

## ⚡ <i>Bonus: Optional Header Row Removal, details are below.</i>

This code helps remove repeated or stray header rows inside messy CSVs
(usually when a report was exported from Excel or multiple tables were merged).

❗️ **When to use:**
- You scanned a file and noticed weird duplicated values like "type" or "sale_date"
- You know your file includes repeated headers (you may have seen them in Excel file when you opened it)

📋 **Instructions:**
1. Below this comment, you'll see a method called 'remove_headers(df)', edit the list 'known_headers' to include any words you want to treat as "header rows".
2. In regards to editing 'known_headers', you can add more values or remove some, it's completely on you.
3. Go to method 'scan_csv()' in the code, you'll see '#df = remove_headers(df)', just remove # and that's it, voila removed headers are implemented.

Example:
```bash
def scan_csv(self, similarity_threshold=85):
    try:
        df = self.safe_read_csv(file_path)
        #df = remove_headers(df) <-- Here, simply delete # and its done
```

---

## 🚧 <i>Future Plans: Mauzalyzer v2.0 (coming soon...)</i>

Mauzalyzer Engineers are already cooking up new features for v2.0. Stay tuned! 👾

- 👁️ Better schema detection for extremely messy files

- 🗂️ Support for more formats: JSON, XML, TXT (as inputs)

- 🎛️ GUI mode (TBD)

- 🔧 Interactive mode for manual value inspection

- ⚙️ Additional CLI support

---

## 👨‍💻 <i>Author</i>

**mauzware** <br>
**GitHub: github.com/mauzware**

---

<i>**All kuddos go to my professor who taught me everything I know, I think she will be proud of me using this many emojis.**</i> 😅
<br>
<i>**To all my friends who supported me on this wonderful journey — I haven't forgotten you, folks. Big thanks and much love to all of you!**</i> ❤️









