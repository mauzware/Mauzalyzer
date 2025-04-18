import json
import pandas as pd
import requests
import re
import argparse
import sys
import os
import io
import hashlib
import dicttoxml
import logging
import termcolor
from io import StringIO
from datetime import datetime
from collections import Counter, defaultdict
from rapidfuzz import process, fuzz
from pathlib import Path


REPORT_DIR = "data_report"
TIMEOUT = 15

class Mauzalyzer:
    def __init__(self, file_path, file_type=None, chunksize=50000, fast_mode=False, detailed_mode=False, messy=False):
        """
        Initialize either with:
        - File path (CSV)
        - URL (to CSV/API endpoint)
        - Direct pandas DataFrame
        """

        self.file_path = self._normalize_path(file_path)
        self.file_type = file_type or self._file_checker()
        self.chunksize = chunksize
        self.dataframe = None
        self.raw_data = None
        self.fast_mode = fast_mode
        self.detailed_mode = detailed_mode
        self.findings = {}
        self.messy = messy

        self.mode = 'standard'

        if self.fast_mode:
            self.mode = 'fast'

        elif self.detailed_mode:
            self.mode = 'detailed'

        if self._is_url(self.file_path):
            self._load_from_url()

        else:
            self._load_from_file()

        self.results = {
            'analysis_date': datetime.now().isoformat(),
            'data_source': file_path,
            'findings': []
        }


    @staticmethod
    def is_number(val):
        """Numeric checker"""

        val = val.strip()
        #Remove currency symbols
        if re.match(r'^[\$\€\£\¥]', val):
            val = val[1:]

        #Handles percentages
        if val.endswith('%'):
            val = val[:-1]

        try:
            float(val)
            return True
        
        except ValueError:
            return False
        
    @staticmethod
    def _is_url(value: str) -> bool:
        """Checking if given string is a valid HTTP/HTTPS URL"""

        return isinstance(value, str) and re.match(r"^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", value.strip()) is not None
    
    def _normalize_path(self, path):
        """Normalize and validate URL or local path"""

        return path.strip()

    def _normalize_url(self, value: str) -> str:
        """Ensure URL has proper scheme and format"""

        if self._is_url(value):
            return value.strip().lower()
        
        return None
    
    def _categorize_value(self, value: str) -> str:
        """Categorizing values"""

        if self.is_number(value):
            return "Numeric"
        
        elif re.fullmatch(r"[a-zA-Z\s]+", value.strip()):
            return "Textual"
        
        elif re.search(r"[a-zA-Z\s]", value) and re.search(r"\d", value):
            return "Mixed"
        
        else:
            return "Unknown"
        
    def _file_checker(self):
        """Checking for file type"""

        if self.file_path.endswith('.csv'):
            return 'csv'
        
        elif self.file_path.endswith('.xlsx') or self.file_path.endswith('.xls'):
            return 'xlsx'
        
        else:
            raise ValueError(termcolor.colored((f"🚨 Unable to determine file type from: {self.file_path}"), 'red'))
        
    def _load_from_url(self):
        """Loading data from URLs"""

        try:
            response = requests.get(self.file_path)
            response.raise_for_status()
            self.raw_data = io.StringIO(response.text if self.file_type == 'csv' else response.content)
            print(termcolor.colored((f"🌐 Loaded data from URL: {self.file_path}"), 'green'))

        except Exception as e:
            print(termcolor.colored((f"❌ Failed to load from URL: {e}"), 'red'))
            raise

    def _load_from_file(self):
        """Loading data from file"""

        try:
            if self.file_type == 'csv':
                self.raw_data = open(self.file_path, 'r', encoding="utf-8")

            elif self.file_type == 'xlsx':
                self.raw_data = self.file_path #path used directly by pandas.read_excel

            else:
                raise ValueError(termcolor.colored((f"❌ Unsupported file type for local file: {self.file_type}"), 'red'))
            
            print(termcolor.colored((f"✅ Loaded data from local file: {self.file_path}"), 'green'))

        except Exception as e:
            print(termcolor.colored((f"❌ Failed to load data from local file: {e}"), 'red'))
            raise

    def _processing_values(self, df, similarity_threshold=85):
        """Processes and analyzes values in DataFrame"""

        self.df = df

        #Handling weird CSV with multiple values per row (comma-separated)
        if df.shape[1] == 1:
            all_values = []

            for row in df.iloc[:, 0].dropna():
                all_values.extend([v.strip() for v in str(row).split(',') if v.strip()])

        else:
            all_values = [str(v).strip() for v in df.values.flatten() if pd.notna(v) and str(v).strip()] #converts the DataFrame to a list of strings 

        #Normalize URLs to look like one
        normalized_values = []
        for val in all_values:
            url = self._normalize_url(val)
            normalized_values.append(url if url else val)            

        #Doing categorization       
        categorized = defaultdict(list)
        for val in normalized_values:
            category = self._categorize_value(val)
            categorized[category.lower()].append(val)

        #Collecting all findings
        self.findings = []
        for category, values in categorized.items():
            counts = Counter(values)
            duplicates = {val: count for val, count in counts.items() if count > 1}
            seen = set()
            similar_groups = []

            for val in duplicates:
                if val in seen:
                    continue

                matches = process.extract(val, duplicates.keys(), limit=None, scorer=fuzz.ratio, score_cutoff=similarity_threshold)
                #print(f"Matches for '{val}': {matches}")
                match_vals = [m[0] for m in matches if m[0] != val]
                if match_vals:
                    similar_groups.append([val] + match_vals)
                    seen.update(match_vals + [val])

            self.findings.append({
                'type': category,
                'exact_duplicates': list(duplicates.keys()),
                'similar_patterns': similar_groups
            })

        self.results['findings'] = self.findings
        self._print_findings()

    def _print_findings(self):
        """Prints all values found during the scan"""

        if not self.findings:
            print(termcolor.colored(("🔁 No findings to display."), 'yellow'))
            return
        
        print(termcolor.colored(("\n🎯 Analysis Complete - Categorized Results: "), 'green', attrs=["bold"]))

        for group in self.findings:
            print(termcolor.colored((f"\n 📁 {group['type'].capitalize()} Values: "), 'cyan'))
            print(termcolor.colored((f"   🔁 Exact Duplicates: {len(group['exact_duplicates'])}"), 'green'))
            print(termcolor.colored((f"   🔍 Similar Groups: {len(group['similar_patterns'])}"), 'cyan'))

        for dup in group['exact_duplicates'][:10]: #shows first 10 duplicates
            print(termcolor.colored((f"  -  {dup}"), 'green'))

        if group['similar_patterns']:
            for pattern_group in group['similar_patterns'][:5]: #shows first 5 similar patterns
                print(termcolor.colored((f"  - {' | '.join(pattern_group)}"), 'green'))

    def preprocess_messy_csv(self, df):
        """Processes 'messy' CSV files (in table format a single-column CSV where each row is a comma-separated bundle of values, 
        kind of like rows got squashed horizontally into vertical lines): 
        - Single-column: reshapes flattened rows into structured table with header
        - Multi-column: removes repeated headers if detected
        - Fallback: assigns generic column names if headers are missing
        """
            
        if df.shape[1] == 1:
            #Split all values in each row (assuming CSV is in a single column) ; handling 1-column squashed CSV's - unpacks it and sets header
            split_rows = df.iloc[:, 0].dropna().apply(lambda x: [v.strip() for v in str(x).split(',')])
            row_lengths = split_rows.apply(len)
            most_common_length = row_lengths.mode()[0]
            clean_rows = split_rows[row_lengths == most_common_length]
            final_df = pd.DataFrame(clean_rows.tolist()) #Converts to DataFrame

            #Set first row as header
            final_df.columns = final_df.iloc[0]
            final_df = final_df[1:]

            return final_df
        
        elif df.shape[1] > 1:
            #Detecting repeated headers and removing them
            print(termcolor.colored(("🌐 Preprocessing messy CSV: auto-detected header structure and cleaned rows."), 'yellow'))
            first_row = df.iloc[0].tolist()
            lower_headers = [str(col).strip().lower() for col in first_row]
            cleaned_df = df[~df.apply(lambda row: all(str(cell).strip().lower() in lower_headers for cell in row), axis=1)]

            return cleaned_df
        
        else:
            #Fallback if header is missing or malformed - assigns default headers
            df.columns = [f"col_{i}" for i in range(df.shape[1])]
            return df
    


    def safe_read_csv(self, file_path, chunksize=50000):
        """Checks for file size, depending on size will do respective analysis"""

        try:
            return pd.read_csv(file_path, header=None, engine='python', on_bad_lines='skip')
        
        except MemoryError:
            print(termcolor.colored(("⚠️ CSV file too large or complex, switching to chunk reading..."), 'green'))
            chunks = [chunk for chunk in pd.read_csv(file_path, chunksize=chunksize, on_bad_lines='skip')]
            return pd.concat(chunks, ignore_index=True)
        
            #Debug mode - shows warnings for bad rows
            #self.df = pd.read_csv(path, chunksize=50000, on_bad_lines='warn')

        except Exception as e:
            print(termcolor.colored((f"❌ Failed to read CSV safely: {e}"), 'red'))
            return None        

    def safe_read_xlsx(self, file_path): #maybe implement chunksize option in the future
        """Checks for file size, depending on size will do respective analysis"""

        try:
            return pd.read_excel(file_path)
        
        except MemoryError:
            print(termcolor.colored(("🚨 XLSX file too large or complex!"), 'red'))
            raise

        except Exception as e:
            print(termcolor.colored((f"❌ Error while reading XLSX: {e}"), 'red'))
            raise

    def scan_csv(self, similarity_threshold=85):
        """Scanning CSV files"""

        print(termcolor.colored(("🔍 Scanning CSV file..."), 'green', attrs=["bold"]))

        try:
            df = self.safe_read_csv(self.file_path)
            #df = remove_headers(df) #Uncomment this line to ignore the first row/header of the CSV during scanning
            if df is None:
                print(termcolor.colored(("❌ Could not read CSV data!"), 'red'))
                return
            
            if self.messy:
                print(termcolor.colored(("🧹 Detected messy CSV layout. Preprocessing before scan..."), 'yellow'))
                df = self.preprocess_messy_csv(df)
        
            self.df = df
            all_values = []
            print(termcolor.colored(("📊 CSV data loaded successfully!"), 'green'))

            #Flatten all values across all rows and columns
            for _, row in df.iterrows():
                for value in row:
                    if pd.notna(value): #Skip NaN
                        all_values.append(str(value).strip())

            self._processing_values(self.df, similarity_threshold)

        except Exception as e:
            print(termcolor.colored((f"🚨 Error while scanning CSV: {e}")))

        if self.mode == 'fast':
            #Skip deep similarity checks or fuzzy matching
            print(termcolor.colored(("⚡ Running in FAST mode (only basic checks)."), 'green'))

        elif self.mode == 'detailed':
            #Perform fuzzy matching and deeper analysis
            print(termcolor.colored(("🔬 Running in DETAILED mode (performing all checks)."), 'green'))

        else:
            #Balanced scan mode
            print(termcolor.colored(("🔁 Running in STANDARD mode."), 'green'))

    def scan_xlsx(self, similarity_threshold=85):
        """Scanning XLSX files"""

        print(termcolor.colored(("🔍 Scanning XLSX file..."), 'green', attrs=["bold"]))

        self.df = self.safe_read_xlsx(self.file_path)
        print(termcolor.colored(("📊 XLSX data loaded successfully!"), 'green'))

        self._processing_values(self.df, similarity_threshold)

        if self.mode == 'fast':
            #Skip deep similarity checks or fuzzy matching
            print(termcolor.colored(("⚡ Running in FAST mode (only basic checks)."), 'green'))

        elif self.mode == 'detailed':
            #Perform fuzzy matching and deeper analysis
            print(termcolor.colored(("🔬 Running in DETAILED mode (performing all checks)."), 'green'))

        else:
            #Balanced scan mode
            print(termcolor.colored(("🔁 Running in STANDARD mode."), 'green'))
                
    def scan_data(self, similarity_threshold=85): 
        """Scanning data for exact and similar patterns"""
        
        print(termcolor.colored((f"🔍 Starting scan for file type: {self.file_type.upper()}"), 'green', attrs=["bold"]))

        if self.file_type == 'csv':
            result = self.scan_csv(similarity_threshold)
        
        
        elif self.file_type == 'xlsx':
            result = self.scan_xlsx(similarity_threshold)
        
        else:
            raise ValueError(termcolor.colored((f"💥 Unsupported file type: {self.file_type}"), 'red'))
        
        #Quick summary
        print(termcolor.colored(("\n Summary of findings:"), 'cyan', attrs=["bold"]))
        for group in self.findings:
            print(termcolor.colored((f"  {group['type'].title()} : {len(group['exact_duplicates'])} duplicates, {len(group['similar_patterns'])} similar groups"), 'cyan'))

        return result
         

    def summarize_similar_patterns(self):
        """Adds summary of most common values found in similar patterns group"""

        summary = defaultdict(Counter)
        for finding in self.results['findings']:
            for group in finding['similar_patterns']:
                summary[finding['type']].update(group)

        self.results['summary'] = {
            cat: counter.most_common(10) for cat, counter in summary.items()
        }


        print(termcolor.colored(("\n📊 Top recurring similar values by category: "), 'green'))
        for cat, values in self.results['summary'].items():
            print(termcolor.colored((f"\n  >  {cat.capitalize()}: "), 'cyan'))
            for val, count in values:
                print(termcolor.colored((f"  -  {val[:60]}{'...' if len(val) > 60 else ''}  ({count} times)"), 'green'))


    def generate_report(self, output_filename=None, output_format="json"):
        """Generating report"""

        #Creates hash of data source
        hash_input = self.file_path.encode('utf-8')
        source_hash = hashlib.md5(hash_input).hexdigest()[:8] #short hash for filename
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        #Default filename generation
        if not output_filename:
            filename = f"report_{source_hash}_{timestamp}.{output_format}"
        
        else:
            filename = f"{output_filename}.{output_format}"

        
        output_path = os.path.join(REPORT_DIR, filename)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        report = {
            "analysis_date": self.results.get("analysis_date", str(datetime.now())),
            "data_source": self.file_path,
            "findings": self.results.get("findings", []),
            "summary": self.results.get("summary", {})
        }

        #Saving the report in user requested format
        if output_format == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

        elif output_format == "txt":
            with open(output_path, "w", encoding="utf-8") as f:
                for category in self.results["findings"]:
                    f.write(f" 📁 {category['type'].capitalize()} Values:\n")

                    for val in category['exact_duplicates']:
                        f.write(f"  🔁  Exact Duplicates: {len(category['exact_duplicates'])} : {val}\n")

                    for val in category['similar_patterns']:
                        f.write(f"  🔍  Similar Groups: {len(category['similar_patterns'])} : {val}\n")

                    f.write("\n")

        elif output_format == "xml":
            xml_report = dicttoxml.dicttoxml(report, custom_root='report', attr_type=False)
            with open(output_path, "w", encoding="utf-8") as f:
                #Write human-readable summary
                for category in self.results["findings"]:
                    f.write(f" 📁 {category['type'].capitalize()} Values:\n")

                    for val in category['exact_duplicates']:
                        f.write(f"  🔁  Exact Duplicates: {len(category['exact_duplicates'])} : {val}\n")

                    for val in category['similar_patterns']:
                        f.write(f"  🔍  Similar Groups: {len(category['similar_patterns'])} : {val}\n")

                f.write("\n===== Full XML Report =====\n")
                f.write(xml_report.decode("utf-8")) #Convert bytes to string before writing

        print(termcolor.colored((f"\n💾 Report saved to {output_path}"), 'green'))


def parse_args():
    """CLI setup"""

    parser = argparse.ArgumentParser(
        description=termcolor.colored(("Ultimate Data Duplication and Similarity Scanner"), 'cyan'),
        add_help=False #Disables default help option
    )

    parser.add_argument("source", nargs="?", help="Insert data source Path or URL")
    parser.add_argument("--fast", action="store_true", help="Enable fast scanning (skips detailed similarity matching)")
    parser.add_argument("--detailed", action="store_true", help="Enable detailed scanning with deep similarity checks")
    parser.add_argument("--chunksize", type=int, help="Specify custom chunk size (default: 50000)")
    parser.add_argument("--type", choices=["csv", "xlsx"], help="Specify file type (csv or xlsx)")
    parser.add_argument("-C", action="store_const", const="csv", dest="type", help="Shortcut for --type=csv")
    parser.add_argument("-X", action="store_const", const="xlsx", dest="type", help="Shortcut for --type=xlsx")
    parser.add_argument("--version", action="store_true", help="Show tool version and exit")
    parser.add_argument("--help", action="store_true", help="Show options")
    parser.add_argument("-o", "--output", type=str, help="Output file name (default: JSON), it's suggested to use default report generation")
    parser.add_argument("--output-format", choices=["json", "txt", "xml"], default="json", help="Specify output format (json, txt, xml)")
    parser.add_argument("--debug", action="store_true", help="Debugging mode, prints full traceback and internal logs")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode, suppresses all non-essential output (emojis, banners, summaries, etc.)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode, shows more detailed steps during scan")
    parser.add_argument("--messy", action="store_true", help="Enable preprocessing for messy CSV file")
    

    args = parser.parse_args()

    if args.version:
        print(termcolor.colored(("🔢 Version: 1.0 - Mauzalyzer - Created by mauzware"), 'cyan', attrs=["bold"]))
        print(termcolor.colored(("🎨 Github: https://github.com/mauzware"), 'cyan'))
        sys.exit(0)

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    if args.quiet:
        logging.disable(logging.CRITICAL)

    if args.fast and args.detailed:
        print(termcolor.colored(("⚠️ You can't use both --fast nad --detailed at the same time! Choose one option."), 'red'))

    if args.help or not args.source:
        print(termcolor.colored(("🧪 Mauzalyzer - Created by mauzware\n"), 'cyan', attrs=["bold"]))
        print("📚 Usage: python3 mauzalyzer.py [OPTIONS] source\n")

        print("COMMANDS: ")
        print(" -h, --help".ljust(35), "Show this help option")
        print("     --version".ljust(35), "Show tool version\n")

        print("OPTIONS: ")
        for action in parser._actions:
            if not action.option_strings:
                continue

            if "--help" in action.option_strings or "--version" in action.option_strings:
                continue

            option_line = " " + " / ".join(action.option_strings)
            print(option_line.ljust(35), action.help)

        print("\nREQUIRED ARGUMENT: ")
        print("  source".ljust(35), "File path or URL to scan")

        sys.exit(0)

    return args


def print_logo():
    neon_colors = ['green', 'yellow', 'blue', 'magenta', 'cyan']
    logo = r"""
         __    __     ______     __  __     ______     ______     __         __  __     ______     ______     ______    
        /\ "-./  \   /\  __ \   /\ \/\ \   /\___  \   /\  __ \   /\ \       /\ \_\ \   /\___  \   /\  ___\   /\  == \   
        \ \ \-./\ \  \ \  __ \  \ \ \_\ \  \/_/  /__  \ \  __ \  \ \ \____  \ \____ \  \/_/  /__  \ \  __\   \ \  __<   
         \ \_\ \ \_\  \ \_\ \_\  \ \_____\   /\_____\  \ \_\ \_\  \ \_____\  \/\_____\   /\_____\  \ \_____\  \ \_\ \_\ 
          \/_/  \/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/   \/_____/   \/_____/   \/_/ /_/ 
                                                                          Ultimate Duplicate & Similarity Analyzer v1.0
                                                                                            https://github.com/mauzware
                                                                                                    Created by mauzware                                                                                                            
    """
    
    lines = logo.splitlines()
    for i, line in enumerate(lines):
        print(termcolor.colored(line, neon_colors[i % len(neon_colors)]))


# BONUS: Optional Header Row Removal (for advanced users), details are below.

"""

This code helps remove repeated or stray header rows inside messy CSVs
(usually when a report was exported from Excel or multiple tables were merged).

❗️ When to use:
- You scanned a file and noticed weird duplicated values like "type" or "sale_date"
- You know your file includes repeated headers (you may have seen them in Excel file when you opened it)

📋 Instructions:
1. Below this comment, you'll see a method called 'remove_headers(df)', edit the list 'known_headers' to include any words you want to treat as "header rows".
2. In regards to editing 'known_headers', you can add more values or remove some, it's completely on you.
3. Go to method 'scan_csv()' in the code, you'll see '#df = remove_headers(df)', just remove # and that's it, voila removed headers are implemented.

Example:
def scan_csv(self, similarity_threshold=85):
    try:
        df = self.safe_read_csv(file_path)
        #df = remove_headers(df) <-- Here, simply delete # and its done

"""

def remove_headers(df):
    known_headers = ['type', 'total_amount', 'sale_date'] # <-- You edit this, replace values in '' with your specific values from Excel header
    return df[~df.apply(lambda row: any(str(cell).lower() in known_headers for cell in row), axis=1)]


if __name__=="__main__":

    print_logo()
    args = parse_args()
    similarity_threshold = 85
    chunksize = args.chunksize if args.chunksize else 50000

    if args.fast:
        similarity_threshold = 70
        chunksize = min(chunksize, 20000)

    elif args.detailed:
        similarity_threshold = 95
        chunksize = max(chunksize, 75000)

    mauzalyzer = Mauzalyzer(
        file_path=args.source,
        file_type=args.type.lower() if args.type else None, 
        chunksize=args.chunksize or 50000,
        fast_mode=args.fast, 
        detailed_mode=args.detailed,
        messy=args.messy
    )

    mauzalyzer.scan_data(similarity_threshold=similarity_threshold)
    mauzalyzer.summarize_similar_patterns()
    mauzalyzer.generate_report(output_filename=args.output, output_format=args.output_format)

        

        