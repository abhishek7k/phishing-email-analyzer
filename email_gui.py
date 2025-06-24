import email
from email import policy
import re
import hashlib
import base64
import requests
import sys
import os
from urllib.parse import urlparse
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import threading
import queue # For thread-safe communication

# --- Configuration ---

VIRUSTOTAL_API_KEY = "3158d577d20761eb2b83202848f70882db35413c1ab1b9ea2edb2838c7915f78"

# --- Helper Functions ---

def extract_urls(text):
    """Extracts URLs from text using a simple regex."""
    urls = re.findall(r'http[s]?://\S+', text)
    return list(set(urls))

def get_domain_from_url(url):
    """Extracts the domain from a URL."""
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc
    except Exception:
        return None

def is_download_link(url):
    """Checks if a URL is likely a direct file download link based on common extensions."""
    malicious_extensions = ['.exe', '.zip', '.rar', '.7z', '.scr', '.iso', '.img', '.msi',
                            '.hta', '.js', '.vbs', '.wsf', '.jar', '.pdf', # PDFs can contain malicious scripts
                            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'] # Office docs with macros
    parsed_url = urlparse(url)
    path = parsed_url.path
    for ext in malicious_extensions:
        if path.lower().endswith(ext):
            return True
    return False

def check_url_with_virustotal(url):
    """Checks a URL's reputation using VirusTotal API."""
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return "API_KEY_MISSING", None

    # VirusTotal API v3 requires URL to be base64 encoded and then cleaned
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(vt_url, headers=headers)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        if data and data.get('data'):
            attributes = data['data'].get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            undetected_count = last_analysis_stats.get('undetected', 0)
            
            if malicious_count > 0:
                return "MALICIOUS", {"malicious": malicious_count, "suspicious": suspicious_count, "undetected": undetected_count}
            elif suspicious_count > 0:
                return "SUSPICIOUS", {"malicious": malicious_count, "suspicious": suspicious_count, "undetected": undetected_count}
            else:
                return "CLEAN", {"malicious": malicious_count, "suspicious": suspicious_count, "undetected": undetected_count}
        return "UNKNOWN", None # No data or unexpected response structure

    except requests.exceptions.HTTPError as errh:
        if errh.response.status_code == 404:
            return "NOT_SCANNED_YET", None # URL not found in VirusTotal's database
        elif errh.response.status_code == 429: # Too Many Requests
            return "RATE_LIMITED", None
        else:
            return f"HTTP_ERROR: {errh.response.status_code}", None
    except requests.exceptions.ConnectionError as errc:
        return f"CONNECTION_ERROR: {errc}", None
    except requests.exceptions.Timeout as errt:
        return f"TIMEOUT_ERROR: {errt}", None
    except requests.exceptions.RequestException as err:
        return f"REQUEST_ERROR: {err}", None
    except Exception as e:
        return f"GENERIC_ERROR: {e}", None

def check_hash_with_virustotal(file_hash):
    """Checks a file hash's reputation using VirusTotal API."""
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return "API_KEY_MISSING", None

    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(vt_url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data and data.get('data'):
            attributes = data['data'].get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            
            if malicious_count > 0:
                return "MALICIOUS", {"malicious": malicious_count, "suspicious": suspicious_count}
            elif suspicious_count > 0:
                return "SUSPICIOUS", {"malicious": malicious_count, "suspicious": suspicious_count}
            else:
                return "CLEAN", {"malicious": malicious_count, "suspicious": suspicious_count}
        return "UNKNOWN", None

    except requests.exceptions.HTTPError as errh:
        if errh.response.status_code == 404:
            return "NOT_FOUND", None # Hash not found in VT database
        elif errh.response.status_code == 429:
            return "RATE_LIMITED", None
        else:
            return f"HTTP_ERROR: {errh.response.status_code}", None
    except requests.exceptions.RequestException as err:
        return f"REQUEST_ERROR: {err}", None
    except Exception as e:
        return f"GENERIC_ERROR: {e}", None

# --- Phishing Analyzer Class (Modified for GUI output) ---

class PhishingAnalyzer:
    def __init__(self, email_input, is_file=False):
        self.email_input = email_input
        self.is_file = is_file
        self.msg = None
        self.analysis_results = {
            "Errors": [],
            "Risk Score": 0,
            "Header Analysis": [],
            "Body Content Analysis": [],
            "Attachment Analysis": [],
            "Extracted URLs": []
        }
        self._parse_email()

    def _parse_email(self):
        """Parses the email content from a file or string."""
        try:
            if self.is_file:
                with open(self.email_input, 'rb') as f:
                    self.msg = email.message_from_bytes(f.read(), policy=policy.default)
            else:
                self.msg = email.message_from_string(self.email_input, policy=policy.default)
        except Exception as e:
            self.analysis_results["Errors"].append(f"Failed to parse email: {e}")
            self.msg = None

    def analyze_headers(self):
        """Performs header-based analysis for phishing indicators."""
        if not self.msg:
            return

        from_header = self.msg.get("From", "N/A")
        return_path = self.msg.get("Return-Path", "N/A")
        subject = self.msg.get("Subject", "N/A")

        self.analysis_results["Header Analysis"].append(f"From: {from_header}")
        self.analysis_results["Header Analysis"].append(f"Subject: {subject}")
        self.analysis_results["Header Analysis"].append(f"Return-Path: {return_path}")

        from_domain = get_domain_from_url(from_header)
        return_path_domain = get_domain_from_url(return_path)

        if from_domain and return_path_domain and from_domain.lower() != return_path_domain.lower():
            self.analysis_results["Header Analysis"].append(f"  [FLAG] Potential Spoofing: 'From' domain ({from_domain}) mismatch with 'Return-Path' domain ({return_path_domain}).")
            self.analysis_results["Risk Score"] += 20

        self.analysis_results["Header Analysis"].append("  [INFO] DMARC/SPF/DKIM checks not implemented in this simplified version. These would provide stronger authenticity verification.")

    def analyze_body(self):
        """Performs body content analysis for phishing indicators."""
        if not self.msg:
            return

        email_body_text = ""
        email_body_html = ""

        for part in self.msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))

            if ctype == 'text/plain' and 'attachment' not in cdispo:
                email_body_text = part.get_payload(decode=True).decode(errors='ignore')
            elif ctype == 'text/html' and 'attachment' not in cdispo:
                email_body_html = part.get_payload(decode=True).decode(errors='ignore')

        main_body_content = email_body_text if email_body_text else email_body_html

        self.analysis_results["Body Content Analysis"].append(f"Email Body (Excerpt): {main_body_content[:500]}..." if len(main_body_content) > 500 else main_body_content)

        urls = extract_urls(main_body_content)
        if urls:
            self.analysis_results["Extracted URLs"] = urls
            self.analysis_results["Body Content Analysis"].append("\n--- URL Analysis ---")
            for url in urls:
                self.analysis_results["Body Content Analysis"].append(f"  URL Found: {url}")
                domain = get_domain_from_url(url)
                if domain:
                    self.analysis_results["Body Content Analysis"].append(f"    Domain: {domain}")

                vt_status, vt_data = check_url_with_virustotal(url)
                if vt_status == "MALICIOUS":
                    self.analysis_results["Body Content Analysis"].append(f"    [DANGER] VirusTotal: MALICIOUS (Detections: {vt_data['malicious']})")
                    self.analysis_results["Risk Score"] += 50
                elif vt_status == "SUSPICIOUS":
                    self.analysis_results["Body Content Analysis"].append(f"    [WARNING] VirusTotal: SUSPICIOUS (Detections: {vt_data['suspicious']})")
                    self.analysis_results["Risk Score"] += 30
                elif vt_status == "CLEAN":
                    self.analysis_results["Body Content Analysis"].append("    [INFO] VirusTotal: CLEAN")
                elif vt_status == "NOT_SCANNED_YET":
                    self.analysis_results["Body Content Analysis"].append("    [INFO] VirusTotal: Not previously scanned. (Consider submitting)")
                elif vt_status == "RATE_LIMITED":
                    self.analysis_results["Body Content Analysis"].append("    [WARNING] VirusTotal: Rate limit hit. Cannot check this URL.")
                    self.analysis_results["Risk Score"] += 5 # Minor flag for unverified status
                elif vt_status == "API_KEY_MISSING":
                    self.analysis_results["Body Content Analysis"].append("    [ERROR] VirusTotal API Key Missing/Invalid. Cannot check URL reputation.")
                else:
                    self.analysis_results["Body Content Analysis"].append(f"    [ERROR] VirusTotal: {vt_status}")

                if is_download_link(url):
                    self.analysis_results["Body Content Analysis"].append(f"    [FLAG] Appears to be a direct file download link. Exercise caution.")
                    self.analysis_results["Risk Score"] += 25
        else:
            self.analysis_results["Body Content Analysis"].append("No URLs found in the email body.")

        common_typos = ["recieve", "wierd", "untill", "succesfull", "definately", "securty"]
        for typo in common_typos:
            if re.search(r'\b' + re.escape(typo) + r'\b', main_body_content.lower()):
                self.analysis_results["Body Content Analysis"].append(f"  [FLAG] Potential typo detected: '{typo}'. Phishers often make grammatical errors.")
                self.analysis_results["Risk Score"] += 5

        urgency_keywords = ["immediate action required", "account suspended", "your account will be closed",
                            "urgent", "expire", "verify your account", "security alert", "click here to avoid"]
        for keyword in urgency_keywords:
            if keyword in main_body_content.lower():
                self.analysis_results["Body Content Analysis"].append(f"  [FLAG] Urgency/Threatening keyword detected: '{keyword}'.")
                self.analysis_results["Risk Score"] += 10

        generic_greetings = ["dear customer", "dear user", "valued client", "attention", "dear sir/madam"]
        if any(re.search(r'\b' + re.escape(g) + r'\b', main_body_content.lower()) for g in generic_greetings):
            self.analysis_results["Body Content Analysis"].append("  [FLAG] Generic greeting detected. Legitimate organizations often personalize.")
            self.analysis_results["Risk Score"] += 5

        sensitive_info_keywords = ["confirm password", "update banking details", "social security number",
                                   "credit card number", "login credentials", "verify your identity", "otp"]
        if any(re.search(r'\b' + re.escape(k) + r'\b', main_body_content.lower()) for k in sensitive_info_keywords):
            self.analysis_results["Body Content Analysis"].append("  [DANGER] Request for sensitive information detected. BE EXTREMELY CAREFUL.")
            self.analysis_results["Risk Score"] += 30

    def analyze_attachments(self):
        """Analyzes email attachments for potential threats."""
        if not self.msg:
            return

        attachments_found = False
        self.analysis_results["Attachment Analysis"].append("--- Attachments ---")

        for part in self.msg.walk():
            filename = part.get_filename()
            if filename:
                attachments_found = True
                content_type = part.get_content_type()
                self.analysis_results["Attachment Analysis"].append(f"  Attachment Found: {filename} (Type: {content_type})")

                try:
                    attachment_payload = part.get_payload(decode=True)
                except Exception as e:
                    self.analysis_results["Attachment Analysis"].append(f"    [ERROR] Could not decode attachment payload: {e}")
                    attachment_payload = None

                if attachment_payload:
                    attachment_hash = hashlib.sha256(attachment_payload).hexdigest()
                    self.analysis_results["Attachment Analysis"].append(f"    SHA256 Hash: {attachment_hash}")

                    vt_status, vt_data = check_hash_with_virustotal(attachment_hash)
                    if vt_status == "MALICIOUS":
                        self.analysis_results["Attachment Analysis"].append(f"    [DANGER] VirusTotal: MALICIOUS (Detections: {vt_data['malicious']})")
                        self.analysis_results["Risk Score"] += 70
                    elif vt_status == "SUSPICIOUS":
                        self.analysis_results["Attachment Analysis"].append(f"    [WARNING] VirusTotal: SUSPICIOUS (Detections: {vt_data['suspicious']})")
                        self.analysis_results["Risk Score"] += 40
                    elif vt_status == "CLEAN":
                        self.analysis_results["Attachment Analysis"].append("    [INFO] VirusTotal: CLEAN")
                    elif vt_status == "NOT_FOUND":
                        self.analysis_results["Attachment Analysis"].append("    [INFO] VirusTotal: Hash not found in database. (May be a new or rare file)")
                    elif vt_status == "RATE_LIMITED":
                        self.analysis_results["Attachment Analysis"].append("    [WARNING] VirusTotal: Rate limit hit. Cannot check this hash.")
                        self.analysis_results["Risk Score"] += 5 # Minor flag for unverified status
                    elif vt_status == "API_KEY_MISSING":
                        self.analysis_results["Attachment Analysis"].append("    [ERROR] VirusTotal API Key Missing/Invalid. Cannot check attachment hash.")
                    else:
                        self.analysis_results["Attachment Analysis"].append(f"    [ERROR] VirusTotal: {vt_status}")
                else:
                    self.analysis_results["Attachment Analysis"].append("    [INFO] No payload for hash calculation (e.g., inline image without separate file).")

                if '.' in filename:
                    ext = filename.rsplit('.', 1)[1].lower()
                    if ext in ['exe', 'bat', 'scr', 'cmd', 'ps1', 'vbs', 'js', 'hta', 'iso', 'img', 'lnk', 'zip', 'rar', '7z']:
                        self.analysis_results["Attachment Analysis"].append(f"    [FLAG] Potentially dangerous file extension '{ext}'.")
                        self.analysis_results["Risk Score"] += 40
                    elif ext in ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'] and "macro" in content_type:
                         self.analysis_results["Attachment Analysis"].append(f"    [FLAG] Office/PDF file with potential for macros/scripts ({content_type}).")
                         self.analysis_results["Risk Score"] += 30

        if not attachments_found:
            self.analysis_results["Attachment Analysis"].append("  No attachments found.")

    def run_analysis(self):
        """Executes all analysis steps and returns the formatted report."""
        self.analyze_headers()
        self.analyze_body()
        self.analyze_attachments()
        return self._format_report()

    def _format_report(self):
        """Formats the analysis results into a human-readable string."""
        report_lines = []
        report_lines.append("="*70)
        report_lines.append("          PHISHING/SPAM EMAIL ANALYSIS REPORT")
        report_lines.append("="*70)

        total_risk_score = self.analysis_results["Risk Score"]
        risk_level = "LOW"
        if total_risk_score >= 80:
            risk_level = "CRITICAL - HIGHLY LIKELY PHISHING/MALICIOUS"
        elif total_risk_score >= 50:
            risk_level = "HIGH - LIKELY PHISHING/SPAM"
        elif total_risk_score >= 20:
            risk_level = "MEDIUM - SUSPICIOUS"
        else:
            risk_level = "LOW - APPEARS LEGITIMATE (EXERCISE CAUTION)"

        report_lines.append(f"\nOverall Risk Score: {total_risk_score}")
        report_lines.append(f"Calculated Risk Level: {risk_level}")

        report_lines.append("\n" + "-"*30 + " Summary of Findings " + "-"*30)
        
        if self.analysis_results["Errors"]:
            report_lines.append("\n--- Errors ---")
            for error in self.analysis_results["Errors"]:
                report_lines.append(f"- {error}")

        report_lines.append("\n--- Header Analysis ---")
        if self.analysis_results["Header Analysis"]:
            for item in self.analysis_results["Header Analysis"]:
                report_lines.append(f"- {item}")
        else:
            report_lines.append("- No significant header findings.")

        report_lines.append("\n--- Body Content Analysis ---")
        if self.analysis_results["Body Content Analysis"]:
            for item in self.analysis_results["Body Content Analysis"]:
                report_lines.append(f"- {item}")
        else:
            report_lines.append("- No significant body content findings.")

        report_lines.append("\n--- Attachment Analysis ---")
        if self.analysis_results["Attachment Analysis"]:
            for item in self.analysis_results["Attachment Analysis"]:
                report_lines.append(f"- {item}")
        else:
            report_lines.append("- No attachments found or analyzed.")

        report_lines.append("\n" + "="*70)
        report_lines.append("Disclaimer: This tool provides an indicative analysis. Always apply human judgment.")
        report_lines.append("="*70)
        
        return "\n".join(report_lines)

# --- GUI Application ---

class PhishingAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Phishing Email Analyzer")
        master.geometry("1000x800")
        master.configure(bg="#f0f0f0") # Light grey background

        self.file_path = tk.StringVar()
        self.status_message = tk.StringVar()
        self.status_message.set("Ready to analyze email.")

        # --- Frames ---
        self.input_frame = tk.Frame(master, padx=10, pady=10, bg="#ffffff", bd=2, relief="groove")
        self.input_frame.pack(fill="x", padx=10, pady=10)

        self.output_frame = tk.Frame(master, padx=10, pady=10, bg="#ffffff", bd=2, relief="groove")
        self.output_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Input Widgets ---
        tk.Label(self.input_frame, text="Select .eml file or paste raw email:", font=("Arial", 12, "bold"), bg="#ffffff").pack(pady=5)

        # File path entry and browse/remove buttons
        file_row = tk.Frame(self.input_frame, bg="#ffffff")
        file_row.pack(fill="x", pady=5)
        self.file_entry = tk.Entry(file_row, textvariable=self.file_path, width=70, state="readonly", font=("Arial", 10), bd=1, relief="solid")
        self.file_entry.pack(side="left", padx=(0, 5), expand=True, fill="x")
        tk.Button(file_row, text="Browse .eml", command=self.browse_file, font=("Arial", 10, "bold"), bg="#4CAF50", fg="white", activebackground="#45a049", relief="raised", bd=2).pack(side="left")
        # New "Remove EML" button
        tk.Button(file_row, text="Remove EML", command=self.clear_file_path, font=("Arial", 10), bg="#FF4C4C", fg="white", activebackground="#CC3333", relief="raised", bd=2).pack(side="left", padx=(5, 0))


        # Raw email text input
        raw_email_label_frame = tk.Frame(self.input_frame, bg="#ffffff")
        raw_email_label_frame.pack(fill="x", pady=(10, 2))
        tk.Label(raw_email_label_frame, text="OR paste raw email text here:", font=("Arial", 10), bg="#ffffff").pack(side="left")
        # New "Clear Raw Email" button
        tk.Button(raw_email_label_frame, text="Clear Raw Email", command=self.clear_raw_email_text, font=("Arial", 10), bg="#FF4C4C", fg="white", activebackground="#CC3333", relief="raised", bd=2).pack(side="right")
        
        self.raw_email_text = scrolledtext.ScrolledText(self.input_frame, height=10, width=80, font=("Consolas", 10), bd=1, relief="solid", wrap="word", bg="#f8f8f8")
        self.raw_email_text.pack(fill="both", expand=True, pady=5) # Made resizable

        # Analyze Button
        tk.Button(self.input_frame, text="Analyze Email", command=self.start_analysis_thread, font=("Arial", 14, "bold"), bg="#008CBA", fg="white", activebackground="#007bb5", relief="raised", bd=3, padx=10, pady=5).pack(pady=10)

        # Status Label
        tk.Label(master, textvariable=self.status_message, font=("Arial", 10, "italic"), fg="#555555", bg="#f0f0f0").pack(pady=5)

        # --- Output Widgets ---
        tk.Label(self.output_frame, text="Analysis Report:", font=("Arial", 12, "bold"), bg="#ffffff").pack(pady=5)
        self.report_output = scrolledtext.ScrolledText(self.output_frame, font=("Consolas", 10), bg="#e9e9e9", fg="#333333", bd=1, relief="solid", wrap="word", state="disabled")
        self.report_output.pack(fill="both", expand=True, pady=5)

        # Queue for thread communication
        self.q = queue.Queue()
        self.master.after(100, self.process_queue) # Start checking the queue periodically


    def browse_file(self):
        """Opens a file dialog to select an .eml file."""
        filetypes = [("EML files", "*.eml"), ("All files", "*.*")]
        filepath = filedialog.askopenfilename(filetypes=filetypes)
        if filepath:
            self.file_path.set(filepath)
            self.raw_email_text.delete(1.0, tk.END) # Clear raw text if file selected
            self.status_message.set(f"Selected file: {os.path.basename(filepath)}")

    def clear_file_path(self):
        """Clears the selected .eml file path."""
        self.file_path.set("")
        self.status_message.set("EML file selection cleared.")
        self.report_output.config(state="normal")
        self.report_output.delete(1.0, tk.END)
        self.report_output.config(state="disabled")

    def clear_raw_email_text(self):
        """Clears the raw email text area."""
        self.raw_email_text.delete(1.0, tk.END)
        self.status_message.set("Raw email text cleared.")
        self.report_output.config(state="normal")
        self.report_output.delete(1.0, tk.END)
        self.report_output.config(state="disabled")

    def start_analysis_thread(self):
        """Starts the analysis in a separate thread to keep the GUI responsive."""
        email_content = None
        is_file = False

        if self.file_path.get():
            email_content = self.file_path.get()
            is_file = True
            if not os.path.exists(email_content):
                messagebox.showerror("Error", f"File not found: {email_content}")
                return
            # If EML file is selected, clear raw text to avoid ambiguity
            self.raw_email_text.delete(1.0, tk.END)
        else:
            email_content = self.raw_email_text.get(1.0, tk.END).strip()
            if not email_content:
                messagebox.showwarning("Input Missing", "Please select an .eml file or paste raw email text.")
                return
            # If raw text is used, clear EML file selection to avoid ambiguity
            self.file_path.set("")

        # Clear previous results via queue to ensure thread safety
        self.q.put(("clear_output", None))
        
        self.status_message.set("Analyzing email... This may take a moment due to VirusTotal API calls.")

        # Start the analysis in a new thread
        threading.Thread(target=self._run_analysis_in_thread, args=(email_content, is_file), daemon=True).start()

    def _run_analysis_in_thread(self, email_content, is_file):
        """Worker function for the analysis thread."""
        try:
            analyzer = PhishingAnalyzer(email_content, is_file)
            report = analyzer.run_analysis()
            self.q.put(("analysis_complete", report))
        except Exception as e:
            self.q.put(("error", f"An unexpected error occurred during analysis: {e}"))

    def process_queue(self):
        """Processes messages from the analysis thread queue."""
        try:
            while True:
                message_type, data = self.q.get_nowait()
                if message_type == "analysis_complete":
                    self.report_output.config(state="normal")
                    self.report_output.delete(1.0, tk.END)
                    self.report_output.insert(tk.END, data)
                    self.report_output.config(state="disabled")
                    self.status_message.set("Analysis complete.")
                elif message_type == "error":
                    messagebox.showerror("Analysis Error", data)
                    self.status_message.set("Analysis failed.")
                elif message_type == "clear_output":
                    self.report_output.config(state="normal")
                    self.report_output.delete(1.0, tk.END)
                    self.report_output.config(state="disabled")
                self.master.update_idletasks() # Update GUI
        except queue.Empty:
            pass # No messages in queue
        finally:
            self.master.after(100, self.process_queue) # Check again after 100ms

# --- Main Application Entry Point ---

def main():
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        messagebox.showwarning("API Key Missing", "Please replace 'YOUR_VIRUSTOTAL_API_KEY' in the script with your actual VirusTotal API key to enable full functionality.")
        
    root = tk.Tk()
    app = PhishingAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()