Phishing Email Analyzer

A user-friendly desktop application built with Python and Tkinter for analyzing .eml email files and raw email text to detect common phishing and spam indicators. This tool integrates with the VirusTotal API to provide reputation checks for URLs and file attachments, helping users identify malicious content.

Table of Contents

Features

How it Works

Getting Started

Prerequisites

VirusTotal API Key

Installation

Running the Application

Usage

Risk Scoring Explained

Important Security Considerations

Future Enhancements

Contributing

License

Features

User-Friendly GUI: Intuitive interface built with Tkinter for easy interaction.

Email Input Options:

EML File Analysis: Browse and select .eml files for analysis.

Raw Email Text Input: Paste raw email content directly into a resizable text area.

Clear Input Management: Dedicated "Remove EML" and "Clear Raw Email" buttons for efficient workflow.

Header Analysis:

Checks for sender address spoofing (comparing From and Return-Path domains).

Displays From, Subject, and Return-Path headers.

Body Content Analysis:

Extracts and lists all URLs from the email body.

Detects common typos, grammatical errors, and suspicious phrasing.

Identifies urgency or threatening language.

Flags generic greetings (e.g., "Dear Customer").

Detects requests for sensitive information (e.g., passwords, banking details).

Flags potential direct file download links within the email body.

Attachment Analysis:

Lists detected attachments and their content types.

Calculates SHA256 hashes of attachments.

Flags potentially dangerous file extensions (e.g., .exe, .zip, .pdf with scripts, .doc with macros).

VirusTotal Integration:

URL Reputation Check: Submits extracted URLs to VirusTotal for malware/phishing detection.

Attachment Hash Check: Submits attachment hashes to VirusTotal to check for known malicious files.

Risk Scoring: Assigns a cumulative risk score based on detected phishing indicators, classifying the email as LOW, MEDIUM, HIGH, or CRITICAL risk.

Asynchronous Processing: Runs analysis in a separate thread to keep the GUI responsive during API calls.

Detailed Report: Generates a comprehensive, human-readable report summarizing all findings directly in the application.

How it Works

The analyzer parses the raw structure of an email, including its headers, body (both plain text and HTML), and attachments. It then applies a series of heuristic rules and integrates with the VirusTotal API to identify suspicious patterns, malicious links, and known bad files. A cumulative risk score is calculated, which determines the overall risk level of the email.

Getting Started

Prerequisites

Python 3.x installed on your system.

requests Python library.

VirusTotal API Key

Obtain an API Key: Go to the VirusTotal website and sign up for a free account. Once logged in, you can find your API key in your profile settings.

Update the Code: Open the phishing_analyzer_gui.py file. Locate the line:

VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"



Replace "YOUR_VIRUSTOTAL_API_KEY" with the actual API key you obtained from VirusTotal.

Installation

Clone the repository:

git clone https://github.com/your-username/phishing-email-analyzer.git
cd phishing-email-analyzer



(Replace your-username with your actual GitHub username if you create a repository).

Install dependencies:

pip install requests



Running the Application

After setting up the API key and installing dependencies, you can run the application from your terminal:

python phishing_analyzer_gui.py



Usage

Select EML File: Click the "Browse .eml" button and choose an .eml file from your computer.

Paste Raw Email: Alternatively, copy the full raw content of an email (e.g., "Show original" from Gmail) and paste it into the "OR paste raw email text here:" box.

Clear Inputs: Use the "Remove EML" or "Clear Raw Email" buttons to clear the respective input fields before analyzing a new email.

Analyze: Click the "Analyze Email" button. The analysis report will appear in the "Analysis Report" text area below. The status bar at the bottom will provide real-time updates.

Risk Scoring Explained

The risk score is a heuristic-based system designed to provide an indicative measure of how likely an email is to be phishing or spam. Each detected suspicious indicator contributes a specific number of points to the Overall Risk Score.

Example Scoring:

[FLAG] Potential Spoofing: +20 points

[DANGER] VirusTotal: MALICIOUS (URL): +50 points

[DANGER] VirusTotal: MALICIOUS (Attachment Hash): +70 points

[FLAG] Appears to be a direct file download link: +25 points

[DANGER] Request for sensitive information detected: +30 points

[FLAG] Potentially dangerous file extension: +40 points

[FLAG] Urgency/Threatening keyword detected: +10 points

...and so on.

Risk Levels:

LOW (Score < 20): Appears legitimate based on checks.

MEDIUM (Score 20-49): Suspicious elements detected.

HIGH (Score 50-79): Likely phishing or spam.

CRITICAL (Score >= 80): Highly likely phishing or malicious.

A higher score indicates more numerous or more severe suspicious indicators.

Important Security Considerations

VirusTotal API Usage: When URLs or file hashes are sent to VirusTotal, they are processed by VirusTotal's public analysis systems. Do not use this tool with highly confidential or sensitive email content/attachments that you do not wish to be publicly analyzed by VirusTotal.

Tool Limitations: This tool provides an indicative analysis based on common phishing patterns and VirusTotal data. It is not a substitute for comprehensive security solutions or expert human analysis. Always exercise caution with suspicious emails.

Future Enhancements

DMARC, SPF, DKIM Verification: Implement checks for email authentication records for more robust sender verification.

Advanced URL Analysis: Include detection for URL redirection chains, homograph attacks (visually similar characters), and domain squatting.

Enhanced NLP for Content: Utilize more sophisticated Natural Language Processing libraries (e.g., spaCy) for deeper contextual analysis of email body text.

Image Analysis: Implement image processing to detect embedded malicious QR codes or visually misleading elements.

Logging: Add robust logging functionality for analysis history and debugging.

Configuration File: Allow API keys and thresholds to be configured via a separate configuration file.

Export Report: Add functionality to save the analysis report to a file (e.g., PDF, TXT).

Contributing

Feel free to fork this repository, open issues, and submit pull requests. Any contributions to improve the analyzer are welcome!
