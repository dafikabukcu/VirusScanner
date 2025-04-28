# Virus Scanner
A simple command-line virus scanner powered by the VirusTotal API. It uploads files, polls for analysis, and displays results with color-coded output.

## Features
- Uploads files to VirusTotal for scanning
- Supports large files (>32 MB) via special upload URL
- Displays detailed engine results with color-coded terminal output

## Installation & Setup
- Just get a free VirusTotal API
- Create a .env file and add:
    - VIRUSTOTAL_API_KEY=your_api_key
    - VIRUSTOTAL_API_URL=https://www.virustotal.com/api/v3/
- Creating an environment is always recommended, up to you though.

## Usage
`python virusScanner.py --malw [path to file]`
