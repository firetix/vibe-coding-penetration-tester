# VibePenTester Web UI

A simple web interface for the VibePenTester security scanner.

## Features

- Clean, modern interface for web application security testing
- Real-time progress monitoring
- Beautiful security report generation
- Mark-down formatted reports with syntax highlighting
- Download reports for offline viewing

## Requirements

- Python 3.8 or higher
- Dependencies listed in requirements.txt

## Installation

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

2. Make sure you have a working installation of Playwright:

```bash
playwright install
```

## Running the Web UI

1. Start the web server:

```bash
python web_ui.py
```

2. Open your browser and navigate to:

```
http://localhost:5050
```

3. Enter the target URL and click "Start Security Scan"

## Usage

1. Enter a valid URL to test (e.g., `https://example.com`)
2. Wait for the scan to complete while monitoring progress
3. View the security report with found vulnerabilities
4. Download the report or start a new scan

## Screenshots

![VibePenTester Web UI](docs/webui-screenshot.png)

## Notes

- The scanner should be used only on websites you have permission to test
- Some scans may take several minutes depending on the target website
- For best results, use a recent version of Chrome, Firefox, or Safari