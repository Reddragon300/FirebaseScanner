# Firebase Scanner

Firebase Scanner is a Python script for analyzing Firebase usage in Android apps. It can be used to identify Firebase project names in an APK file or analyze a list of Firebase project names.

## Table of Contents

- [Firebase Scanner](#firebase-scanner)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Analyze Firebase Project Names](#analyze-firebase-project-names)
- [Dependencies](#dependencies)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Reddragon300/FirebaseScanner.git
```
2. Change Directory:
```bash
cd FirebaseScanner
```
3. Install the requirements:
```bash
pip3 install -r requirements.txt
```

# Usage

## Analyze an APK File
To analyze an APK file, run the following command:
```bash
python main.py --apk /path/to/your.apk
```

Replace `/path/to/your.apk` with the path to the APK file you want to analyze.

## Analyze Firebase Project Names

To analyze a list of Firebase project names, run the following command:
```bash
python main.py --projects project1,project2,project3
```

Replace `project1,project2,project3` with the comma-separated list of Firebase project names you want to analyze.

# Dependencies

APKTool (included in the `Dependencies` folder)
