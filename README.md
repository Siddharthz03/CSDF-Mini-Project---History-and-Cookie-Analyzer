# 🧪 CSDF Mini Project  
## **History & Cookie Analyzer + Safety Detection + Visualization**

### **Author:** Siddharth Zende (Siddzendeofficial03)
This project analyzes **Chrome browser history & cookies**, evaluates **safety risks**, and generates **CSV reports + visualizations** for cybersecurity and forensic investigation.

---

## ✅ **Project Features**

### 🔍 **1. Browser History Extraction**
- Reads Chrome **History** SQLite database  
- Converts Chrome timestamps to real date-time  
- Shows:
  - Top visited domains  
  - Recent visits  
  - Visit counts  
  - Timestamps  

### 🍪 **2. Cookie Extraction**
- Extracts cookies from Chrome’s `Cookies` database  
- Converts creation & expiry timestamps  
- Saves complete cookie dataset to CSV  

### 🔐 **3. Safety Risk Detection**
Detects unsafe / suspicious browsing using:

- **Suspicious TLDs** (xyz, top, cyou, click…)  
- **Phishing keywords** (login, verify, bank, secure…)  
- **Piracy keywords** (torrent, crack, keygen…)  
- **Adult content keywords**  

Generates:
- ✅ Risk Score  
- ✅ List of risky URLs  
- ✅ Status: SAFE, MODERATE RISK, HIGH RISK  

### 📊 **4. Visualization**
Automatically plots:
- **Top 8 most visited domains** (Bar chart)  
- **Browsing Safety Status** (Pie chart)  

### 📁 **5. Report Generation**
Exports:
- `browser_history_report.csv`  
- `browser_cookies_report.csv`  
into `/reports` folder.

---

## 📂 **Project Structure**
```
analyzer.py              → main project script  
tmp_dbs/                 → temporary copied Chrome DBs  
reports/                 → auto-generated CSV reports  
```

---

## 🛠️ **Requirements**

Install required Python libraries:
```bash
pip install pandas matplotlib argparse
```

---

## ▶️ **How to Run the Project**

Run with default settings:
```bash
python3 analyzer.py
```

Run with custom values:
```bash
python3 analyzer.py --top 10 --recent 20
```

### Arguments:
| Argument     | Description |
|--------------|-------------|
| `--top`      | Number of top domains to display |
| `--recent`   | Number of recent visits to show |

---

## 🔍 **How It Works Internally**

### ✅ 1. Locates Chrome profile path  
Supports macOS, Windows & Linux.

### ✅ 2. Safely copies history & cookie DBs  
Chrome locks original files — script works on safe copies.

### ✅ 3. Extracts data from SQLite databases
- `urls` table → history  
- `cookies` table → cookies  

### ✅ 4. Evaluates safety of URLs  
Checks for suspicious extensions, phishing, piracy & adult content.

### ✅ 5. Generates CSV & Charts

---

## ✅ **Output Example**

### ✅ Safety Report (Terminal)
```
========= USER SAFETY REPORT =========
Browsing Risk Score: 7
Overall Safety Status: HIGH RISK ❌

⚠️ Potentially Risky Sites Visited:
 - https://secure-login-bank.xyz
 - https://torrent-download.click
======================================
```

### ✅ CSV Files  
- `browser_history_report.csv`
- `browser_cookies_report.csv`

### ✅ Charts  
- Bar chart → top domains  
- Pie chart → safety evaluation  

---

## 🎯 **Project Purpose**
This CSDF mini-project helps in:
- Browser forensic investigation  
- Tracking user online behavior  
- Detecting phishing & unsafe browsing  
- Visualizing history patterns  
- Generating forensic-ready reports  

---

## 📧 Contact  
GitHub: **Siddzendeofficial03**
