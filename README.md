# PortSpy - Your Network's Silent Guardian 🛡️

Welcome to **PortSpy**, a fast and efficient multi-threaded port scanner designed for developers, system administrators, and security enthusiasts. Whether you need to audit your own network or identify potential vulnerabilities, PortSpy makes it easy to detect open ports, operating systems, and service banners—all while keeping things fast and lightweight.

## What is PortSpy?
PortSpy is a tool designed to help you:
- 🔍 **Scan open ports** on single or multiple IP addresses.
- 🕵️ **Identify running services** using banner grabbing.
- 🖥️ **Detect operating systems** using network packet analysis.
- 🔐 **Look up CVE vulnerabilities** (mocked, but extendable for real-time data).
- 📄 **Generate comprehensive reports** in CSV, JSON, or PDF formats.

---

## 🚀 Getting Started

Follow these steps to set up PortSpy and get scanning in no time:

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/PortSpy.git
cd PortSpy
```

### 2. Install the Dependencies
PortSpy relies on a few Python libraries. Install them using:
```bash
pip install -r requirements.txt
```

Main libraries include:
- **scapy**: For advanced packet crafting and OS detection.
- **pythonping**: For checking host availability.
- **fpdf**: To create PDF reports.

### 3. Run PortSpy
Once everything is installed, simply run:
```bash
python scanner.py
```

---

## ⚙️ How to Use PortSpy

PortSpy offers both **single IP scanning** and **IP range scanning**, making it versatile for different use cases.

### Scanning a Single IP
1. Run PortSpy:
   ```bash
   python scanner.py
   ```
2. Choose the scan mode:
   - **Quick Scan**: Covers ports 1-1024.
   - **Comprehensive Scan**: Scans all available ports (1-65535).
3. Enter the target IP address to scan.
4. Review the results, including open ports, OS information, service banners, and potential vulnerabilities.

### Scanning an IP Range
1. After starting PortSpy, select the option to scan an IP range.
2. Enter the start and end IP addresses (e.g., `192.168.1.1` to `192.168.1.100`).
3. PortSpy will automatically detect live hosts, scan their ports, and display the results.

---

## 💾 Saving Scan Results

Once the scan is complete, PortSpy allows you to save the results for future reference. You can choose from the following formats:
- **CSV**: For spreadsheet-friendly data.
- **JSON**: For easily-parsed structured data.
- **PDF**: For professional-grade reports.

PortSpy will prompt you to save the results at the end of each scan.

---

## Key Features

- **Multi-threaded Port Scanning**: Scan multiple ports simultaneously for fast results.
- **OS Detection**: Identifies the target operating system based on network responses.
- **Banner Grabbing**: Retrieves service information from open ports.
- **CVE Vulnerability Lookup**: Checks known vulnerabilities based on service version (mock implementation, extendable).
- **Host Availability Check**: Ensures the target host is alive before performing a scan.
- **Progress Indicator**: Provides real-time feedback on scan progress.
- **Report Generation**: Export your scan results in CSV, JSON, or PDF formats.

---

## ⚙️ Customization

PortSpy is flexible! Here’s how you can adjust it to fit your specific needs:
- **Service Detection**: The `common_ports` dictionary can be easily updated with additional ports and services.
- **CVE Lookup**: Integrate with real-time APIs such as the [National Vulnerability Database (NVD)](https://nvd.nist.gov) to fetch live CVE data.
- **Adjust Thread Count and Timeout**: Change the number of threads or timeouts in the script to balance performance with network load.

---

## 🔌 How to Add Real-Time CVE API Integration

Currently, PortSpy uses a mock CVE vulnerability lookup for demonstration purposes. To integrate **real-time CVE data** using the NVD API or any other vulnerability API, follow these steps:

### Step 1: Get an API Key

To access CVE data, you’ll need an API key from a vulnerability database. Here are a few options:
- [NVD API](https://nvd.nist.gov/developers): Sign up to get an API key for accessing the National Vulnerability Database.

### Step 2: Update the CVE Lookup Function

In the `scanner.py` file, replace the mock **`cve_vulnerability_lookup`** function with one that fetches real CVE data.

Here’s an example using the NVD API:

```python
import requests

def cve_vulnerability_lookup(service, version):
    api_key = "YOUR_NVD_API_KEY"  # Replace with your API key
    headers = {
        "apiKey": api_key,
        "Content-Type": "application/json"
    }
    query = f"{service} {version}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={query}"
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data.get("result", {}).get("CVE_Items"):
                # Return the first CVE found for simplicity
                cve = data["result"]["CVE_Items"][0]["cve"]["CVE_data_meta"]["ID"]
                description = data["result"]["CVE_Items"][0]["cve"]["description"]["description_data"][0]["value"]
                return f"{cve}: {description}"
            else:
                return "No known vulnerabilities found"
        else:
            return f"Error retrieving CVE data: {response.status_code}"
    except Exception as e:
        return f"Error retrieving CVE data: {str(e)}"
```

### Step 3: Install `requests` Library

Ensure you have the `requests` library installed to make API calls:

```bash
pip install requests
```

### Step 4: Test the Integration

After updating the function, run a scan and check if the CVE lookup returns real-time vulnerability data based on the service and version detected.

---

## Potential Limitations

- **OS Detection**: The TTL-based OS detection method may not always be accurate, especially for routers or network devices.
- **Network Security**: Some firewalls or intrusion detection systems (IDS) might block or filter your scanning attempts, affecting results.

---

## Contributing

Want to make PortSpy even better? Contributions are always welcome! Whether it's fixing a bug, adding a feature, or improving the documentation, we’d love to see your pull request.

Here’s how you can contribute:
1. **Fork the repository**.
2. **Create a feature branch**:
   ```bash
   git checkout -b feature-name
   ```
3. **Commit your changes**:
   ```bash
   git commit -m "Add feature"
   ```
4. **Push to the branch**:
   ```bash
   git push origin feature-name
   ```
5. **Open a pull request** and contribute to the project!

---

## License

PortSpy is licensed under the **MIT License**, giving you the freedom to use, modify, and distribute it as needed. See the `LICENSE` file for more details.

---

That's all you need to get started with **PortSpy**! We hope this tool makes it easier for you to manage and secure your network. If you have any feedback or suggestions, feel free to reach out or open an issue.
