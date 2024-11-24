Agentless Vulnerability and Network Scanner

This is a comprehensive tool designed to scan systems for potential vulnerabilities and network configurations without requiring any agent installation. It leverages a simple, yet powerful, user interface that allows users to quickly gather information about their operating system, scan for open ports, detect vulnerable services, and generate detailed reports.

Features
Basic System Information: Retrieve details about your operating system, available memory, CPU information, and more.
Open Ports Scan: Identify which ports are open on your local machine.
Service Vulnerability Scan: Scan for known vulnerabilities in the services running on your machine.
Download Reports: Export your scan results to a PDF report for documentation or further analysis.
Interactive Pie Chart: Visualize the number of vulnerabilities found with a dynamic pie chart, representing 'safe' versus 'vulnerable' services.
Technologies Used
PySide6: For building the graphical user interface (GUI).
psutil: To gather system information like memory, CPU, and disk usage.
nmap: For scanning open ports and detecting services running on your local machine.
requests: To search for known vulnerabilities in services from the National Vulnerability Database (NVD).
fpdf: To generate and download scan reports as PDFs.
Installation
Clone the repository to your local machine:

bash
Copy code
git clone https://github.com/your-username/Agentless-Vulnerability-Scanner.git
Install the required dependencies:

Copy code
pip install -r requirements.txt
Run the application:

css
Copy code
python main.py
How It Works
Scan System: You can scan your system to get basic OS information and learn about its hardware (CPU, RAM, etc.).
Scan Open Ports: Check which ports are open on your system and determine any exposed services.
Vulnerability Detection: The app checks your running services against a database of known CVEs to find vulnerabilities.
Generate PDF Report: After scanning, you can download a PDF report with all the scan results.
