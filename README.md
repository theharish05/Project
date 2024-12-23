# Agentless Vulnerability and Network Scanner

This tool is designed to help you quickly assess the security of your systems by scanning for vulnerabilities and analyzing network configurations—all **without the need for installing any agents**. It features an intuitive graphical user interface (GUI) that allows users to:

- Retrieve detailed system information
- Scan for open ports
- Detect vulnerable services
- Generate PDF reports summarizing scan results

## Features

- **System Information**: Easily retrieve comprehensive details about your operating system, memory usage, CPU performance, and other key hardware components.
- **Open Ports Scan**: Identify which ports are open on your machine and determine which services might be exposed to potential threats.
- **Service Vulnerability Detection**: Scan the services running on your system and compare them to a database of known vulnerabilities (CVEs) to uncover any security risks.
- **PDF Report Generation**: After completing the scans, generate and download a detailed PDF report that summarizes all your findings for documentation or further review.
- **Interactive Vulnerability Chart**: View a dynamic pie chart that visually represents the number of safe vs. vulnerable services detected on your system.

## Technologies Used

This project utilizes several powerful libraries and tools to ensure the scanning process is efficient and effective:

- **PySide6**: Provides the graphical user interface (GUI) that makes interacting with the tool simple and user-friendly.
- **psutil**: Allows us to gather information about the system's resources, including CPU, memory, and disk usage.
- **nmap**: Used to perform network scans, identifying open ports and active services on your local machine.
- **requests**: Helps query the National Vulnerability Database (NVD) to identify vulnerabilities (CVEs) in the services running on your system.
- **fpdf**: A Python library that enables us to generate and download PDF reports from the scan results.

## Installation

Follow the steps below to get the tool up and running on your machine:

1. **Clone the repository**:

    ```bash
    git clone https://github.com/theharish05/Project.git
    ```

2. **Install the required dependencies**:

    First, navigate to the project folder, then install the necessary Python libraries using `pip`:

    ```bash
    pip install -r requirements.txt
    ```

3. **Run the application**:

    To start the application, simply run the following command:

    ```bash
    python Main_frontend_Code.py

    ```

## How It Works

Here’s a quick overview of how the tool works and what it does:

1. **Scan System**: Get detailed information about your system’s operating system, CPU, memory, and other hardware components to better understand its current state.
2. **Scan Open Ports**: Identify which ports are open and which services might be exposed to the network. This helps you assess potential entry points for attackers.
3. **Vulnerability Detection**: The tool cross-references the services running on your system with a database of known vulnerabilities (CVEs) to check if any of them are vulnerable to exploits.
4. **Generate PDF Reports**: After performing the scans, you can download a comprehensive PDF report that summarizes all the results, helping you document your findings or share them with others.

## Contributors

This project was developed by the following team members:

- **[Teammate 1 Name](https://github.com/teammate1)** - Developer
- **[Teammate 2 Name](https://github.com/teammate2)** - Developer
- **[Teammate 3 Name](https://github.com/teammate3)** - Developer
- **[Teammate 4 Name](https://github.com/teammate4)** - Developer
- **[Teammate 5 Name](https://github.com/teammate5)** - Developer
- **[Teammate 6 Name](https://github.com/teammate6)** - Developer
