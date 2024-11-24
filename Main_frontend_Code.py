import sys
import os
import platform
import psutil
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QLabel
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon, QColor, QPainter
from PySide6.QtCharts import QChart, QChartView, QPieSeries
from fpdf import FPDF 
from MainBackend import scan_service, get_open_ports  # Backend script

class VulnerabilityScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Agentless Vulnerability and Network Scanner")
        self.setGeometry(100, 100, 1000, 600)


        self.setStyleSheet("""
            QMainWindow {
                background: rgb(2,0,36);
                background: linear-gradient(90deg, rgba(2,0,36,1) 0%, rgba(9,9,121,1) 35%, rgba(0,212,255,1) 100%);
            }
        """)


        main_layout = QHBoxLayout()
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)


        self.sidebar = QVBoxLayout()
        self.sidebar.setSpacing(10)
        self.sidebar.setContentsMargins(10, 10, 10, 10)

        sidebar_widget = QWidget()
        sidebar_widget.setLayout(self.sidebar)
        sidebar_widget.setFixedWidth(200)
        sidebar_widget.setStyleSheet("background-color: #36454F; border-radius: 10px;")
        sidebar_widget.setVisible(True)  # Sidebar visible by default


        self.scan_system_button = QPushButton("Basic OS Info")
        self.scan_system_button.setStyleSheet(self.button_style())
        self.scan_system_button.clicked.connect(self.display_os_info)

        self.scan_ports_button = QPushButton("Scan Open Ports")
        self.scan_ports_button.setStyleSheet(self.button_style())
        self.scan_ports_button.clicked.connect(self.display_open_ports)

        self.scan_service_button = QPushButton("Scan Service Vulnerabilities")
        self.scan_service_button.setStyleSheet(self.button_style())
        self.scan_service_button.clicked.connect(self.display_service_scan)

        self.download_button = QPushButton("Download Report As PDF")
        self.download_button.setStyleSheet(self.button_style())
        self.download_button.clicked.connect(self.download_report_as_pdf)


        self.sidebar.addWidget(self.scan_system_button)
        self.sidebar.addWidget(self.scan_ports_button)
        self.sidebar.addWidget(self.scan_service_button)
        self.sidebar.addWidget(self.download_button)
        self.sidebar.addStretch()


        self.menu_button = QPushButton()
        self.menu_button.setIcon(QIcon("menu_icon.png"))  # Provide an icon for the menu
        self.menu_button.setFixedSize(40, 40)
        self.menu_button.setStyleSheet("border: none;")
        self.menu_button.clicked.connect(self.toggle_sidebar)


        header_layout = QHBoxLayout()
        header_layout.addWidget(self.menu_button)
        header_layout.addStretch()

        header_widget = QWidget()
        header_widget.setLayout(header_layout)

        content_layout = QVBoxLayout()

        title_label = QLabel("Agentless Vulnerability and Network Scanner")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        content_layout.addWidget(title_label)

        self.result_display = QTextEdit()
        self.result_display.setReadOnly(True)
        self.result_display.setStyleSheet("background-color: white; color: black; font-size: 15px;")
        content_layout.addWidget(self.result_display)

        self.chart = QChart()
        self.chart.setTitle("Vulnerability Overview")
        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        content_layout.addWidget(self.chart_view)

        main_layout.addWidget(sidebar_widget)
        main_layout.addLayout(content_layout)

        self.sidebar_widget = sidebar_widget  # For toggling visibility

    def button_style(self):
        """Return stylesheet for sidebar buttons with hover and click effects."""
        return """
            QPushButton {
                background-color: #556B7D;
                color: white;
                padding: 10px;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #6C849A;
            }
            QPushButton:pressed {
                background-color: #3D4E5A;
            }
        """

    def toggle_sidebar(self):
        """Show or hide the sidebar when the menu button is clicked."""
        current_state = self.sidebar_widget.isVisible()
        self.sidebar_widget.setVisible(not current_state)

    def display_os_info(self):
        """Display basic OS information in the result display."""
        self.result_display.clear()
        self.result_display.append("Fetching Basic OS Information...\n")

        os_name = platform.system()
        os_version = platform.version()
        processor = platform.processor()

        memory = psutil.virtual_memory()
        total_memory = memory.total // (1024 ** 2)
        available_memory = memory.available // (1024 ** 2)

        cpu_cores = psutil.cpu_count(logical=True)

        info = (
            f"Operating System: {os_name}\n"
            f"OS Version: {os_version}\n"
            f"Processor: {processor}\n"
            f"Total Memory: {total_memory} MB\n"
            f"Available Memory: {available_memory} MB\n"
            f"CPU Cores: {cpu_cores}\n"
        )

        self.result_display.append(info)

    def display_service_scan(self):
        self.result_display.clear()
        self.result_display.append("Running Service Vulnerability Scan...\n")
        scan_result = scan_service()
        self.result_display.append(scan_result)
        self.update_pie_chart(scan_result.count("vulnerability"))

    def display_open_ports(self):
        self.result_display.clear()
        self.result_display.append("Running Open Ports Scan...\n")
        open_ports_result = get_open_ports()
        self.result_display.append(open_ports_result)
        self.update_pie_chart(open_ports_result.count("open port"))

    def download_report_as_pdf(self):
        file_path = os.path.join(os.getcwd(), "scan_report.pdf")
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Agentless Vulnerability and Network Scanner Report", ln=True, align='C')
        pdf.ln(10)

        scan_result_text = self.result_display.toPlainText()
        for line in scan_result_text.splitlines():
            pdf.cell(200, 10, txt=line, ln=True)
        pdf.output(file_path)
        self.result_display.append(f"\nReport saved as {file_path}")

    def update_pie_chart(self, vulnerabilities_count):
        safe_count = 100 - vulnerabilities_count if vulnerabilities_count <= 100 else 0
        vulnerable_count = min(vulnerabilities_count, 100)

        self.chart.removeAllSeries()
        series = QPieSeries()
        series.append("Safe", safe_count)
        series.append("Vulnerable", vulnerable_count)

        series.slices()[0].setBrush(QColor(76, 175, 80))
        series.slices()[1].setBrush(QColor(244, 67, 54))

        self.chart.addSeries(series)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = VulnerabilityScannerApp()
    main_window.show()
    sys.exit(app.exec())
