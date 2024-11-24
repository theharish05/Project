import wmi
import winreg
import subprocess
import json
import os
from fpdf import FPDF
import win32com.client
import platform

class PDF(FPDF):
    def header(self):
        self.set_font('times', 'B', 20)
        self.cell(0, 10, 'Scan Report', ln=1, align='C')

    def footer(self):
        self.set_y(-15)
        self.set_font('times', '', 10)
        self.cell(0, 10, f"Page: {self.page_no()}", ln=1, align='C')


pdf = PDF('P', 'mm', 'letter')
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()

def write_pdf(head, content):
    pdf.set_font('times', 'B', 18)
    pdf.cell(0, 10, head, ln=1)
    pdf.set_font('times', '', 16)
    icontent = "\n".join(f"    {line}" for line in content.splitlines())
    pdf.multi_cell(0, 10, icontent)

def get_full_os_info():
    
    os_info = f"System: {platform.system()}\n" 
    os_info += f"Host Name: {platform.node()}\n"  
    os_info += f"Release: {platform.release()}\n" 
    os_info += f"Version: {platform.version()}\n"  
    os_info += f"Machine: {platform.machine()}\n"  
    os_info += f"Processor: {platform.processor()}\n"   
    os_info += f"Python Version: {platform.python_version()}\n"
    return [os_info]
 
def get_dotnet_version():
    w = wmi.WMI()
    dotnet_versions = []
    registry_query = "SELECT * FROM StdRegProv"
    reg = w.query(registry_query)
    for reg_obj in reg:
        if "Software\\Microsoft\\NET Framework Setup\\NDP" in reg_obj:
            version = reg_obj["Version"]
            dotnet_versions.append(version)
    
    if not dotnet_versions:
        return ["NO .NET Framework versions found."]
    
    return [".NET Versions:", f".NET Framework Versions found: {', '.join(dotnet_versions)}"]

def classic_audit_policies():
    policy_path = r"SYSTEM\CurrentControlSet\Services\EventLog\Security"
    cap = ""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, policy_path) as key:
            cap += '\nFile Path: ' + winreg.QueryValueEx(key, 'File')[0]
            cap += '\nMax Size: ' + f"{winreg.QueryValueEx(key, 'MaxSize')[0] / (1024**2):.0f} MB"
            cap += '\nRetention Policy: ' + f"{winreg.QueryValueEx(key, 'Retention')[0]}"
            cap += '\nRestrict Guest Access: ' + f"{winreg.QueryValueEx(key, 'RestrictGuestAccess')[0]}"
    except PermissionError:
        cap = "Error: Access is denied."
    except FileNotFoundError:
        cap = "Error: Registry path not found."
    except Exception as e:
        cap = f"Unexpected error: {e}"

    return ["Classic Audit Policies:", cap]

def advanced_audit_policies():
    policy_paths = [
        r"SYSTEM\CurrentControlSet\Policies\Microsoft\Windows\AdvancedAudit",
        r"SOFTWARE\Policies\Microsoft\Windows\AdvancedAudit"
    ]
    details = ''
    f = 1
    for policy_path in policy_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, policy_path) as key:
                i = 0
                while True:
                    try:
                        policy_name, policy_value, _ = winreg.EnumValue(key, i)
                        if policy_value == 1:
                            details += f"{policy_name}: " + "Enabled"
                            f = 0
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue  
        except PermissionError:
            details = "Error: Access is denied. Please run as Administrator."
            return ["Advanced Audit Policies:", details]
        except Exception as e:
            details = (f"Unexpected error: {e}")
            return ["Advanced Audit Policies:", details]

    if f == 1:
        details = "No essential advanced audit policies found or policies are not configured."
    
    return ["Advanced Audit Policies:", details]

def get_registry_autorun_entries():
    autorun_keys = {
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce": winreg.HKEY_CURRENT_USER,
    }
    
    autorun_entries = []

    for path, hive in autorun_keys.items():
        try:
            key = winreg.OpenKey(hive, path.split('\\', 1)[1])
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, value, _ = winreg.EnumValue(key, i)
                autorun_entries.append((name, value, path))
            winreg.CloseKey(key)
        except FileNotFoundError:
            continue

    return autorun_entries

def get_scheduled_tasks():
    task_service = win32com.client.Dispatch("Schedule.Service")
    task_service.Connect()
    root_folder = task_service.GetFolder("\\")
    tasks = []

    def _enum_tasks(folder):
        for task in folder.GetTasks(0):
            if task.Enabled:
                tasks.append(task.Path)
        for subfolder in folder.GetFolders(0):
            _enum_tasks(subfolder)

    _enum_tasks(root_folder)
    return tasks

def get_startup_folder_entries():
    startup_folders = [
        os.path.join(os.getenv("PROGRAMDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        os.path.join(os.getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
    ]
    
    startup_entries = []
    for folder in startup_folders:
        if os.path.isdir(folder):
            for item in os.listdir(folder):
                startup_entries.append(os.path.join(folder, item))
    
    return startup_entries

def get_autorun_programs():
    autorun_programs = {
        "Registry Entries": get_registry_autorun_entries(),
        "Scheduled Tasks": get_scheduled_tasks(),
        "Startup Folder": get_startup_folder_entries()
    }
    
    return autorun_programs

def get_autorun_info():
    autoruns = get_autorun_programs()

    autorun_data = {}

    if autoruns["Registry Entries"]:
        autorun_data["Registry Autorun Entries"] = [
            f"[{path}] {name} -> {value}" for name, value, path in autoruns["Registry Entries"]
        ]
    else:
        autorun_data["Registry Autorun Entries"] = ["No registry autorun entries found."]
    
    if autoruns["Scheduled Tasks"]:
        autorun_data["Scheduled Tasks"] = autoruns["Scheduled Tasks"]
    else:
        autorun_data["Scheduled Tasks"] = ["No scheduled tasks found."]
    
    if autoruns["Startup Folder"]:
        autorun_data["Startup Folder Entries"] = autoruns["Startup Folder"]
    else:
        autorun_data["Startup Folder Entries"] = ["No startup folder entries found."]
    res = ''
    for i, j in autorun_data.items():
        res += ("\n" + i + "\n    " + "\n    ".join(j))
    return res


def get_essential_defender_settings():
    cmd = "powershell -Command \"Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, SignatureUpToDate, LastQuickScanTime | ConvertTo-Json\""
    cmd_preferences = "powershell -Command \"Get-MpPreference | Select-Object ScanScheduleDay, ScanScheduleTime | ConvertTo-Json\""
    
    status_output = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    preferences_output = subprocess.run(cmd_preferences, capture_output=True, text=True, shell=True)
    lst = [] 
    if status_output.returncode == 0 and preferences_output.returncode == 0:
        status_data = json.loads(status_output.stdout)
        preferences_data = json.loads(preferences_output.stdout)
        essential_settings = {**status_data, **preferences_data}
        
        head = "Essential Windows Defender Settings"
        content = "\n".join(f"{key}: {value}" for key, value in essential_settings.items())
        
        return [head, content]
    else:
        print("Error retrieving essential Defender settings.")

def get_firewall_rules():
    cmd = "powershell -Command \"Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | ConvertTo-Json\""
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    
    if result.returncode == 0:
        return json.loads(result.stdout)
    else:
        print("Error retrieving firewall rules.")
        return None

def analyze_firewall_rules(rules):
    exposed_ports = []
    dangerous_ports = [3389, 445, 23, 21]
    
    for rule in rules:
        local_ports = rule.get('LocalPort', '')
        if local_ports and isinstance(local_ports, str):
            local_ports = [int(p) for p in local_ports.split(',')]
        
        if local_ports:
            for port in local_ports:
                if port in dangerous_ports:
                    exposed_ports.append(f"Port {port} is open and exposed!")
    
    return exposed_ports

def get_firewall_issues():
    rules = get_firewall_rules()
    
    if not rules:
        return "No firewall rules found or failed to retrieve them."
    
    issues = analyze_firewall_rules(rules)
    if issues:
        return "Firewall Vulnerabilities Detected:\n" + "\n".join(issues)
    else:
        return "No critical firewall vulnerabilities found."

def get_installed_hotfixes():
    cmd = "wmic qfe list"
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    
    if result.returncode == 0:
        return result.stdout
    else:
        return "Error retrieving hotfixes."

def get_local_users_powershell():
    cmd = (
        "powershell -Command \"" 
        "Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordExpires, AccountExpires, UserMayChangePassword | ConvertTo-Json\""
    )
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    
    if result.returncode == 0:
        users = json.loads(result.stdout)
        return users if isinstance(users, list) else [users]
    else:
        return []

def get_pending_updates():
    cmd = (
        "powershell -Command \"" 
        "Get-WindowsUpdate -IsPending | Select-Object Title, KBArticleID, Installed, Date | ConvertTo-Json\""
    )
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    
    if result.returncode == 0:
        updates = json.loads(result.stdout)
        if isinstance(updates, list):
            output = "\n".join([f"Title: {update['Title']}, KB: {update['KBArticleID']}, Installed: {update['Installed']}, Date: {update['Date']}" for update in updates])
            return output
        else:
            return f"Title: {updates['Title']}, KB: {updates['KBArticleID']}, Installed: {updates['Installed']}, Date: {updates['Date']}"
    else:
        return "No pending updates found."
    
import subprocess
import re

def get_dns_cache_entries():
    try:
        output = subprocess.check_output(["ipconfig", "/displaydns"], text=True)
    
        domain_pattern = re.compile(r"Record Name\s+:\s+([\w\.-]+)")
        
        dns_entries = []

        lines = output.splitlines()
        for line in lines:
            domain_match = domain_pattern.search(line)
            
            if domain_match:
                dns_entries.append(domain_match.group(1))
        
        if dns_entries:
            print("DNS Cache Entries:")
            for entry in dns_entries:
                print(entry)
        else:
            print("No DNS cache entries found.")
    
    except Exception as e:
        print(f"Error retrieving DNS cache: {e}")
def run_all_checks_and_write_to_pdf():
    os_info = get_full_os_info()
    write_pdf("OS_INFO",*os_info)
    dotnet_info = get_dotnet_version()
    write_pdf(".Net Version", *dotnet_info)

    audit_info = classic_audit_policies()
    write_pdf(audit_info[0], audit_info[1])

    advanced_audit_info = advanced_audit_policies()
    write_pdf(advanced_audit_info[0], advanced_audit_info[1])

    autorun_info = get_autorun_info()
    write_pdf("Autorun Programs", autorun_info)

    defender_info = get_essential_defender_settings()
    if defender_info:       
        write_pdf(defender_info[0], defender_info[1])

    firewall_issues = get_firewall_issues()
    write_pdf("Firewall Issues", firewall_issues)

    hotfixes = get_installed_hotfixes()
    write_pdf("Hotfixes", hotfixes)

    local_users = get_local_users_powershell()
    if local_users:
        local_users_info = "\n".join([f"Name: {user['Name']}, Enabled: {user['Enabled']}, LastLogon: {user['LastLogon']}" for user in local_users])
        write_pdf("Local User Accounts", local_users_info)

    updates = get_pending_updates()
    write_pdf("Pending Updates", updates)

    pdf.output("result.pdf")

run_all_checks_and_write_to_pdf()
