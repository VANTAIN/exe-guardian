import os
import math
import sys
import re
import pefile
from rich.console import Console
from rich.table import Table

console = Console()

SHADY_APIS = {
    "SetWindowsHookExA": ("CRITICAL", "Intercepts global keyboard input (potential keylogger)."),
    "SetWindowsHookExW": ("CRITICAL", "Intercepts global keyboard input (potential keylogger)."),
    "GetAsyncKeyState": ("WARNING", "Polls state of keyboard keys directly to monitor inputs."),
    "VirtualAllocEx": ("CRITICAL", "Allocates memory inside a completely different running process."),
    "WriteProcessMemory": ("CRITICAL", "Modifies code inside a different running process (Injection)."),
    "CreateRemoteThread": ("CRITICAL", "Forces a different process to execute external code paths."),
    "InternetOpenUrlA": ("WARNING", "Attempts to connect to external URLs or download hidden payloads."),
    "InternetOpenUrlW": ("WARNING", "Attempts to connect to external URLs or download hidden payloads."),
    "URLDownloadToFileA": ("CRITICAL", "Silently downloads a web file directly to local storage."),
    "URLDownloadToFileW": ("CRITICAL", "Silently downloads a web file directly to local storage."),
    "IsDebuggerPresent": ("WARNING", "Checks if code is running inside a security analyst sandbox.")
}

def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            byte_arr = bytearray(f.read())
    except:
        return -1.0

    file_size = len(byte_arr)
    if file_size == 0:
        return 0.0

    frequencies = [0] * 256
    for byte in byte_arr:
        frequencies[byte] += 1

    entropy = 0.0
    for freq in frequencies:
        if freq > 0:
            prob = float(freq) / file_size
            entropy -= prob * math.log(prob, 2)
            
    return round(entropy, 2)

def scan_pe_imports(file_path):
    findings = []
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return findings

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    if func_name in SHADY_APIS:
                        severity, explanation = SHADY_APIS[func_name]
                        findings.append({"api": func_name, "severity": severity, "explanation": explanation})
    except pefile.PEFormatError:
        return "NOT_A_PE"
    except:
        return "ERROR"
    return findings

def scan_suspicious_strings(file_path):
    findings = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
        ip_pattern = rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        url_pattern = rb'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        reg_pattern = rb'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        
        ips = set(re.findall(ip_pattern, data))
        urls = set(re.findall(url_pattern, data))
        regs = set(re.findall(reg_pattern, data, re.IGNORECASE))
        
        if ips:
            findings.append({"type": "IP Addresses", "count": len(ips), "severity": "WARNING", "explanation": "Hardcoded IPs found. Potential C2 servers."})
        if urls:
            findings.append({"type": "Web URLs", "count": len(urls), "severity": "WARNING", "explanation": "Hardcoded web links found. Potential payload drops."})
        if regs:
            findings.append({"type": "Registry Startup", "count": len(regs), "severity": "CRITICAL", "explanation": "Attempts to inject into Windows Startup for persistence."})
            
    except:
        return "ERROR"
    return findings

def main():
    console.print("[bold blue]=========================================[/bold blue]")
    console.print("[bold cyan]🛡️  EXE-GUARDIAN: ANTI-MALWARE STATIC ANALYZER[/bold cyan]")
    console.print("[bold blue]=========================================[/bold blue]\n")
    
    if len(sys.argv) < 2:
        console.print("[bold red]Error:[/bold red] Please provide a file path to scan.")
        return

    target_file = sys.argv[1]
    
    if not os.path.exists(target_file):
        console.print(f"[bold red]Error:[/bold red] File '{target_file}' not found.")
        return

    threat_score = 0

    table = Table(title=f"Scan Report for: [bold yellow]{os.path.basename(target_file)}[/bold yellow]")
    table.add_column("Scan Module", style="cyan")
    table.add_column("Finding", style="white")
    table.add_column("Severity", style="bold")
    table.add_column("Explanation", style="magenta")

    # 1. ENTROPY CHECK
    entropy_score = calculate_entropy(target_file)
    if entropy_score > 7.2:
        table.add_row("Entropy Check", f"Score: {entropy_score}/8.0", "[bold red]CRITICAL[/bold red]", "Highly packed or encrypted.")
        threat_score += 40
    elif entropy_score > 6.8:
        table.add_row("Entropy Check", f"Score: {entropy_score}/8.0", "[bold yellow]WARNING[/bold yellow]", "Heavily compressed.")
        threat_score += 20
    elif entropy_score >= 0:
        table.add_row("Entropy Check", f"Score: {entropy_score}/8.0", "[bold green]SAFE[/bold green]", "Normal code structure.")

    # 2. PE IMPORT SCAN
    import_results = scan_pe_imports(target_file)
    if import_results == "NOT_A_PE":
        table.add_row("PE Import Scan", "N/A", "[bold blue]INFO[/bold blue]", "Not a Windows PE format (Skipped).")
    elif import_results == "ERROR":
        pass
    elif len(import_results) == 0:
        table.add_row("PE Import Scan", "0 Flags Found", "[bold green]SAFE[/bold green]", "No high-risk APIs detected.")
    else:
        for alert in import_results:
            color = "red" if alert["severity"] == "CRITICAL" else "yellow"
            table.add_row("PE Import Scan", f"Found {alert['api']}", f"[bold {color}]{alert['severity']}[/bold {color}]", alert['explanation'])
            if alert["severity"] == "CRITICAL":
                threat_score += 30
            else:
                threat_score += 15

    # 3. STRING SIGNATURE SCAN
    string_results = scan_suspicious_strings(target_file)
    if string_results == "ERROR":
        pass
    elif len(string_results) == 0:
        table.add_row("String Hunter", "Clean", "[bold green]SAFE[/bold green]", "No suspicious IPs, URLs, or Registry paths found.")
    else:
        for alert in string_results:
            color = "red" if alert["severity"] == "CRITICAL" else "yellow"
            table.add_row("String Hunter", f"Found {alert['count']} {alert['type']}", f"[bold {color}]{alert['severity']}[/bold {color}]", alert['explanation'])
            if alert["severity"] == "CRITICAL":
                threat_score += 25
            else:
                threat_score += 15

    console.print(table)

    final_score = min(threat_score, 100)
    
    if final_score >= 70:
        verdict = "[bold red]DANGER: HIGHLY MALICIOUS RISK[/bold red]"
    elif final_score >= 35:
        verdict = "[bold yellow]SUSPICIOUS: PROCEED WITH CAUTION[/bold yellow]"
    else:
        verdict = "[bold green]CLEAN: LOW RISK[/bold green]"
        
    console.print("\n[bold blue]=========================================[/bold blue]")
    console.print(f"📊 [bold white]TOTAL THREAT SCORE:[/bold white] {final_score}/100")
    console.print(f"🔒 [bold white]FINAL VERDICT:[/bold white] {verdict}")
    console.print("[bold blue]=========================================[/bold blue]")

if __name__ == "__main__":
    main()

