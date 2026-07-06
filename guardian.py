import os
import math
import sys
import pefile
from rich.console import Console
from rich.table import Table

console = Console()

# A curated watchlist of high-risk Windows APIs frequently abused by malware/cracks
SHADY_APIS = {
    # Keylogging / Input Monitoring
    "SetWindowsHookExA": ("CRITICAL", "Intercepts global keyboard input (potential keylogger)."),
    "SetWindowsHookExW": ("CRITICAL", "Intercepts global keyboard input (potential keylogger)."),
    "GetAsyncKeyState": ("WARNING", "Polls state of keyboard keys directly to monitor inputs."),
    
    # Process Injection / Stealth Execution
    "VirtualAllocEx": ("CRITICAL", "Allocates memory inside a completely different running process."),
    "WriteProcessMemory": ("CRITICAL", "Modifies code inside a different running process (Injection)."),
    "CreateRemoteThread": ("CRITICAL", "Forces a different process to execute external code paths."),
    
    # Network Payloads / Calling Home
    "InternetOpenUrlA": ("WARNING", "Attempts to connect to external URLs or download hidden payloads."),
    "InternetOpenUrlW": ("WARNING", "Attempts to connect to external URLs or download hidden payloads."),
    "URLDownloadToFileA": ("CRITICAL", "Silently downloads a web file directly to local storage."),
    "URLDownloadToFileW": ("CRITICAL", "Silently downloads a web file directly to local storage."),
    
    # Evasion / Anti-Analysis
    "IsDebuggerPresent": ("WARNING", "Checks if code is running inside a security analyst sandbox.")
}

def calculate_entropy(file_path):
    """Calculates the Shannon entropy of the file to detect obfuscation."""
    try:
        with open(file_path, 'rb') as f:
            byte_arr = bytearray(f.read())
    except Exception as e:
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
    """Scans a Windows PE file's Import Address Table for high-risk APIs."""
    findings = []
    try:
        # Load the executable structure via pefile
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()
        
        # Check if the binary actually has an import table
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return findings

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    if func_name in SHADY_APIS:
                        severity, explanation = SHADY_APIS[func_name]
                        findings.append({
                            "api": func_name,
                            "severity": severity,
                            "explanation": explanation
                        })
    except pefile.PEFormatError:
        # Expected if running a non-Windows executable like a Python script
        return "NOT_A_PE"
    except Exception as e:
        return "ERROR"
        
    return findings

def main():
    console.print("[bold blue]=========================================[/bold blue]")
    console.print("[bold cyan]🛡️  EXE-GUARDIAN: ANTI-MALWARE STATIC ANALYZER[/bold cyan]")
    console.print("[bold blue]=========================================[/bold blue]\n")
    
    if len(sys.argv) < 2:
        console.print("[bold red]Error:[/bold red] Please provide a file path to scan.")
        console.print("Usage: python guardian.py <path_to_exe>")
        return

    target_file = sys.argv[1]
    
    if not os.path.exists(target_file):
        console.print(f"[bold red]Error:[/bold red] File '{target_file}' not found.")
        return

    # Initialize our Rich Table Layout
    table = Table(title=f"Scan Report for: [bold yellow]{os.path.basename(target_file)}[/bold yellow]")
    table.add_column("Scan Module", style="cyan")
    table.add_column("Finding", style="white")
    table.add_column("Severity", style="bold")
    table.add_column("Explanation", style="magenta")

    # ---- MODULE 1: RUN ENTROPY CHECK ----
    entropy_score = calculate_entropy(target_file)
    
    if entropy_score > 7.2:
        table.add_row("Entropy Check", f"Score: {entropy_score} / 8.0", "[bold red]CRITICAL[/bold red]", "File is highly packed or encrypted. High obfuscation risk.")
    elif entropy_score > 6.8:
        table.add_row("Entropy Check", f"Score: {entropy_score} / 8.0", "[bold yellow]WARNING[/bold yellow]", "File is heavily compressed. Possible obfuscation.")
    elif entropy_score >= 0:
        table.add_row("Entropy Check", f"Score: {entropy_score} / 8.0", "[bold green]SAFE[/bold green]", "Normal unencrypted code structure.")
    else:
        table.add_row("Entropy Check", "Error", "[bold red]ERROR[/bold red]", "Could not read file for calculation.")

    # ---- MODULE 2: RUN WINDOWS PE IMPORT SCAN ----
    import_results = scan_pe_imports(target_file)
    
    if import_results == "NOT_A_PE":
        table.add_row("PE Import Scan", "N/A", "[bold blue]INFO[/bold blue]", "Not a Windows Portable Executable format (Skipped).")
    elif import_results == "ERROR":
        table.add_row("PE Import Scan", "Error", "[bold red]ERROR[/bold red]", "Failed to process the file binary structure.")
    elif len(import_results) == 0:
        table.add_row("PE Import Scan", "0 Flags Found", "[bold green]SAFE[/bold green]", "No high-risk Windows APIs detected in the import table.")
    else:
        for alert in import_results:
            color = "red" if alert["severity"] == "CRITICAL" else "yellow"
            table.add_row(
                "PE Import Scan", 
                f"Found {alert['api']}", 
                f"[bold {color}]{alert['severity']}[/bold {color}]", 
                alert['explanation']
            )

    # Render the finished table layout
    console.print(table)

if __name__ == "__main__":
    main()
