#!/usr/bin/env python3
"""
XRO Server Sniffer - Main UI Launcher (updated)

Improvements:
 - Better interactive menu with filters (show responsive, non-responsive, or all)
 - Nicely formatted output table including device type and open/total ports
 - Writes richer JSON with per-port statuses and device type
"""

import argparse
import asyncio
import itertools
import json
import os
import sys
import signal
from colorama import Fore, Style, init
from typing import Dict, Iterable, List, Optional
from xro_scanner import scan_targets, parse_ports, validate_and_expand_targets, generate_random_public_ips, DEFAULT_PORTS, detect_device_type, scan_with_rustscan, tcp_check

init(autoreset=True)

_partial_results = {}
_output_file = "xro_results.json"
_scan_interrupted = False

RAINBOW_COLORS = [
    Fore.RED,
    Fore.LIGHTRED_EX,
    Fore.YELLOW,
    Fore.LIGHTGREEN_EX,
    Fore.CYAN,
    Fore.LIGHTBLUE_EX,
    Fore.MAGENTA,
]

def rainbow_text(text: str, bright: bool = True, repeat: int = 2) -> str:
    """
    Return text decorated with a smooth rainbow gradient.
    The `repeat` parameter controls how many visible characters share the same color.
    """
    if not text:
        return ""
    styled_chars = []
    color_cycle = itertools.cycle(RAINBOW_COLORS)
    current_color = next(color_cycle)
    visible_count = 0
    for char in text:
        if char == "\n":
            styled_chars.append(Style.RESET_ALL + "\n")
            current_color = next(color_cycle)
            visible_count = 0
            continue
        if not char.strip():
            styled_chars.append(char)
            continue
        if visible_count >= repeat:
            current_color = next(color_cycle)
            visible_count = 0
        prefix = current_color + (Style.BRIGHT if bright else "")
        styled_chars.append(prefix + char)
        visible_count += 1
    styled_chars.append(Style.RESET_ALL)
    return "".join(styled_chars)

def rainbow_print(text: str, bright: bool = True, repeat: int = 2) -> None:
    """
    Convenience wrapper around rainbow_text for printing.
    """
    print(rainbow_text(text, bright=bright, repeat=repeat))

def rainbow_line(length: int = 72, char: str = "═", bright: bool = False, repeat: int = 3) -> str:
    return rainbow_text(char * length, bright=bright, repeat=repeat)

def save_partial_results(results: Dict, output_file: str, interrupted: bool = False):
    """Save partial or complete results to JSON file"""
    if not results:
        print(Fore.YELLOW + "\n[!] No results to save." + Style.RESET_ALL)
        return
    
    for ip, data in results.items():
        if "ports" in data:
            ports_list = data["ports"]
            open_count = sum(1 for p in ports_list if p["status"] == "open")
            data["summary"] = {
                "has_open": open_count > 0,
                "open_count": open_count,
                "total_ports": len(ports_list),
            }
            data["device_type"] = detect_device_type(ports_list)
    
    active_hosts = sum(1 for data in results.values() if data.get("summary", {}).get("has_open", False))
    meta = {
        "scan_info": {
            "total_ips_scanned": len(results),
            "active_hosts_found": active_hosts,
            "scan_status": "interrupted" if interrupted else "completed",
        },
        "timestamp": __import__('datetime').datetime.now().isoformat(),
    }
    
    try:
        with open(output_file, "w") as outfh:
            json.dump({"meta": meta, "results": results}, outfh, indent=2)
        
        if interrupted:
            print(Fore.YELLOW + f"\n\n{'='*80}")
            print(Fore.YELLOW + "  SCAN INTERRUPTED - PARTIAL RESULTS SAVED")
            print(Fore.YELLOW + f"{'='*80}" + Style.RESET_ALL)
        print(Fore.GREEN + f"✓ Results saved to: {output_file}")
        print(Fore.CYAN + f"  • IPs scanned: {len(results)}")
        print(Fore.CYAN + f"  • Active hosts: {active_hosts}" + Style.RESET_ALL)
        return True
    except Exception as e:
        print(Fore.RED + f"[!] Failed to save results: {e}" + Style.RESET_ALL)
        return False

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully - save partial results"""
    global _scan_interrupted, _partial_results, _output_file
    _scan_interrupted = True
    
    print(Fore.YELLOW + "\n\n[!] Scan interrupted by user (Ctrl+C)" + Style.RESET_ALL)
    print(Fore.CYAN + "[*] Saving partial results..." + Style.RESET_ALL)
    
    if _partial_results:
        if save_partial_results(_partial_results, _output_file, interrupted=True):
            print(Fore.GREEN + "\n✓ Partial results saved successfully!" + Style.RESET_ALL)
            print(Fore.WHITE + f"  You can view them in: {_output_file}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "\n✗ Failed to save partial results" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] No results collected yet" + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\nExiting..." + Style.RESET_ALL)
    sys.exit(0)

def build_misc_options(args) -> Dict[str, bool]:
    """
    Extract miscellaneous CLI switches that can be toggled in the UI.
    """
    return {
        "allow_public": bool(getattr(args, "allow_public", False)),
    }

def build_misc_protocols(default_protocol: str = "tcp") -> Dict[str, bool]:
    options = {
        "tcp": False,
        "udp": False,
    }
    default_protocol = (default_protocol or "tcp").lower()
    if default_protocol in options:
        options[default_protocol] = True
    else:
        options["tcp"] = True
    return options

def format_misc_status(misc_options: Dict[str, bool]) -> str:
    """
    Format misc settings into a readable string of toggles.
    """
    if not misc_options:
        return "none"
    parts = []
    for key, value in misc_options.items():
        state = "ON" if value else "OFF"
        parts.append(f"{key}={state}")
    return ", ".join(parts)

def format_protocol_status(protocols: Dict[str, bool]) -> str:
    active = [name.upper() for name, enabled in protocols.items() if enabled]
    inactive = [name.upper() for name, enabled in protocols.items() if not enabled]
    if not active:
        return "None selected"
    if not inactive:
        return ", ".join(active)
    return f"Active: {', '.join(active)} | Disabled: {', '.join(inactive)}"

def sync_misc_to_args(args, misc_options: Dict[str, bool]) -> None:
    """
    Update argparse namespace with the latest misc settings.
    """
    for key, value in misc_options.items():
        if hasattr(args, key):
            setattr(args, key, value)

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    XRO Server Sniffer dev Less               ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    rainbow_print(banner)

def parse_args():
    p = argparse.ArgumentParser(description="XRO Server Sniffer UI Launcher.")
    p.add_argument("--protocol", choices=['tcp', 'udp'], default='tcp', help="Protocol to scan (default: tcp).")
    p.add_argument("--allow-public", action='store_true', help="Allow scanning public IPs (for worldwide scanning).")
    p.add_argument("--concurrency", "-c", type=int, default=200, help="Max concurrent connections (default 200).")
    p.add_argument("--timeout", type=float, default=2.0, help="Connect timeout in seconds (default 2.0).")
    p.add_argument("--output", "-o", default="xro_results.json", help="JSON output file.")
    return p.parse_args()

def get_targets():
    specs = []
    print(Fore.CYAN + "Enter target IPs or CIDRs (one per line, empty line to finish):")
    while True:
        try:
            line = input(Fore.GREEN + "> ").strip()
        except EOFError:
            break
        if not line:
            break
        specs.append(line)
    return specs

def get_ports():
    port_spec = input(Fore.CYAN + f"Enter ports (comma-separated or ranges, default: {','.join(map(str, DEFAULT_PORTS))}): ").strip()
    if not port_spec:
        port_spec = ",".join(map(str, DEFAULT_PORTS))
    return parse_ports(port_spec)

def ensure_device_type(data: Dict[str, Dict[str, List]]) -> None:
    for entry in data.values():
        if not entry.get("device_type"):
            entry["device_type"] = detect_device_type(entry.get("ports", []))

def print_results_table(results: Dict[str, Dict[str, List]], filter_mode: str = "all"):
    """
    Enhanced results table with OS detection
    filter_mode: "all", "responsive", "nonresponsive"
    """
    if not results:
        print(Fore.RED + "[!] No results to display." + Style.RESET_ALL)
        return
    ensure_device_type(results)
    
    total_ips = len(results)
    responsive_ips = sum(1 for data in results.values() if data.get("summary", {}).get("has_open", False))
    
    print("\n" + Fore.YELLOW + "="*100 + Style.RESET_ALL)
    print(Fore.CYAN + f"  SCAN RESULTS: {responsive_ips}/{total_ips} IPs with open ports" + Style.RESET_ALL)
    print(Fore.YELLOW + "="*100 + Style.RESET_ALL)
    
    separator = Fore.YELLOW + "─"*100 + Style.RESET_ALL
    header = f"{'IP ADDRESS':<18} {'OS / DEVICE TYPE':<45} {'PORTS':>10} {'STATUS':<15}"
    print(Fore.WHITE + Style.BRIGHT + header + Style.RESET_ALL)
    print(separator)
    
    for ip, data in results.items():
        s = data.get("summary", {})
        device = data.get("device_type", "Unknown OS")
        open_cnt = s.get("open_count", 0)
        tot = s.get("total_ports", 0)
        has_open = s.get("has_open", False)

        if filter_mode == "responsive" and not has_open:
            continue
        if filter_mode == "nonresponsive" and has_open:
            continue

        status_str = "✓ ACTIVE" if has_open else "✗ NO RESPONSE"
        color = Fore.GREEN if has_open else Fore.RED
        open_tot = f"{open_cnt}/{tot}"
        
        row = f"{ip:<18} {device:<45} {open_tot:>10} {status_str:<15}"
        print(color + Style.BRIGHT + row + Style.RESET_ALL)
        
        open_ports = [p for p in data["ports"] if p["status"] == "open"]
        if open_ports:
            for p in sorted(open_ports, key=lambda z: z["port"]):
                port_color = Fore.GREEN
                info = p.get("info", "")
                banner_preview = info[:60] + "..." if len(info) > 60 else info
                detail = f"  └─ Port {p['port']:>5}/{p['protocol']:<3} OPEN"
                if banner_preview:
                    detail += f" │ {banner_preview}"
                print(port_color + detail + Style.RESET_ALL)
    
    print(separator)
    print(Fore.CYAN + f"  Total: {responsive_ips} active hosts found" + Style.RESET_ALL)
    print(Fore.YELLOW + "="*100 + Style.RESET_ALL + "\n")

def perform_scan(targets, ports, protocols, concurrency, timeout, output, allow_public=True, misc_options=None):
    global _partial_results, _output_file, _scan_interrupted
    
    if misc_options is None:
        misc_options = {}
    protocols = [p.lower() for p in protocols if p]
    if not protocols:
        print(Fore.RED + "[!] No protocols selected; aborting scan.")
        return
    
    _output_file = output
    _scan_interrupted = False
    signal.signal(signal.SIGINT, signal_handler)
    
    rainbow_print(f"[+] Protocols selected: {', '.join(proto.upper() for proto in protocols)}", bright=False)
    ips = validate_and_expand_targets(targets, allow_public=allow_public)
    if not ips:
        print(Fore.RED + "[!] No valid IPs after expansion.")
        return
    rainbow_print(f"[+] Misc options: {format_misc_status(misc_options)}", bright=False)
    rainbow_print(f"[+] Protocols: {', '.join(proto.upper() for proto in protocols)}", bright=False)
    rainbow_print(f"[+] Scanning {len(ips)} IP(s) × {len(ports)} port(s) (concurrency={concurrency})", bright=False)
    print(Fore.YELLOW + "\n[TIP] Press Ctrl+C to stop scan and save partial results" + Style.RESET_ALL)

    def progress_formatter(ip: str, port: int, message: str) -> None:
        if port is None or port < 0:
            prefix = f"[{ip}]"
        else:
            prefix = f"[{ip}:{port}]"
        if "open" in message.lower() or "responsive" in message.lower():
            print(Fore.GREEN + f"{prefix} {message}" + Style.RESET_ALL)
        elif "closed" in message.lower() or "no response" in message.lower() or "error" in message.lower():
            print(Fore.RED + f"{prefix} {message}" + Style.RESET_ALL)
        else:
            print(Fore.CYAN + f"{prefix} {message}" + Style.RESET_ALL)
    
    def rustscan_progress(ip: str, is_valid: Optional[bool]) -> None:
        """Progress callback for rustscan - shows real-time scanning"""
        if is_valid is None:
            print(Fore.CYAN + f"[Scanning] {ip}..." + Style.RESET_ALL, end='\r')
        elif is_valid:
            print(Fore.GREEN + f"[✓ FOUND] {ip} - SSH/Services detected!".ljust(80) + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[✗ Empty] {ip}".ljust(80) + Style.RESET_ALL, end='\r')

    combined_results = {}
    _partial_results = {}
    
    for protocol in protocols:
        if protocol.lower() == 'tcp':
            rustscan_results = scan_with_rustscan(ips, ports, timeout, progress_cb=rustscan_progress)
            for ip, open_ports in rustscan_results.items():
                if ip not in combined_results:
                    combined_results[ip] = {"summary": None, "device_type": None, "ports": []}
                for port in ports:
                    status = "open" if port in open_ports else "closed"
                    combined_results[ip]["ports"].append({
                        "port": port,
                        "protocol": "TCP",
                        "status": status,
                        "info": ""
                    })
                _partial_results = dict(combined_results)
        else:
            protocol_results = asyncio.run(scan_targets(
                ips,
                ports,
                protocol=protocol,
                concurrency=concurrency,
                timeout=timeout,
                progress_cb=progress_formatter,
            ))
            for ip, data in protocol_results.items():
                if ip not in combined_results:
                    combined_results[ip] = {"summary": None, "device_type": None, "ports": []}
                combined_results[ip]["ports"].extend(data["ports"])
                _partial_results = dict(combined_results)

    for ip, data in combined_results.items():
        open_tcp_ports = [p["port"] for p in data["ports"] if p["status"] == "open" and p["protocol"] == "TCP"]
        if open_tcp_ports:
            banners = {}
            sem = asyncio.Semaphore(concurrency)
            async def grab_banner(port):
                status, info = await tcp_check(ip, port, timeout, sem)
                banners[port] = info
            tasks = [grab_banner(port) for port in open_tcp_ports]
            asyncio.run(asyncio.gather(*tasks))
            for p in data["ports"]:
                if p["port"] in banners:
                    p["info"] = banners[p["port"]]
            _partial_results = dict(combined_results)

    for ip, data in combined_results.items():
        ports_list = data["ports"]
        open_count = sum(1 for p in ports_list if p["status"] == "open")
        data["summary"] = {
            "has_open": open_count > 0,
            "open_count": open_count,
            "total_ports": len(ports_list),
        }
        data["device_type"] = detect_device_type(ports_list)

    results = dict(sorted(combined_results.items(), key=lambda item: item[0]))
    _partial_results = results  

 
    print(Fore.CYAN + "\n[*] Finalizing scan results..." + Style.RESET_ALL)
    active_hosts = sum(1 for data in results.values() if data.get("summary", {}).get("has_open", False))
    meta = {
        "scan_info": {
            "total_ips_scanned": len(ips),
            "active_hosts_found": active_hosts,
            "ports_per_ip": len(ports),
            "protocols": protocols,
            "scan_status": "completed",
        },
        "timestamp": __import__('datetime').datetime.now().isoformat(),
    }
    try:
        with open(output, "w") as outfh:
            json.dump({"meta": meta, "results": results}, outfh, indent=2)
        print(Fore.GREEN + f"\n✓ Scan complete! Results saved to: {output}")
        print(Fore.CYAN + f"  • Total IPs scanned: {len(ips)}")
        print(Fore.CYAN + f"  • Active hosts found: {active_hosts}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Failed writing JSON output: {e}" + Style.RESET_ALL)

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    show_results_ui(results)

def perform_mass_scan(protocols: Iterable[str], timeout, output, misc_options, concurrency=500, batch_size=100, continuous=False):
    """
    Perform automatic mass scanning with continuous IP generation
    batch_size: number of IPs to scan per batch
    continuous: if True, scan continuously until interrupted
    """
    global _partial_results, _output_file, _scan_interrupted
    
    if not misc_options.get("allow_public"):
        print(Fore.RED + "[!] Mass scan requires allow_public to be enabled in misc options.")
        return
    
    protocols_list = ['tcp']
    timeout = 1.5 
    
    ssh_ports = [22, 2222, 2200, 22222]
    
    _output_file = output
    _scan_interrupted = False
    signal.signal(signal.SIGINT, signal_handler)
    
    print(Fore.CYAN + f"\n[+] Starting automatic mass scanner")
    print(Fore.CYAN + f"[+] Scanning for SSH servers on ports: {', '.join(map(str, ssh_ports))}")
    print(Fore.YELLOW + "[+] Mode: {'CONTINUOUS' if continuous else 'BATCH'}")
    print(Fore.YELLOW + "[TIP] Press Ctrl+C to stop and save results\n" + Style.RESET_ALL)
    
    total_scanned = 0
    total_found = 0
    batch_num = 0
    
    try:
        while True:
            if _scan_interrupted:
                break
                
            batch_num += 1
            print(Fore.MAGENTA + f"\n{'='*80}")
            print(Fore.MAGENTA + f"  BATCH #{batch_num} - Generating {batch_size} random IPs...")
            print(Fore.MAGENTA + f"{'='*80}" + Style.RESET_ALL)
            
            targets = generate_random_public_ips(count=batch_size)
            
            if not targets:
                print(Fore.RED + "[!] Failed to generate IPs. Retrying...")
                continue
            
            print(Fore.GREEN + f"[✓] Generated {len(targets)} IPs - Starting scan..." + Style.RESET_ALL)
            
            def rustscan_progress(ip: str, is_valid: Optional[bool]) -> None:
                """Progress callback for rustscan"""
                if is_valid is None:
                    print(Fore.CYAN + f"[Scanning] {ip}...".ljust(80) + Style.RESET_ALL, end='\r')
                elif is_valid:
                    print(Fore.GREEN + f"[✓ FOUND] {ip} - SSH Server detected!".ljust(80) + Style.RESET_ALL)
                else:
                    pass  
            

            rustscan_results = scan_with_rustscan(targets, ssh_ports, timeout, progress_cb=rustscan_progress)
            

            if not rustscan_results:
                print(Fore.YELLOW + "[*] Using Python-based scanning..." + Style.RESET_ALL)
                
                def progress_formatter(ip: str, port: int, message: str) -> None:
                    if "open" in message.lower():
                        print(Fore.GREEN + f"[{ip}:{port}] {message}" + Style.RESET_ALL)
                
                scan_results = asyncio.run(scan_targets(
                    targets,
                    ssh_ports,
                    protocol='tcp',
                    concurrency=concurrency,
                    timeout=timeout,
                    progress_cb=progress_formatter,
                ))
                
                rustscan_results = {}
                for ip, data in scan_results.items():
                    open_ports = [p["port"] for p in data["ports"] if p["status"] == "open"]
                    rustscan_results[ip] = open_ports

            batch_found = 0
            for ip, open_ports in rustscan_results.items():
                if open_ports:
                    batch_found += 1
                    if ip not in _partial_results:
                        _partial_results[ip] = {"summary": None, "device_type": None, "ports": []}
                    
                    for port in ssh_ports:
                        status = "open" if port in open_ports else "closed"
                        _partial_results[ip]["ports"].append({
                            "port": port,
                            "protocol": "TCP",
                            "status": status,
                            "info": "SSH" if status == "open" else ""
                        })
            
            total_scanned += len(targets)
            total_found += batch_found
            
            print(Fore.CYAN + f"\n[Batch #{batch_num} Summary]")
            print(Fore.WHITE + f"  • IPs scanned: {len(targets)}")
            print(Fore.GREEN + f"  • SSH servers found: {batch_found}")
            print(Fore.YELLOW + f"[Total] Scanned: {total_scanned} | Found: {total_found}" + Style.RESET_ALL)
            
            if batch_num % 5 == 0:
                save_partial_results(_partial_results, output, interrupted=False)
            
            if not continuous:
                break
                
    except KeyboardInterrupt:
        pass
    finally:
        if _partial_results:
            print(Fore.CYAN + "\n[*] Saving final results..." + Style.RESET_ALL)
            save_partial_results(_partial_results, output, interrupted=_scan_interrupted)
            
            if _partial_results:
                show_results_ui(_partial_results)
        
        signal.signal(signal.SIGINT, signal.SIG_DFL)

def show_results_ui(results):
    while True:
        rainbow_print("\nResults UI:", repeat=4)
        rainbow_print("1. Show all hosts", bright=False)
        rainbow_print("2. Show responsive hosts only", bright=False)
        rainbow_print("3. Show non-responsive hosts only", bright=False)
        rainbow_print("4. Back to main menu", bright=False)
        choice = input(Fore.MAGENTA + "Choose an option: ").strip()
        if choice == "1":
            print_results_table(results, "all")
        elif choice == "2":
            print_results_table(results, "responsive")
        elif choice == "3":
            print_results_table(results, "nonresponsive")
        elif choice == "4":
            break
        else:
            print(Fore.RED + "[!] Invalid choice.")

def settings_menu(args, misc_options, protocol_toggles):
    while True:
        rainbow_print("\nSettings:", repeat=4)
        rainbow_print("Miscellaneous Options:", bright=False)
        misc_status = f"Current: {format_misc_status(misc_options)}"
        rainbow_print(misc_status, bright=False)
        misc_keys = list(misc_options.keys())
        for idx, key in enumerate(misc_keys, start=1):
            state = "ON" if misc_options[key] else "OFF"
            rainbow_print(f" {idx}. {key:<15} -> {state}", bright=False)
        proto_start_idx = len(misc_keys) + 1
        rainbow_print("Protocol Options:", bright=False)
        proto_status = f"Current: {format_protocol_status(protocol_toggles)}"
        rainbow_print(proto_status, bright=False)
        proto_keys = list(protocol_toggles.keys())
        for idx, key in enumerate(proto_keys, start=proto_start_idx):
            state = "ON" if protocol_toggles[key] else "OFF"
            rainbow_print(f" {idx}. {key.upper()+' Protocol':<15} -> {state}", bright=False)
        rainbow_print(" T. Toggle option by number", bright=False)
        rainbow_print(" B. Back to main menu", bright=False)
        choice = input(Fore.MAGENTA + "Choose an option: ").strip().lower()
        if choice == "b":
            break
        if choice == "t":
            selection = input(Fore.CYAN + "Enter option number to toggle: ").strip()
            if not selection.isdigit():
                print(Fore.RED + "[!] Please enter a valid number.")
                continue
            idx = int(selection) - 1  
            if 0 <= idx < len(misc_keys):
                key = misc_keys[idx]
                misc_options[key] = not misc_options[key]
                sync_misc_to_args(args, misc_options)
                rainbow_print(f"[*] {key} set to {misc_options[key]}", bright=False)
            elif idx >= len(misc_keys) and idx < len(misc_keys) + len(proto_keys):
                key = proto_keys[idx - len(misc_keys)]
                protocol_toggles[key] = not protocol_toggles[key]
                rainbow_print(f"[*] {key.upper()} Protocol set to {protocol_toggles[key]}", bright=False)
            else:
                print(Fore.RED + "[!] Invalid selection.")
        else:
            print(Fore.RED + "[!] Invalid choice.")

def main():
    args = parse_args()
    misc_options = build_misc_options(args)
    protocol_toggles = build_misc_protocols(args.protocol)

    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    while True:
        rainbow_print("\n╔════════════════════════════════════════════════════════════╗")
        rainbow_print("║                    MAIN MENU                               ║")
        rainbow_print("╚════════════════════════════════════════════════════════════╝")
        rainbow_print(f"Settings: {format_misc_status(misc_options)}", bright=False)
        print()
        rainbow_print("1. SSH Mass Scanner (Time-Based Public IP Scanning)")
        rainbow_print("2. Custom Target Scan (Manual IP/CIDR Entry)")
        rainbow_print("3. Settings & Configuration")
        rainbow_print("4. Exit")
        print()
        choice = input(Fore.MAGENTA + "➤ Select option: ").strip()

        selected_protocols = [proto for proto, enabled in protocol_toggles.items() if enabled]

        if choice == "1":
            print(Fore.CYAN + "\n╔════════════════════════════════════════════════════════════╗")
            print(Fore.CYAN + "║           SSH MASS SCANNER - PUBLIC IP SWEEP               ║")
            print(Fore.CYAN + "╚════════════════════════════════════════════════════════════╝" + Style.RESET_ALL)
            
            if not misc_options.get("allow_public"):
                print(Fore.YELLOW + "\n⚠ WARNING: Public IP scanning requires authorization!")
                print(Fore.YELLOW + "Only scan networks you own or have permission to test." + Style.RESET_ALL)
                confirm = input(Fore.RED + "\nEnable public scanning and proceed? (y/N): ").strip().lower()
                if confirm == "y":
                    misc_options["allow_public"] = True
                    sync_misc_to_args(args, misc_options)
                    print(Fore.GREEN + "✓ Public scanning enabled" + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + "✗ Scan aborted." + Style.RESET_ALL)
                    continue
            
            print(Fore.CYAN + "\nScan Configuration:")
            print(Fore.WHITE + "  • Target: Random public IPs (auto-generated)")
            print(Fore.WHITE + "  • Ports: SSH (22, 2222, 2200, 22222)")
            print(Fore.WHITE + "  • Protocol: TCP only")
            print(Fore.WHITE + "  • Scanner: RustScan (if available) or Python fallback" + Style.RESET_ALL)
            
            print(Fore.MAGENTA + "\nScan Mode:")
            print(Fore.WHITE + "  1. Single Batch (scan 100 IPs and stop)")
            print(Fore.WHITE + "  2. Continuous (keep scanning until Ctrl+C)" + Style.RESET_ALL)
            
            mode_choice = input(Fore.MAGENTA + "\n➤ Select mode (1/2, default: 1): ").strip()
            continuous = (mode_choice == "2")
            
            batch_size_input = input(Fore.MAGENTA + "➤ IPs per batch (default: 100): ").strip()
            try:
                batch_size = int(batch_size_input) if batch_size_input else 100
                if batch_size <= 0 or batch_size > 1000:
                    print(Fore.RED + "[!] Batch size must be 1-1000. Using default 100.")
                    batch_size = 100
            except ValueError:
                print(Fore.RED + "[!] Invalid batch size. Using default 100.")
                batch_size = 100
            
            mode_str = "CONTINUOUS" if continuous else "SINGLE BATCH"
            print(Fore.GREEN + f"\n✓ Starting {mode_str} scan with {batch_size} IPs per batch..." + Style.RESET_ALL)
            perform_mass_scan(selected_protocols, args.timeout, args.output, misc_options, 
                            batch_size=batch_size, continuous=continuous)
        elif choice == "2":
            targets = get_targets()
            if not targets:
                print(Fore.RED + "[!] No targets entered.")
                continue
            ports = get_ports()
            perform_scan(
                targets,
                ports,
                selected_protocols,
                args.concurrency,
                args.timeout,
                args.output,
                allow_public=misc_options.get("allow_public", False),
                misc_options=misc_options,
            )
        elif choice == "3":
            settings_menu(args, misc_options, protocol_toggles)
        elif choice == "4":
            print(Fore.GREEN + "Exiting...")
            break
        else:
            print(Fore.RED + "[!] Invalid choice.")

if __name__ == "__main__":
    main()
