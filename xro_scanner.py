#!/usr/bin/env python3
"""
XRO Server Sniffer - Core scanning module (updated)

Features added:
 - Per-port status values: "open", "closed", "timeout", "no response", "error:..."
 - Distinguish TCP timeouts vs connection refused
 - scan_targets returns detailed per-port entries and a detected device_type per-IP based on banners + common ports
"""

import asyncio
import random
import socket
import subprocess
import sys
from ipaddress import ip_network, ip_address
from typing import List, Iterable, Tuple, Dict, Any, Callable, Optional

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 8080, 2222]

def generate_random_public_ips(count: int = 1000, duration: Optional[float] = None, progress_cb: Optional[Callable[[str], None]] = None) -> List[str]:
    """
    Generate public IPs efficiently. If duration is specified (in seconds), generate IPs for that duration.
    Otherwise, generate 'count' IPs.
    progress_cb: callback to report each IP being generated
    """
    import time
    import random
    ips = []
    start_time = time.time() if duration else None
    last_report = 0
    
    private_ranges = [
        (int(ip_address("0.0.0.0")), int(ip_address("0.255.255.255"))),
        (int(ip_address("10.0.0.0")), int(ip_address("10.255.255.255"))),
        (int(ip_address("100.64.0.0")), int(ip_address("100.127.255.255"))),
        (int(ip_address("127.0.0.0")), int(ip_address("127.255.255.255"))),
        (int(ip_address("169.254.0.0")), int(ip_address("169.254.255.255"))),
        (int(ip_address("172.16.0.0")), int(ip_address("172.31.255.255"))),
        (int(ip_address("192.0.0.0")), int(ip_address("192.0.0.255"))),
        (int(ip_address("192.0.2.0")), int(ip_address("192.0.2.255"))),
        (int(ip_address("192.168.0.0")), int(ip_address("192.168.255.255"))),
        (int(ip_address("198.18.0.0")), int(ip_address("198.19.255.255"))),
        (int(ip_address("198.51.100.0")), int(ip_address("198.51.100.255"))),
        (int(ip_address("203.0.113.0")), int(ip_address("203.0.113.255"))),
        (int(ip_address("224.0.0.0")), int(ip_address("239.255.255.255"))),
        (int(ip_address("240.0.0.0")), int(ip_address("255.255.255.255"))),
    ]
    
    def is_in_private_range(ip_int):
        for start, end in private_ranges:
            if start <= ip_int <= end:
                return True
        return False
    
    min_ip = int(ip_address("1.0.0.0"))
    max_ip = int(ip_address("223.255.255.255"))
    
    attempts = 0
    max_attempts = count * 10 if not duration else 1000000
    
    while attempts < max_attempts:
        if duration and (time.time() - start_time) >= duration:
            break
        if not duration and len(ips) >= count:
            break
        
        ip_int = random.randint(min_ip, max_ip)
        
        if is_in_private_range(ip_int):
            attempts += 1
            continue
            
        ip_str = str(ip_address(ip_int))
        if ip_str not in ips:
            ips.append(ip_str)
            if progress_cb and (len(ips) - last_report >= 50):
                progress_cb(ip_str)
                last_report = len(ips)
        
        attempts += 1
        
        if attempts % 1000 == 0:
            time.sleep(0.001)
    
    return ips

def is_public_ip(ip: str) -> bool:
    """Check if IP is a valid public IP (not private, loopback, multicast, etc.)"""
    try:
        a = ip_address(ip)
    except Exception:
        return False
    if a.is_private or a.is_loopback or a.is_multicast or a.is_reserved or a.is_link_local:
        return False
    return True

def is_allowed_ip(ip: str) -> bool:
    """Check if IP is allowed for scanning (private or loopback)"""
    try:
        a = ip_address(ip)
    except Exception:
        return False
    if a.is_loopback or a.is_private:
        return True
    return False

def expand_targets(specs: List[str]) -> Iterable[str]:
    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue
        try:
            if "/" in spec:
                net = ip_network(spec, strict=False)
                for h in net.hosts():
                    yield str(h)
            else:
                yield str(ip_address(spec))
        except Exception as e:
            print(f"[!] Ignoring invalid target spec '{spec}': {e}", file=sys.stderr)
            continue

async def tcp_check(
    ip: str,
    port: int,
    timeout: float = 2.0,
    sem: Optional[asyncio.Semaphore] = None,
    progress_cb: Optional[Callable[[str, int, str], None]] = None,
    status_cb: Optional[Callable[[str, int, str, str], None]] = None,
) -> Tuple[str, str]:
    """
    Try connecting with asyncio.open_connection (TCP).
    Returns (status, info)
    status is one of: "open", "closed", "timeout", "error"
    info contains banner (if open) or error description
    """
    protocol_label = "TCP"
    if sem is None:
        sem = asyncio.Semaphore(100)
    await sem.acquire()
    try:
        if progress_cb:
            progress_cb(ip, port, f"{protocol_label} establishing connection")
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            banner = ""
            try:
                writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=0.8)
                if data:
                    banner = data.decode('utf-8', errors='replace').strip()
            except Exception:
                banner = ""
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if progress_cb:
                progress_cb(ip, port, f"{protocol_label} open")
            status = "open"
            info = banner or "open"
            if status_cb:
                status_cb(ip, port, protocol_label, status)
            return status, info
        except asyncio.TimeoutError:
            if progress_cb:
                progress_cb(ip, port, f"{protocol_label} no response")
            status = "no response"
            info = ""
            if status_cb:
                status_cb(ip, port, protocol_label, status)
            return status, info
        except ConnectionRefusedError:
            if progress_cb:
                progress_cb(ip, port, f"{protocol_label} closed")
            status = "closed"
            info = "connection refused"
            if status_cb:
                status_cb(ip, port, protocol_label, status)
            return status, info
        except OSError as e:
            if progress_cb:
                progress_cb(ip, port, f"{protocol_label} error: {e}")
            status = "error"
            info = f"oserror:{e}"
            if status_cb:
                status_cb(ip, port, protocol_label, status)
            return status, info
        except Exception as e:
            if progress_cb:
                progress_cb(ip, port, f"{protocol_label} error: {e}")
            status = "error"
            info = f"err:{e}"
            if status_cb:
                status_cb(ip, port, protocol_label, status)
            return status, info
    finally:
        sem.release()

async def udp_check(
    ip: str,
    port: int,
    timeout: float = 2.0,
    sem: Optional[asyncio.Semaphore] = None,
    progress_cb: Optional[Callable[[str, int, str], None]] = None,
    status_cb: Optional[Callable[[str, int, str, str], None]] = None,
) -> Tuple[str, str]:
    """
    UDP probe: send an empty packet and wait for a response.
    Returns (status, info)
    """
    protocol_label = "UDP"
    if sem is None:
        sem = asyncio.Semaphore(100)
    await sem.acquire()
    try:
        if progress_cb:
            progress_cb(ip, port, f"{protocol_label} probing")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(b"", (ip, port))
            data, _ = sock.recvfrom(1024)
            if progress_cb:
                progress_cb(ip, port, f"{protocol_label} open")
            status = "open"
            info = data.decode('utf-8', errors='replace').strip() or "response"
            if status_cb:
                status_cb(ip, port, protocol_label, status)
            return status, info
        except socket.timeout:
            if progress_cb:
                progress_cb(ip, port, f"{protocol_label} no response")
            status = "no response"
            info = ""
            if status_cb:
                status_cb(ip, port, protocol_label, status)
            return status, info
        except ConnectionRefusedError:
            if progress_cb:
                progress_cb(ip, port, f"{protocol_label} closed")
            status = "closed"
            info = "connection refused (ICMP)"
            if status_cb:
                status_cb(ip, port, protocol_label, status)
            return status, info
        except Exception as e:
            if progress_cb:
                progress_cb(ip, port, f"{protocol_label} error: {e}")
            status = "error"
            info = f"err:{e}"
            if status_cb:
                status_cb(ip, port, protocol_label, status)
            return status, info
        finally:
            sock.close()
    finally:
        sem.release()

def detect_device_type(ports_info: List[Dict[str, Any]]) -> str:
    """
    Enhanced OS/device detection based on open ports and banners.
    Returns a detailed string describing OS type and services.
    """
    port_set = {p["port"] for p in ports_info if p.get("status") == "open"}
    banners = " ".join([p.get("info","") for p in ports_info if p.get("info")])
    banners_lower = banners.lower()

    if "ubuntu" in banners_lower:
        return "Linux - Ubuntu Server"
    if "centos" in banners_lower:
        return "Linux - CentOS"
    if "red hat" in banners_lower or "rhel" in banners_lower:
        return "Linux - Red Hat Enterprise"
    if "debian" in banners_lower:
        return "Linux - Debian"
    if "fedora" in banners_lower:
        return "Linux - Fedora"
    if "suse" in banners_lower or "opensuse" in banners_lower:
        return "Linux - SUSE"
    if "alpine" in banners_lower:
        return "Linux - Alpine (Container/Minimal)"
    if "arch" in banners_lower:
        return "Linux - Arch Linux"
    if "kali" in banners_lower:
        return "Linux - Kali (Security/Pentesting)"
    if "raspbian" in banners_lower or "raspberry" in banners_lower:
        return "Linux - Raspberry Pi OS"
    if "windows" in banners_lower or "win32" in banners_lower or "microsoft" in banners_lower:
        if "server 2022" in banners_lower:
            return "Windows Server 2022"
        if "server 2019" in banners_lower:
            return "Windows Server 2019"
        if "server 2016" in banners_lower:
            return "Windows Server 2016"
        if "server" in banners_lower:
            return "Windows Server"
        return "Windows OS"
    if "freebsd" in banners_lower:
        return "FreeBSD Unix"
    if "openbsd" in banners_lower:
        return "OpenBSD Unix"
    if "netbsd" in banners_lower:
        return "NetBSD Unix"
    if "solaris" in banners_lower or "sunos" in banners_lower:
        return "Solaris/SunOS Unix"
    if "macos" in banners_lower or "darwin" in banners_lower:
        return "macOS/Darwin"

    if 3389 in port_set:
        if 445 in port_set or 139 in port_set:
            return "Windows Server (RDP + SMB)"
        return "Windows (RDP Enabled)"
    
    if 445 in port_set or 139 in port_set:
        if 22 in port_set:
            return "Linux/Unix (Samba SMB)"
        return "Windows (SMB/File Sharing)"
    
    if 22 in port_set:
        if "openssh" in banners_lower:
            if "ubuntu" in banners_lower or "debian" in banners_lower:
                return "Linux Server (OpenSSH/Debian-based)"
            if "centos" in banners_lower or "rhel" in banners_lower or "fedora" in banners_lower:
                return "Linux Server (OpenSSH/RedHat-based)"
            return "Linux/Unix Server (OpenSSH)"
        if "dropbear" in banners_lower:
            return "Embedded Linux (Dropbear SSH)"
        if "ssh" in banners_lower:
            return "SSH Server (Unix-like)"
        return "SSH Server (Unknown OS)"
    
    if 80 in port_set or 8080 in port_set or 443 in port_set:
        if "nginx" in banners_lower:
            return "Linux Web Server (Nginx)"
        if "apache" in banners_lower:
            if "ubuntu" in banners_lower or "debian" in banners_lower:
                return "Linux Web Server (Apache/Debian)"
            return "Linux Web Server (Apache)"
        if "iis" in banners_lower or "microsoft-iis" in banners_lower:
            return "Windows Web Server (IIS)"
        if "lighttpd" in banners_lower:
            return "Linux Web Server (Lighttpd)"
        if "caddy" in banners_lower:
            return "Web Server (Caddy)"
        return "Web Server (Unknown OS)"
    
    if 21 in port_set:
        if "vsftpd" in banners_lower:
            return "Linux FTP Server (vsftpd)"
        if "proftpd" in banners_lower:
            return "Linux FTP Server (ProFTPD)"
        if "filezilla" in banners_lower:
            return "FTP Server (FileZilla)"
        return "FTP Server"
    
    if 23 in port_set:
        return "Telnet Server (Likely Embedded/IoT Device)"
    
    if 53 in port_set:
        if "bind" in banners_lower:
            return "Linux DNS Server (BIND)"
        return "DNS Server"
    
    if 3306 in port_set:
        if "mariadb" in banners_lower:
            return "Linux Database Server (MariaDB)"
        return "Database Server (MySQL/MariaDB)"
    
    if 5432 in port_set:
        return "Database Server (PostgreSQL)"
    
    if 1433 in port_set:
        return "Windows Database Server (MS SQL)"
    
    if 25 in port_set:
        if "postfix" in banners_lower:
            return "Linux Mail Server (Postfix)"
        if "exim" in banners_lower:
            return "Linux Mail Server (Exim)"
        if "sendmail" in banners_lower:
            return "Unix Mail Server (Sendmail)"
        return "Mail Server (SMTP)"
    
    if "rtsp" in banners_lower or "onvif" in banners_lower or "axis" in banners_lower:
        return "IP Camera/DVR (Embedded Linux)"
    if "hikvision" in banners_lower:
        return "IP Camera (Hikvision/Embedded)"
    if "dahua" in banners_lower:
        return "IP Camera (Dahua/Embedded)"
    
    if "router" in banners_lower or "mikrotik" in banners_lower or "ubnt" in banners_lower or "linksys" in banners_lower:
        return "Router/Network Device (Embedded)"
    if "openwrt" in banners_lower:
        return "Router (OpenWrt Linux)"
    if "dd-wrt" in banners_lower:
        return "Router (DD-WRT Linux)"
    if "pfsense" in banners_lower:
        return "Firewall (pfSense/FreeBSD)"
    if "cisco" in banners_lower:
        return "Cisco Network Device (IOS)"
    
    if port_set:
        return "Unknown OS (Services Detected)"
    return "No Open Ports"

async def scan_targets(
    ips: Iterable[str],
    ports: List[int],
    protocol: str = 'tcp',
    concurrency: int = 200,
    timeout: float = 2.0,
    progress_cb: Optional[Callable[[str, int, str], None]] = None,
    status_cb: Optional[Callable[[str, int, str, str], None]] = None,
):
    """
    Scan given ips x ports with improved memory management. Returns dict:
      { ip: {
          "summary": {"has_open": bool, "open_count": int, "total_ports": int},
          "device_type": str,
          "ports": [
              {"port": int, "protocol": "TCP"/"UDP", "status": "open"/"closed"/"timeout"/"error"/..., "info": "..."}
          ]
        }
      }
    """
    sem = asyncio.Semaphore(concurrency)
    results = {}
    
    ip_list = list(ips)

    batch_size = 10
    
    for batch_start in range(0, len(ip_list), batch_size):
        batch_ips = ip_list[batch_start:batch_start + batch_size]
        tasks = []
        
        for ip in batch_ips:
            if ip not in results:
                results[ip] = {"summary": None, "device_type": None, "ports": []}
            if progress_cb:
                try:
                    progress_cb(ip, -1, "starting host scan")
                except Exception:
                    pass
            
            for port in ports:
                if protocol.lower() == 'tcp':
                    coro = tcp_check(
                        ip,
                        port,
                        timeout=timeout,
                        sem=sem,
                        progress_cb=progress_cb,
                        status_cb=status_cb,
                    )
                elif protocol.lower() == 'udp':
                    coro = udp_check(
                        ip,
                        port,
                        timeout=timeout,
                        sem=sem,
                        progress_cb=progress_cb,
                        status_cb=status_cb,
                    )
                else:
                    raise ValueError("Unsupported protocol. Use 'tcp' or 'udp'.")
                task = asyncio.create_task(coro)
                tasks.append((task, ip, port))
        
        for task, ip, port in tasks:
            try:
                status, info = await task
            except asyncio.CancelledError:
                status, info = "error", "cancelled"
            except Exception as e:
                status, info = "error", f"exception:{e}"
            
            results[ip]["ports"].append({
                "port": port,
                "protocol": protocol.upper(),
                "status": status,
                "info": info
            })
        
        tasks.clear()
    
    for ip, data in results.items():
        ports_list = data["ports"]
        open_count = sum(1 for p in ports_list if p["status"] == "open")
        data["summary"] = {
            "has_open": open_count > 0,
            "open_count": open_count,
            "total_ports": len(ports_list)
        }
        data["device_type"] = detect_device_type(ports_list)

    return results

def parse_ports(spec: str) -> List[int]:
    out = set()
    parts = spec.split(",")
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if "-" in p:
            a,b = p.split("-",1)
            try:
                a_i = int(a); b_i = int(b)
                for x in range(max(1,a_i), min(65535,b_i)+1):
                    out.add(x)
            except:
                continue
        else:
            try:
                out.add(int(p))
            except:
                continue
    return sorted([x for x in out if 1 <= x <= 65535])

def validate_and_expand_targets(specs: List[str], allow_public: bool = False) -> List[str]:
    ips = list(expand_targets(specs))
    if not allow_public:
        blocked = [ip for ip in ips if not is_allowed_ip(ip)]
        if blocked:
            print("[!] Found public or non-private addresses in targets but public scanning not allowed.", file=sys.stderr)
            print("    To allow (risky), set allow_public=True.", file=sys.stderr)
            print("    Removing blocked targets:", file=sys.stderr)
            for b in blocked:
                print("     -", b, file=sys.stderr)
            ips = [ip for ip in ips if is_allowed_ip(ip)]
    return ips

def check_rustscan_available() -> bool:
    """Check if RustScan is installed and available"""
    try:
        result = subprocess.run(['rustscan', '--version'], 
                              capture_output=True, 
                              timeout=5,
                              creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return False

def scan_with_rustscan(ips: List[str], ports: List[int], timeout: float, progress_cb: Optional[Callable[[str, bool], None]] = None) -> Dict[str, List[int]]:
    """
    Use RustScan to scan TCP ports on given IPs.
    Returns dict of ip -> list of open ports.
    Falls back to Python scanning if RustScan is not available.
    progress_cb: callback(ip, is_valid) to report scanning progress
    """
    if not check_rustscan_available():
        print("[!] RustScan ")
        print("[*] Falling back to Python-based scanning...")
        return {}
    
    results = {}
    port_str = ','.join(map(str, ports))
    
    async def scan_batch(batch_ips: List[str]):
        """Scan a batch of IPs to prevent memory issues"""
        batch_results = {}
        sem = asyncio.Semaphore(20)
        
        async def scan_ip(ip: str):
            async with sem:
                try:
                    if progress_cb:
                        progress_cb(ip, None)
                    
                    cmd = [
                        'rustscan',
                        '-a', ip,
                        '-p', port_str,
                        '--timeout', str(int(timeout * 1000)),
                        '--batch-size', '1000',
                        '--tries', '1',
                        '--greppable'
                    ]
                    
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                    )
                    
                    try:
                        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
                    except asyncio.TimeoutError:
                        try:
                            proc.kill()
                        except:
                            pass
                        batch_results[ip] = []
                        if progress_cb:
                            progress_cb(ip, False)
                        return
                    
                    output = stdout.decode('utf-8', errors='ignore')
                    open_ports = []
                    
                    for line in output.split('\n'):
                        line = line.strip()
                        if '->' in line or 'Open' in line:
                            import re
                            port_matches = re.findall(r'\b(\d+)\b', line)
                            for port_str_match in port_matches:
                                try:
                                    port_num = int(port_str_match)
                                    if 1 <= port_num <= 65535 and port_num in ports:
                                        open_ports.append(port_num)
                                except ValueError:
                                    continue
                    
                    batch_results[ip] = list(set(open_ports))
                    if progress_cb:
                        progress_cb(ip, len(open_ports) > 0)
                        
                except Exception as e:
                    batch_results[ip] = []
                    if progress_cb:
                        progress_cb(ip, False)
        
        tasks = [scan_ip(ip) for ip in batch_ips]
        await asyncio.gather(*tasks, return_exceptions=True)
        return batch_results
    
    batch_size = 50
    for i in range(0, len(ips), batch_size):
        batch = ips[i:i + batch_size]
        try:
            batch_results = asyncio.run(scan_batch(batch))
            results.update(batch_results)
        except Exception as e:
            print(f"[!] Error scanning batch: {e}")
            for ip in batch:
                if ip not in results:
                    results[ip] = []
    
    return results
