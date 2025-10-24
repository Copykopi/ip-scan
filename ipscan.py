#!/usr/bin/env python3
import sys
import logging
import requests
import time
import socket
from scapy.all import Ether, ARP, srp, IP, TCP, sr1, conf
from colorama import init, Fore, Style


init(autoreset=True)

 
C_RESET = Style.RESET_ALL
C_JUDUL = Fore.CYAN + Style.BRIGHT
C_HEADER = Fore.YELLOW + Style.BRIGHT
C_SUKSES = Fore.GREEN
C_IP = Fore.GREEN + Style.BRIGHT
C_PORT = Fore.YELLOW
C_WARN = Fore.YELLOW + Style.BRIGHT
C_ERROR = Fore.RED + Style.BRIGHT
C_INFO = Fore.CYAN
C_VENDOR = Fore.MAGENTA
C_DIM = Style.DIM

COMMON_PORTS_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt"
}
# ----------------------------------------

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

def dapatkan_vendor_mac(mac):
    """Mencari vendor perangkat berdasarkan MAC address menggunakan API."""
    url = f"https://api.macvendors.com/{mac}"
    try:
        respons = requests.get(url, timeout=3)
        if respons.status_code == 200:
            return respons.text.strip()
        else:
            return "Vendor Tidak Dikenal"
    except requests.exceptions.RequestException:
        return "Gagal Cek Vendor"

def tebak_os(ttl):
    """Menebak OS berdasarkan nilai TTL."""
    ttl = int(ttl)
    if ttl <= 64:
        return "Linux / Unix / macOS"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Cisco / Solaris"

def ambil_banner(ip, port):
    """Mencoba melakukan 'banner grabbing' pada port yang terbuka."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5) 
        s.connect((ip, port))
        s.send(b'\r\n\r\n')
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return "".join(c for c in banner if c.isprintable())
    except Exception:
        return None

def temukan_host(ip_range):
    """Fase 1: Menemukan host di jaringan menggunakan ARP scan."""
    print(f"\n{C_INFO}[*] Fase 1: Memindai jaringan: {C_WARN}{ip_range}...")
    
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    
    try:
        terjawab, _ = srp(arp_request, timeout=2, retry=1)
    except PermissionError:
        print(f"\n{C_ERROR}[ERROR] Gagal mengirim paket. Script ini perlu hak akses root/administrator.")
        sys.exit(1)
    
    hosts = []
    
    print(f"\n{C_SUKSES}[+] Host Aktif Ditemukan:")
    print(C_HEADER + "-------------------------------------------------------------------------")
    print(C_HEADER + f"{'IP Address':<16} | {'MAC Address':<18} | {'Vendor Perangkat'}")
    print(C_HEADER + "-------------------------------------------------------------------------")

    for kirim, terima in terjawab:
        mac = terima.hwsrc
        ip = terima.psrc
        vendor = dapatkan_vendor_mac(mac)
        
        hosts.append({'ip': ip, 'mac': mac, 'vendor': vendor})
        
        print(f"{C_IP}{ip:<16} {C_DIM}| {mac:<18} | {C_VENDOR}{vendor}")
        time.sleep(0.1) 
        
    print(C_HEADER + "-------------------------------------------------------------------------")
    return hosts

def scan_port_syn(ip, port):
    """Memindai satu port menggunakan TCP SYN scan."""
    try:
        scan_paket = IP(dst=ip) / TCP(dport=port, flags="S")
        respons = sr1(scan_paket, timeout=0.5)
        
        if respons and respons.haslayer(TCP):
            if respons[TCP].flags == 0x12: # SYN-ACK
                rst_paket = IP(dst=ip) / TCP(dport=port, flags="R")
                sr1(rst_paket, timeout=0.5)
                return True, respons[IP].ttl
            else: # RST-ACK
                return False, None
        else: # Di-filter
            return False, None
    except Exception:
        return False, None

if __name__ == "__main__":
    
    print(C_JUDUL + "\n" + "="*55)
    print("           IP SCAN TOOLS BY Nyx     ")
    print("    (Network Scanner + OS/Service/Vendor Detection)")
    print(C_JUDUL + "="*55)
    
    try:
        print(f"{C_WARN}Masukkan network range Anda (cth: 192.168.1.0/24): ", end="")
        network_range = input()
        
        if not network_range:
            print(f"\n{C_ERROR}[ERROR] Network range tidak boleh kosong.")
            sys.exit(1)

        port_umum = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 5900, 8080]
    
       
        hosts_aktif = temukan_host(network_range)
        
        if not hosts_aktif:
            print(f"\n{C_WARN}[!] Tidak ada host aktif yang ditemukan.")
            sys.exit(0)
        
        print(f"\n{C_INFO}[*] Fase 2: Memulai port scanning pada {len(hosts_aktif)} host...")
        
        for host in hosts_aktif:
            print(f"\n--- Hasil Scan untuk {C_IP}{host['ip']} ({C_VENDOR}{host['vendor']}) ---")
            
            port_terbuka_ditemukan = False
            os_tertebak = "Tidak Diketahui"
            ttl_pertama = None

            for port in port_umum:
                terbuka, ttl_saat_ini = scan_port_syn(host['ip'], port)
                
                if terbuka:
                    port_terbuka_ditemukan = True
                    
                    if not ttl_pertama:
                        ttl_pertama = ttl_saat_ini
                        os_tertebak = tebak_os(ttl_pertama)
                    
                    service_name = COMMON_PORTS_SERVICES.get(port, "Lainnya")
                    
                   
                    banner = ambil_banner(host['ip'], port)
                    
                    
                    print(f"  {C_PORT}[!] Port {port:<5} ({service_name:<8}) TERBUKA")
                    if banner:
                        print(f"      {C_DIM}L-> {C_WARN}{banner}")
            
            if not port_terbuka_ditemukan:
                print(f"  {C_DIM}[i] Tidak ada port umum yang terbuka.")
            
            print(f"  {C_INFO}[i] Tebakan OS (via TTL {ttl_pertama}): {C_SUKSES}{os_tertebak}")
                
    except KeyboardInterrupt:
        print(f"\n\n{C_ERROR}[!] Proses dihentikan oleh pengguna.")
        sys.exit(0)
    except Exception as e:
        print(f"\n{C_ERROR}[ERROR] Terjadi kesalahan: {e}")
