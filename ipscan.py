import ipaddress
import requests
import socket
import subprocess
import concurrent.futures
import ssl
import os
import time
import dns.resolver
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import platform
import re
import folium
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import json
import webbrowser
import nmap  # Added for advanced scanning
import paramiko  # Added for SSH checks
import scapy.all as scapy  # Added for packet analysis
import geoip2.database  # Added for more accurate geolocation
import speedtest  # Added for better speed testing
import whois  # Added for domain whois
import cryptography  # Added for certificate analysis
from bs4 import BeautifulSoup  # Added for web scraping
import socketio  # Added for real-time updates
import matplotlib.pyplot as plt  # Added for graphing
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # Added for GUI graphs
import numpy as np  # Added for data analysis
import pandas as pd  # Added for data handling
import netifaces  # Added for network interface info
import pyperclip  # Added for clipboard support
import qrcode  # Added for QR code generation
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Configuration
CONFIG = {
    "virustotal_key": "81fcb279085331b577c95830aacb4baf90b1eb8dc16c890af5ecc1e36ec73398",
    "abuseipdb_key": "313eefef29f0a99a2e9218e2b7913e024e46ecb006f5e0f1322feac71b822e547f275663e68facba",
    "shodan_key": "Y5VLGOqBwOJvHX2oCJrNy5xZq4jerrmr4",
    "whoisxml_key": "44db1963e1e94b4fab95a5d88732c18bSXML_KEY",
    "maxmind_key": "",
    "theme": "dark",
    "default_ports": "21,22,80,443,3389,8080",
    "scan_threads": 100,
    "timeout": 5,
    "geoip_db_path": "GeoLite2-City.mmdb"
}

class UltimateNetworkAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Ultimate Network Analyzer Pro v3.0")
        self.root.geometry("1280x900")
        self.setup_theme()
        self.create_widgets()
        self.create_menu()
        self.load_icons()
        self.setup_tabs()
        self.setup_status_bar()
        self.setup_network_monitor()
        
    def setup_status_bar(self):
        self.status = StringVar()
        self.status.set("Ready")
        status_bar = Label(self.root, textvariable=self.status, bd=1, relief=SUNKEN, anchor=W)
        status_bar.pack(side=BOTTOM, fill=X)
        
    def setup_network_monitor(self):
        # Network traffic monitor frame
        self.traffic_frame = Frame(self.tools_tab, bg=self.bg_color)
        self.traffic_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Create figure for network traffic
        self.fig, self.ax = plt.subplots(figsize=(8, 4), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.traffic_frame)
        self.canvas.get_tk_widget().pack(side=TOP, fill=BOTH, expand=True)
        
        # Initialize data
        self.traffic_data = {'time': [], 'in': [], 'out': []}
        self.update_traffic_graph()

    def update_traffic_graph(self):
        # Simulate network traffic (replace with actual monitoring)
        import random
        now = datetime.now().strftime("%H:%M:%S")
        self.traffic_data['time'].append(now)
        self.traffic_data['in'].append(random.randint(100, 1000))
        self.traffic_data['out'].append(random.randint(50, 500))
        
        # Keep only last 10 data points
        if len(self.traffic_data['time']) > 10:
            for key in self.traffic_data:
                self.traffic_data[key] = self.traffic_data[key][-10:]
        
        # Update plot
        self.ax.clear()
        self.ax.plot(self.traffic_data['time'], self.traffic_data['in'], label='Incoming (KB/s)')
        self.ax.plot(self.traffic_data['time'], self.traffic_data['out'], label='Outgoing (KB/s)')
        self.ax.set_title('Network Traffic Monitor')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('KB/s')
        self.ax.legend()
        self.ax.grid(True)
        self.fig.autofmt_xdate()
        self.canvas.draw()
        
        # Schedule next update
        self.root.after(2000, self.update_traffic_graph)

    def setup_theme(self):
        self.style = ttk.Style()
        if CONFIG["theme"] == "dark":
            self.root.configure(bg='#2d2d2d')
            self.style.theme_use('clam')
            self.style.configure('.', background='#2d2d2d', foreground='white')
            self.style.map('TNotebook.Tab', background=[('selected', '#3d3d3d')])
            self.bg_color = '#2d2d2d'
            self.fg_color = 'white'
            self.entry_bg = '#3d3d3d'
        else:
            self.bg_color = 'white'
            self.fg_color = 'black'
            self.entry_bg = 'white'

    def load_icons(self):
        self.icons = {}
        try:
            icon_names = ["scan", "report", "dns", "geo", "tools", "speed", "ping", "trace"]
            for name in icon_names:
                img = Image.open(f"icons/{name}.png").resize((20,20))
                self.icons[name] = ImageTk.PhotoImage(img)
        except:
            # Fallback if icons not found
            self.icons = {name: None for name in icon_names}

    def create_widgets(self):
        # Header with logo
        header = Frame(self.root, bg=self.bg_color)
        header.pack(fill=X, pady=10)
        
        try:
            logo_img = Image.open("icons/logo.png").resize((150,40))
            self.logo = ImageTk.PhotoImage(logo_img)
            Label(header, image=self.logo, bg=self.bg_color).pack(side=LEFT, padx=10)
        except:
            Label(header, text="Ultimate Network Analyzer Pro", font=("Helvetica", 16), 
                 bg=self.bg_color, fg=self.fg_color).pack(side=LEFT, padx=10)
        
        # Main input area
        input_frame = Frame(self.root, bg=self.bg_color)
        input_frame.pack(pady=15)
        
        Label(input_frame, text="Target IP/Domain:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, padx=5)
        self.target_entry = Entry(input_frame, width=40, bg=self.entry_bg, fg=self.fg_color, 
                                insertbackground=self.fg_color)
        self.target_entry.grid(row=0, column=1, padx=5)
        self.target_entry.bind("<Return>", lambda e: self.analyze_target())
        
        Button(input_frame, text="Analyze", command=self.analyze_target, 
              bg='#4CAF50', fg='white').grid(row=0, column=2, padx=5)
        Button(input_frame, text="Quick Scan", command=self.quick_scan, 
              bg='#2196F3', fg='white').grid(row=0, column=3, padx=5)
        
        # Main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)

    def create_menu(self):
        menubar = Menu(self.root)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Report", command=self.generate_report)
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_command(label="Load Targets", command=self.load_targets)
        file_menu.add_separator()
        file_menu.add_command(label="Settings", command=self.open_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Speed Test", command=self.run_speed_test)
        tools_menu.add_command(label="Packet Loss Test", command=self.packet_loss_test)
        tools_menu.add_command(label="Port Scanner", command=self.focus_port_scanner)
        tools_menu.add_command(label="Network Sniffer", command=self.start_sniffer)
        tools_menu.add_command(label="Wi-Fi Analyzer", command=self.wifi_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dark Theme", command=lambda: self.change_theme("dark"))
        view_menu.add_command(label="Light Theme", command=lambda: self.change_theme("light"))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="Check for Updates", command=self.check_updates)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)

    def setup_tabs(self):
        # Overview Tab
        self.overview_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.overview_tab, text="Overview")
        self.setup_overview_tab()
        
        # Geolocation Tab
        self.geo_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.geo_tab, text="Geolocation")
        self.setup_geolocation_tab()
        
        # Network Tab
        self.network_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.network_tab, text="Network")
        self.setup_network_tab()
        
        # Security Tab
        self.security_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.security_tab, text="Security")
        self.setup_security_tab()
        
        # DNS Tab
        self.dns_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.dns_tab, text="DNS Tools")
        self.setup_dns_tab()
        
        # Port Scan Tab
        self.ports_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.ports_tab, text="Port Scanner")
        self.setup_ports_tab()
        
        # Tools Tab
        self.tools_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.tools_tab, text="Network Tools")
        self.setup_tools_tab()
        
        # New: Vulnerability Scanner Tab
        self.vuln_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.vuln_tab, text="Vulnerability Scanner")
        self.setup_vuln_tab()

    def setup_vuln_tab(self):
        # Vulnerability scanner controls
        vuln_controls = Frame(self.vuln_tab, bg=self.bg_color)
        vuln_controls.pack(fill=X, padx=5, pady=5)
        
        Label(vuln_controls, text="Target:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, padx=5)
        self.vuln_target_entry = Entry(vuln_controls, width=30, bg=self.entry_bg, fg=self.fg_color, 
                                     insertbackground=self.fg_color)
        self.vuln_target_entry.grid(row=0, column=1, padx=5)
        
        self.vuln_type = StringVar(value="quick")
        OptionMenu(vuln_controls, self.vuln_type, "quick", "full", "web", "ssh").grid(row=0, column=2, padx=5)
        
        Button(vuln_controls, text="Scan", command=self.run_vulnerability_scan, 
              bg='#FF5722', fg='white').grid(row=0, column=3, padx=5)
        
        # Vulnerability results
        self.vuln_text = Text(self.vuln_tab, wrap=WORD, bg=self.entry_bg, fg=self.fg_color, 
                            insertbackground=self.fg_color, font=("Consolas", 10))
        scroll = Scrollbar(self.vuln_tab, command=self.vuln_text.yview)
        self.vuln_text.configure(yscrollcommand=scroll.set)
        
        scroll.pack(side=RIGHT, fill=Y)
        self.vuln_text.pack(fill=BOTH, expand=True)

    def run_vulnerability_scan(self):
        target = self.vuln_target_entry.get().strip()
        scan_type = self.vuln_type.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        self.vuln_text.delete(1.0, END)
        self.append_text(self.vuln_text, f"Starting {scan_type} vulnerability scan on {target}...\n")
        self.root.update()
        
        try:
            nm = nmap.PortScanner()
            
            if scan_type == "quick":
                nm.scan(target, arguments='-T4 -F --script vuln')
            elif scan_type == "full":
                nm.scan(target, arguments='-T4 -A -v --script vuln')
            elif scan_type == "web":
                nm.scan(target, arguments='-T4 -p 80,443,8080,8443 --script http-vuln-*')
            elif scan_type == "ssh":
                nm.scan(target, arguments='-T4 -p 22 --script ssh-*')
            
            for host in nm.all_hosts():
                self.append_text(self.vuln_text, f"\nResults for {host}:\n")
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        port_data = nm[host][proto][port]
                        if 'script' in port_data:
                            self.append_text(self.vuln_text, f"\nPort {port}/{proto}:\n")
                            for script, output in port_data['script'].items():
                                self.append_text(self.vuln_text, f"  {script}:\n")
                                self.append_text(self.vuln_text, f"    {output}\n")
            
            self.append_text(self.vuln_text, "\nVulnerability scan completed\n")
        except Exception as e:
            self.append_text(self.vuln_text, f"Vulnerability scan failed: {str(e)}\n")

    def setup_overview_tab(self):
        self.overview_text = Text(self.overview_tab, wrap=WORD, bg=self.entry_bg, fg=self.fg_color, 
                                insertbackground=self.fg_color, state=DISABLED, font=("Consolas", 10))
        scroll = Scrollbar(self.overview_tab, command=self.overview_text.yview)
        self.overview_text.configure(yscrollcommand=scroll.set)
        
        scroll.pack(side=RIGHT, fill=Y)
        self.overview_text.pack(fill=BOTH, expand=True)

    def setup_geolocation_tab(self):
        # Map frame
        map_frame = Frame(self.geo_tab, bg=self.bg_color)
        map_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        self.map_label = Label(map_frame, text="Map will be generated here", bg=self.bg_color, fg=self.fg_color)
        self.map_label.pack(expand=True)
        
        # Geolocation data
        self.geo_text = Text(self.geo_tab, wrap=WORD, bg=self.entry_bg, fg=self.fg_color, 
                           insertbackground=self.fg_color, state=DISABLED, font=("Consolas", 10))
        scroll = Scrollbar(self.geo_tab, command=self.geo_text.yview)
        self.geo_text.configure(yscrollcommand=scroll.set)
        
        scroll.pack(side=RIGHT, fill=Y)
        self.geo_text.pack(fill=BOTH, expand=True)

    def setup_network_tab(self):
        # Network info controls
        net_controls = Frame(self.network_tab, bg=self.bg_color)
        net_controls.pack(fill=X, padx=5, pady=5)
        
        Button(net_controls, text="Show Local Interfaces", command=self.show_local_interfaces,
              bg='#4CAF50', fg='white').pack(side=LEFT, padx=5)
        
        Button(net_controls, text="Show Routing Table", command=self.show_routing_table,
              bg='#4CAF50', fg='white').pack(side=LEFT, padx=5)
        
        # Network results
        self.network_text = Text(self.network_tab, wrap=WORD, bg=self.entry_bg, fg=self.fg_color, 
                               insertbackground=self.fg_color, state=DISABLED, font=("Consolas", 10))
        scroll = Scrollbar(self.network_tab, command=self.network_text.yview)
        self.network_text.configure(yscrollcommand=scroll.set)
        
        scroll.pack(side=RIGHT, fill=Y)
        self.network_text.pack(fill=BOTH, expand=True)

    def show_local_interfaces(self):
        self.append_text(self.network_text, "\n[LOCAL NETWORK INTERFACES]\n")
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                self.append_text(self.network_text, f"\nInterface: {iface}\n")
                addrs = netifaces.ifaddresses(iface)
                for family, addr_info in addrs.items():
                    family_name = {
                        netifaces.AF_INET: 'IPv4',
                        netifaces.AF_INET6: 'IPv6',
                        netifaces.AF_LINK: 'MAC'
                    }.get(family, family)
                    
                    self.append_text(self.network_text, f"  {family_name}:\n")
                    for addr in addr_info:
                        for key, val in addr.items():
                            self.append_text(self.network_text, f"    {key}: {val}\n")
        except Exception as e:
            self.append_text(self.network_text, f"Error getting interfaces: {str(e)}\n")

    def show_routing_table(self):
        self.append_text(self.network_text, "\n[ROUTING TABLE]\n")
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["route", "print"], capture_output=True, text=True)
                self.append_text(self.network_text, result.stdout)
            else:
                result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
                self.append_text(self.network_text, result.stdout)
        except Exception as e:
            self.append_text(self.network_text, f"Error getting routing table: {str(e)}\n")

    def setup_security_tab(self):
        # Security controls
        sec_controls = Frame(self.security_tab, bg=self.bg_color)
        sec_controls.pack(fill=X, padx=5, pady=5)
        
        Button(sec_controls, text="Run Full Scan", command=self.run_full_security_scan, 
              bg='#4CAF50', fg='white').pack(side=LEFT, padx=5)
        
        Button(sec_controls, text="Check Web Security", command=self.check_web_security,
              bg='#2196F3', fg='white').pack(side=LEFT, padx=5)
        
        Button(sec_controls, text="Check Email Security", command=self.check_email_security,
              bg='#FF5722', fg='white').pack(side=LEFT, padx=5)
        
        # Security results
        self.security_text = Text(self.security_tab, wrap=WORD, bg=self.entry_bg, fg=self.fg_color, 
                                insertbackground=self.fg_color, state=DISABLED, font=("Consolas", 10))
        scroll = Scrollbar(self.security_tab, command=self.security_text.yview)
        self.security_text.configure(yscrollcommand=scroll.set)
        
        scroll.pack(side=RIGHT, fill=Y)
        self.security_text.pack(fill=BOTH, expand=True)

    def check_web_security(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "No target specified")
            return
            
        self.append_text(self.security_text, "\n[WEB SECURITY CHECK]\n")
        
        try:
            # Check HTTP headers
            url = f"http://{target}" if not target.startswith(('http://', 'https://')) else target
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            self.append_text(self.security_text, "\nHTTP Headers Analysis:\n")
            security_headers = [
                'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                'Content-Security-Policy', 'Strict-Transport-Security'
            ]
            
            for header in security_headers:
                if header in response.headers:
                    self.append_text(self.security_text, f"  {header}: {response.headers[header]} (Good)\n")
                else:
                    self.append_text(self.security_text, f"  {header}: Missing (Warning)\n")
            
            # Check for common vulnerabilities
            self.append_text(self.security_text, "\nCommon Vulnerability Checks:\n")
            
            # Check for clickjacking vulnerability
            if 'X-Frame-Options' not in response.headers:
                self.append_text(self.security_text, "  Clickjacking possible - X-Frame-Options missing\n")
            
            # Check for XSS protection
            if 'X-XSS-Protection' not in response.headers:
                self.append_text(self.security_text, "  XSS protection not enforced - X-XSS-Protection missing\n")
            
            # Check for MIME sniffing
            if 'X-Content-Type-Options' not in response.headers:
                self.append_text(self.security_text, "  MIME sniffing possible - X-Content-Type-Options missing\n")
            
            # Check for HTTPS redirect
            if not url.startswith('https://'):
                self.append_text(self.security_text, "  Site not using HTTPS (Warning)\n")
            
            # Check for server info disclosure
            if 'Server' in response.headers:
                self.append_text(self.security_text, f"  Server: {response.headers['Server']} (Info disclosure)\n")
            
            self.append_text(self.security_text, "\nWeb security check completed\n")
        except Exception as e:
            self.append_text(self.security_text, f"Web security check failed: {str(e)}\n")

    def check_email_security(self):
        domain = self.target_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "No target specified")
            return
            
        # If it's an IP, we can't check email security
        if self.is_valid_ip(domain):
            self.append_text(self.security_text, "\nCannot check email security for IP addresses\n")
            return
            
        self.append_text(self.security_text, "\n[EMAIL SECURITY CHECK]\n")
        
        try:
            # Check MX records
            answers = dns.resolver.resolve(domain, 'MX')
            mx_servers = [str(rdata.exchange) for rdata in answers]
            
            self.append_text(self.security_text, f"\nMail servers for {domain}:\n")
            for mx in mx_servers:
                self.append_text(self.security_text, f"  {mx}\n")
            
            # Check SPF record
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                spf_found = False
                for rdata in answers:
                    txt = ' '.join([s.decode() for s in rdata.strings])
                    if 'v=spf1' in txt:
                        spf_found = True
                        self.append_text(self.security_text, f"\nSPF Record: {txt}\n")
                        break
                
                if not spf_found:
                    self.append_text(self.security_text, "\nSPF Record: Not found (Warning)\n")
            except dns.resolver.NoAnswer:
                self.append_text(self.security_text, "\nSPF Record: Not found (Warning)\n")
            
            # Check DMARC record
            try:
                answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                dmarc_found = False
                for rdata in answers:
                    txt = ' '.join([s.decode() for s in rdata.strings])
                    if 'v=DMARC1' in txt:
                        dmarc_found = True
                        self.append_text(self.security_text, f"\nDMARC Record: {txt}\n")
                        break
                
                if not dmarc_found:
                    self.append_text(self.security_text, "\nDMARC Record: Not found (Warning)\n")
            except dns.resolver.NoAnswer:
                self.append_text(self.security_text, "\nDMARC Record: Not found (Warning)\n")
            
            # Check DKIM (this is domain-specific)
            try:
                answers = dns.resolver.resolve(f'selector1._domainkey.{domain}', 'TXT')
                for rdata in answers:
                    txt = ' '.join([s.decode() for s in rdata.strings])
                    if 'v=DKIM1' in txt:
                        self.append_text(self.security_text, f"\nDKIM Record (selector1): {txt}\n")
            except dns.resolver.NoAnswer:
                self.append_text(self.security_text, "\nDKIM Record (selector1): Not found (Warning)\n")
            
            self.append_text(self.security_text, "\nEmail security check completed\n")
        except Exception as e:
            self.append_text(self.security_text, f"Email security check failed: {str(e)}\n")

    def setup_dns_tab(self):
        # DNS controls
        dns_controls = Frame(self.dns_tab, bg=self.bg_color)
        dns_controls.pack(fill=X, padx=5, pady=5)
        
        Label(dns_controls, text="Domain:", bg=self.bg_color, fg=self.fg_color).pack(side=LEFT, padx=5)
        self.dns_entry = Entry(dns_controls, width=30, bg=self.entry_bg, fg=self.fg_color, 
                             insertbackground=self.fg_color)
        self.dns_entry.pack(side=LEFT, padx=5)
        
        self.dns_type = StringVar(value="A")
        OptionMenu(dns_controls, self.dns_type, "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR").pack(side=LEFT, padx=5)
        
        Button(dns_controls, text="Lookup", command=self.perform_dns_lookup, bg='#4CAF50', fg='white').pack(side=LEFT, padx=5)
        
        Button(dns_controls, text="Reverse DNS", command=self.perform_reverse_dns, 
              bg='#2196F3', fg='white').pack(side=LEFT, padx=5)
        
        Button(dns_controls, text="DNS Sec Check", command=self.check_dnssec, 
              bg='#FF5722', fg='white').pack(side=LEFT, padx=5)
        
        # DNS results
        self.dns_text = Text(self.dns_tab, wrap=WORD, bg=self.entry_bg, fg=self.fg_color, 
                           insertbackground=self.fg_color, state=DISABLED, font=("Consolas", 10))
        scroll = Scrollbar(self.dns_tab, command=self.dns_text.yview)
        self.dns_text.configure(yscrollcommand=scroll.set)
        
        scroll.pack(side=RIGHT, fill=Y)
        self.dns_text.pack(fill=BOTH, expand=True)

    def perform_reverse_dns(self):
        ip = self.dns_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return
            
        self.dns_text.config(state=NORMAL)
        self.dns_text.delete(1.0, END)
        
        try:
            self.append_text(self.dns_text, f"[REVERSE DNS LOOKUP FOR: {ip}]\n{'='*50}\n\n")
            
            try:
                hostname, aliases, addresses = socket.gethostbyaddr(ip)
                self.append_text(self.dns_text, f"Hostname: {hostname}\n")
                if aliases:
                    self.append_text(self.dns_text, f"Aliases: {', '.join(aliases)}\n")
                self.append_text(self.dns_text, f"Addresses: {', '.join(addresses)}\n")
            except socket.herror:
                self.append_text(self.dns_text, "No reverse DNS record found\n")
            
        except Exception as e:
            self.append_text(self.dns_text, f"Error: {str(e)}\n")
        
        self.dns_text.config(state=DISABLED)

    def check_dnssec(self):
        domain = self.dns_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return
            
        self.dns_text.config(state=NORMAL)
        self.dns_text.delete(1.0, END)
        
        try:
            self.append_text(self.dns_text, f"[DNSSEC VALIDATION FOR: {domain}]\n{'='*50}\n\n")
            
            try:
                # Check for DNSKEY records
                answers = dns.resolver.resolve(domain, 'DNSKEY')
                self.append_text(self.dns_text, "DNSSEC is enabled for this domain\n")
                self.append_text(self.dns_text, f"Found {len(answers)} DNSKEY records\n")
                
                # Check for DS records at parent
                try:
                    answers = dns.resolver.resolve(domain, 'DS')
                    self.append_text(self.dns_text, f"Found {len(answers)} DS records at parent\n")
                    self.append_text(self.dns_text, "DNSSEC validation chain is complete\n")
                except dns.resolver.NoAnswer:
                    self.append_text(self.dns_text, "Warning: No DS records at parent (DNSSEC validation may fail)\n")
                
            except dns.resolver.NoAnswer:
                self.append_text(self.dns_text, "DNSSEC is not enabled for this domain\n")
            
        except Exception as e:
            self.append_text(self.dns_text, f"Error: {str(e)}\n")
        
        self.dns_text.config(state=DISABLED)

    def setup_ports_tab(self):
        # Port scan controls
        port_controls = Frame(self.ports_tab, bg=self.bg_color)
        port_controls.pack(fill=X, padx=5, pady=5)
        
        Label(port_controls, text="Target:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, padx=5)
        self.port_target_entry = Entry(port_controls, width=25, bg=self.entry_bg, fg=self.fg_color, 
                                     insertbackground=self.fg_color)
        self.port_target_entry.grid(row=0, column=1, padx=5)
        
        Label(port_controls, text="Ports:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=2, padx=5)
        self.port_range_entry = Entry(port_controls, width=25, bg=self.entry_bg, fg=self.fg_color, 
                                    insertbackground=self.fg_color)
        self.port_range_entry.grid(row=0, column=3, padx=5)
        self.port_range_entry.insert(0, CONFIG["default_ports"])
        
        Button(port_controls, text="Scan", command=self.scan_ports, bg='#4CAF50', fg='white').grid(row=0, column=4, padx=5)
        
        # Scan type options
        self.scan_type = StringVar(value="connect")
        OptionMenu(port_controls, self.scan_type, "connect", "syn", "udp", "os").grid(row=0, column=5, padx=5)
        
        # Quick scan buttons
        Button(port_controls, text="Common", command=lambda: self.set_port_range("21,22,80,443,3389")).grid(row=1, column=1, pady=5)
        Button(port_controls, text="Top 100", command=lambda: self.set_port_range("1-100")).grid(row=1, column=2, pady=5)
        Button(port_controls, text="All", command=lambda: self.set_port_range("1-65535")).grid(row=1, column=3, pady=5)
        
        # Port scan results
        self.ports_text = Text(self.ports_tab, wrap=WORD, bg=self.entry_bg, fg=self.fg_color, 
                             insertbackground=self.fg_color, font=("Consolas", 10))
        scroll = Scrollbar(self.ports_tab, command=self.ports_text.yview)
        self.ports_text.configure(yscrollcommand=scroll.set)
        
        scroll.pack(side=RIGHT, fill=Y)
        self.ports_text.pack(fill=BOTH, expand=True)

    def setup_tools_tab(self):
        # Ping controls
        ping_frame = LabelFrame(self.tools_tab, text="Ping Test", bg=self.bg_color, fg=self.fg_color)
        ping_frame.pack(fill=X, padx=5, pady=5)
        
        Label(ping_frame, text="Target:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, padx=5)
        self.ping_entry = Entry(ping_frame, width=30, bg=self.entry_bg, fg=self.fg_color, 
                              insertbackground=self.fg_color)
        self.ping_entry.grid(row=0, column=1, padx=5)
        self.ping_entry.insert(0, "google.com")
        
        Button(ping_frame, text="Ping", command=self.do_ping, bg='#4CAF50', fg='white').grid(row=0, column=2, padx=5)
        
        Button(ping_frame, text="Continuous", command=self.do_continuous_ping, 
              bg='#2196F3', fg='white').grid(row=0, column=3, padx=5)
        
        self.ping_results = Text(ping_frame, height=8, wrap=WORD, bg=self.entry_bg, fg=self.fg_color, 
                               insertbackground=self.fg_color, font=("Consolas", 10))
        scroll = Scrollbar(ping_frame, command=self.ping_results.yview)
        self.ping_results.configure(yscrollcommand=scroll.set)
        
        scroll.grid(row=1, column=4, sticky=NS)
        self.ping_results.grid(row=1, column=0, columnspan=4, sticky=NSEW)
        
        # Traceroute controls
        trace_frame = LabelFrame(self.tools_tab, text="Traceroute", bg=self.bg_color, fg=self.fg_color)
        trace_frame.pack(fill=X, padx=5, pady=5)
        
        Label(trace_frame, text="Target:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, padx=5)
        self.trace_entry = Entry(trace_frame, width=30, bg=self.entry_bg, fg=self.fg_color, 
                               insertbackground=self.fg_color)
        self.trace_entry.grid(row=0, column=1, padx=5)
        self.trace_entry.insert(0, "google.com")
        
        Button(trace_frame, text="Trace", command=self.do_traceroute, bg='#4CAF50', fg='white').grid(row=0, column=2, padx=5)
        
        self.trace_results = Text(trace_frame, height=8, wrap=WORD, bg=self.entry_bg, fg=self.fg_color, 
                                insertbackground=self.fg_color, font=("Consolas", 10))
        scroll = Scrollbar(trace_frame, command=self.trace_results.yview)
        self.trace_results.configure(yscrollcommand=scroll.set)
        
        scroll.grid(row=1, column=3, sticky=NS)
        self.trace_results.grid(row=1, column=0, columnspan=3, sticky=NSEW)
        
        # New: Network utilities
        util_frame = LabelFrame(self.tools_tab, text="Network Utilities", bg=self.bg_color, fg=self.fg_color)
        util_frame.pack(fill=X, padx=5, pady=5)
        
        Button(util_frame, text="Whois Lookup", command=self.do_whois_lookup, 
              bg='#9C27B0', fg='white').grid(row=0, column=0, padx=5, pady=5)
        
        Button(util_frame, text="Generate QR Code", command=self.generate_qr_code, 
              bg='#009688', fg='white').grid(row=0, column=1, padx=5, pady=5)
        
        Button(util_frame, text="MAC Vendor Lookup", command=self.mac_vendor_lookup, 
              bg='#795548', fg='white').grid(row=0, column=2, padx=5, pady=5)
        
        Button(util_frame, text="Subnet Calculator", command=self.subnet_calculator, 
              bg='#607D8B', fg='white').grid(row=0, column=3, padx=5, pady=5)

    def do_whois_lookup(self):
        domain = simpledialog.askstring("Whois Lookup", "Enter domain or IP:")
        if not domain:
            return
            
        try:
            w = whois.whois(domain)
            result = "\n".join([f"{k}: {v}" for k, v in w.items()])
            self.show_result_window("Whois Results", result)
        except Exception as e:
            messagebox.showerror("Error", f"Whois lookup failed: {str(e)}")

    def generate_qr_code(self):
        data = simpledialog.askstring("QR Code Generator", "Enter text or URL:")
        if not data:
            return
            
        try:
            img = qrcode.make(data)
            img.show()
        except Exception as e:
            messagebox.showerror("Error", f"QR code generation failed: {str(e)}")

    def mac_vendor_lookup(self):
        mac = simpledialog.askstring("MAC Vendor Lookup", "Enter MAC address (format: 00:11:22:AA:BB:CC):")
        if not mac:
            return
            
        try:
            # Remove any non-hex characters
            mac = ''.join(c for c in mac if c in '0123456789ABCDEFabcdef')
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url)
            if response.status_code == 200:
                self.show_result_window("MAC Vendor", response.text)
            else:
                messagebox.showerror("Error", "Vendor not found or API error")
        except Exception as e:
            messagebox.showerror("Error", f"MAC lookup failed: {str(e)}")

    def subnet_calculator(self):
        ip = simpledialog.askstring("Subnet Calculator", "Enter IP address (e.g., 192.168.1.0/24):")
        if not ip:
            return
            
        try:
            network = ipaddress.ip_network(ip, strict=False)
            result = f"""
Network Address: {network.network_address}
Broadcast Address: {network.broadcast_address}
Netmask: {network.netmask}
Hostmask: {network.hostmask}
Total Addresses: {network.num_addresses}
Usable Hosts: {network.num_addresses - 2}
First Usable: {next(network.hosts())}
Last Usable: {list(network.hosts())[-1]}
"""
            self.show_result_window("Subnet Calculator", result.strip())
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid IP/subnet: {str(e)}")

    def show_result_window(self, title, text):
        window = Toplevel(self.root)
        window.title(title)
        
        text_widget = Text(window, wrap=WORD, font=("Consolas", 10))
        text_widget.insert(END, text)
        text_widget.config(state=DISABLED)
        text_widget.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        Button(window, text="Copy to Clipboard", command=lambda: pyperclip.copy(text)).pack(pady=5)
        Button(window, text="Close", command=window.destroy).pack(pady=5)

    def analyze_target(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        try:
            self.clear_results()
            self.status.set(f"Analyzing {target}...")
            self.root.update()
            
            # Resolve domain to IP if needed
            if not self.is_valid_ip(target):
                try:
                    resolved_ip = socket.gethostbyname(target)
                    self.append_text(self.overview_text, f"Resolved {target} to {resolved_ip}\n")
                    target = resolved_ip
                except socket.gaierror:
                    messagebox.showerror("Error", "Could not resolve domain")
                    return
            
            ip = ipaddress.ip_address(target)
            
            # Update port scan target
            self.port_target_entry.delete(0, END)
            self.port_target_entry.insert(0, str(ip))
            self.vuln_target_entry.delete(0, END)
            self.vuln_target_entry.insert(0, str(ip))
            
            # Start analysis
            self.show_basic_info(ip)
            self.show_geolocation(ip)
            self.show_network_info(ip)
            self.run_security_checks(ip)
            
            # If target was a domain, use it for DNS lookups
            if not self.is_valid_ip(self.target_entry.get().strip()):
                self.dns_entry.delete(0, END)
                self.dns_entry.insert(0, self.target_entry.get().strip())
                self.perform_dns_lookup()
            
            self.status.set("Analysis completed successfully")
            messagebox.showinfo("Success", "Analysis completed successfully")
            
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address format")
        except Exception as e:
            self.status.set(f"Analysis failed: {str(e)}")
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")

    def quick_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        try:
            self.clear_results()
            self.status.set(f"Quick scanning {target}...")
            self.root.update()
            
            # Resolve domain to IP if needed
            if not self.is_valid_ip(target):
                try:
                    resolved_ip = socket.gethostbyname(target)
                    self.append_text(self.overview_text, f"Resolved {target} to {resolved_ip}\n")
                    target = resolved_ip
                except socket.gaierror:
                    messagebox.showerror("Error", "Could not resolve domain")
                    return
            
            ip = ipaddress.ip_address(target)
            
            # Quick checks
            self.append_text(self.overview_text, f"\n[QUICK SCAN RESULTS]\n{'='*50}\n")
            self.append_text(self.overview_text, f"Target: {ip}\n")
            
            # Ping test
            self.append_text(self.overview_text, "\nPing Test:\n")
            try:
                count = "4" if platform.system().lower() == "windows" else "c"
                cmd = ["ping", f"-{count}", "4", str(ip)]
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()
                if error:
                    self.append_text(self.overview_text, f"Error: {error.decode()}")
                else:
                    self.append_text(self.overview_text, output.decode())
            except Exception as e:
                self.append_text(self.overview_text, f"Ping failed: {str(e)}\n")
            
            # Quick port scan
            self.append_text(self.overview_text, "\nQuick Port Scan (Top 10):\n")
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]
            for port in common_ports:
                if self.is_port_open(str(ip), port):
                    self.append_text(self.overview_text, f"Port {port} is open - {self.get_service_name(port)}\n")
            
            # Quick security check
            self.append_text(self.overview_text, "\nQuick Security Check:\n")
            vt_result = self.check_virustotal(ip)
            self.append_text(self.overview_text, f"VirusTotal: {vt_result}\n")
            
            spamhaus_status = self.check_spamhaus(ip)
            self.append_text(self.overview_text, f"Spamhaus Status: {spamhaus_status}\n")
            
            self.status.set("Quick scan completed")
            messagebox.showinfo("Success", "Quick scan completed successfully")
            
        except Exception as e:
            self.status.set(f"Quick scan failed: {str(e)}")
            messagebox.showerror("Error", f"Quick scan failed: {str(e)}")

    def show_basic_info(self, ip):
        self.append_text(self.overview_text, f"[BASIC INFORMATION]\n{'='*50}\n")
        self.append_text(self.overview_text, f"IP Address: {ip}\n")
        self.append_text(self.overview_text, f"Version: {'IPv6' if isinstance(ip, ipaddress.IPv6Address) else 'IPv4'}\n")
        self.append_text(self.overview_text, f"Public/Private: {'Private' if ip.is_private else 'Public'}\n")
        self.append_text(self.overview_text, f"Reserved: {'Yes' if ip.is_reserved else 'No'}\n")
        self.append_text(self.overview_text, f"Multicast: {'Yes' if ip.is_multicast else 'No'}\n")
        self.append_text(self.overview_text, f"Loopback: {'Yes' if ip.is_loopback else 'No'}\n")
        self.append_text(self.overview_text, f"Link-local: {'Yes' if ip.is_link_local else 'No'}\n")
        
        # Check if Tor exit node
        if self.is_tor_exit_node(ip):
            self.append_text(self.overview_text, "Tor Exit Node: Yes (Warning: May be used for anonymous browsing)\n")
        
        # Check Spamhaus
        spamhaus_status = self.check_spamhaus(ip)
        self.append_text(self.overview_text, f"Spamhaus Status: {spamhaus_status}\n")
        
        # Check if IP is in any cloud provider range
        cloud_provider = self.check_cloud_provider(ip)
        if cloud_provider:
            self.append_text(self.overview_text, f"Cloud Provider: {cloud_provider}\n")

    def check_cloud_provider(self, ip):
        # Load cloud provider IP ranges (simplified for example)
        cloud_ranges = {
            'AWS': ['13.32.0.0/15', '15.230.0.0/16'],
            'Azure': ['13.64.0.0/11', '20.33.0.0/16'],
            'GCP': ['8.34.0.0/16', '23.236.48.0/20']
        }
        
        ip_obj = ipaddress.ip_address(str(ip))
        for provider, ranges in cloud_ranges.items():
            for range in ranges:
                if ip_obj in ipaddress.ip_network(range):
                    return provider
        return None

    def show_geolocation(self, ip):
        self.append_text(self.geo_text, f"[GEOLOCATION DATA]\n{'='*50}\n")
        
        try:
            # First try MaxMind local database if available
            if os.path.exists(CONFIG["geoip_db_path"]):
                with geoip2.database.Reader(CONFIG["geoip_db_path"]) as reader:
                    response = reader.city(str(ip))
                    
                    self.append_text(self.geo_text, f"Country: {response.country.name} ({response.country.iso_code})\n")
                    self.append_text(self.geo_text, f"City: {response.city.name}\n")
                    self.append_text(self.geo_text, f"Postal Code: {response.postal.code}\n")
                    self.append_text(self.geo_text, f"Coordinates: {response.location.latitude}, {response.location.longitude}\n")
                    self.append_text(self.geo_text, f"Timezone: {response.location.time_zone}\n")
                    self.append_text(self.geo_text, f"ISP: {response.traits.isp}\n")
                    self.append_text(self.geo_text, f"Organization: {response.traits.organization}\n")
                    self.append_text(self.geo_text, f"Network: {response.traits.network}\n")
                    
                    # Generate map if we have coordinates
                    if response.location.latitude and response.location.longitude:
                        self.generate_map(response.location.latitude, response.location.longitude, 
                                        str(ip), f"{response.city.name}, {response.country.name}")
                    return
            
            # Fallback to ip-api.com if MaxMind not available
            geo_url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
            geo_data = requests.get(geo_url, timeout=CONFIG["timeout"]).json()
            
            if geo_data.get('status') == 'success':
                self.append_text(self.geo_text, f"Country: {geo_data.get('country', 'N/A')}\n")
                self.append_text(self.geo_text, f"Region: {geo_data.get('regionName', 'N/A')}\n")
                self.append_text(self.geo_text, f"City: {geo_data.get('city', 'N/A')}\n")
                self.append_text(self.geo_text, f"ZIP Code: {geo_data.get('zip', 'N/A')}\n")
                self.append_text(self.geo_text, f"Coordinates: {geo_data.get('lat', 'N/A')}, {geo_data.get('lon', 'N/A')}\n")
                self.append_text(self.geo_text, f"Timezone: {geo_data.get('timezone', 'N/A')}\n")
                self.append_text(self.geo_text, f"ISP: {geo_data.get('isp', 'N/A')}\n")
                self.append_text(self.geo_text, f"Organization: {geo_data.get('org', 'N/A')}\n")
                self.append_text(self.geo_text, f"AS Number: {geo_data.get('as', 'N/A')}\n")
                self.append_text(self.geo_text, f"AS Name: {geo_data.get('asname', 'N/A')}\n")
                self.append_text(self.geo_text, f"Reverse DNS: {geo_data.get('reverse', 'N/A')}\n")
                self.append_text(self.geo_text, f"Mobile: {'Yes' if geo_data.get('mobile') else 'No'}\n")
                self.append_text(self.geo_text, f"Proxy/VPN: {'Yes' if geo_data.get('proxy') else 'No'}\n")
                self.append_text(self.geo_text, f"Hosting: {'Yes' if geo_data.get('hosting') else 'No'}\n")
                
                # Generate map if we have coordinates
                if geo_data.get('lat') and geo_data.get('lon'):
                    self.generate_map(geo_data['lat'], geo_data['lon'], str(ip), 
                                    f"{geo_data.get('city', '')}, {geo_data.get('country', '')}")
            else:
                self.append_text(self.geo_text, "Geolocation data unavailable\n")
        except Exception as e:
            self.append_text(self.geo_text, f"Geolocation lookup failed: {str(e)}\n")

    def generate_map(self, lat, lon, ip, location_name):
        try:
            m = folium.Map(location=[lat, lon], zoom_start=10)
            folium.Marker(
                [lat, lon],
                popup=f"<b>{ip}</b><br>{location_name}",
                tooltip="Click for details",
                icon=folium.Icon(color='red', icon='info-sign')
            ).add_to(m)
            
            # Add circle for approximate location accuracy
            folium.Circle(
                location=[lat, lon],
                radius=5000,  # 5km radius
                color='blue',
                fill=True,
                fill_color='blue'
            ).add_to(m)
            
            # Save map to file
            map_file = f"map_{ip.replace('.', '_')}.html"
            m.save(map_file)
            
            # Update UI with map link
            self.map_label.config(text=f"Map generated: {map_file}")
            self.map_label.bind("<Button-1>", lambda e: webbrowser.open(map_file))
        except Exception as e:
            self.append_text(self.geo_text, f"Map generation failed: {str(e)}\n")

    def show_network_info(self, ip):
        self.append_text(self.network_text, f"[NETWORK INFORMATION]\n{'='*50}\n")
        
        try:
            # Get WHOIS data
            whois_data = self.get_whois(str(ip))
            self.append_text(self.network_text, f"WHOIS Data:\n{whois_data[:2000]}...\n\n")
            
            # Get reverse DNS
            try:
                hostname, aliases, addresses = socket.gethostbyaddr(str(ip))
                self.append_text(self.network_text, f"Reverse DNS: {hostname}\n")
                if aliases:
                    self.append_text(self.network_text, f"Aliases: {', '.join(aliases)}\n")
                self.append_text(self.network_text, f"Addresses: {', '.join(addresses)}\n")
            except socket.herror:
                self.append_text(self.network_text, "Reverse DNS: Not found\n")
            
            # Get ASN info if Shodan is configured
            if CONFIG["shodan_key"] != "YOUR_SHODAN_KEY":
                shodan_data = self.get_shodan_info(str(ip))
                if shodan_data:
                    self.append_text(self.network_text, f"\nShodan Data:\n")
                    self.append_text(self.network_text, f"ASN: {shodan_data.get('asn', 'N/A')}\n")
                    self.append_text(self.network_text, f"ISP: {shodan_data.get('isp', 'N/A')}\n")
                    self.append_text(self.network_text, f"Ports: {', '.join(map(str, shodan_data.get('ports', [])))}\n")
                    self.append_text(self.network_text, f"Hostnames: {', '.join(shodan_data.get('hostnames', []))}\n")
                    self.append_text(self.network_text, f"Last Update: {shodan_data.get('last_update', 'N/A')}\n")
        except Exception as e:
            self.append_text(self.network_text, f"Error getting network info: {str(e)}\n")

    def run_security_checks(self, ip):
        self.append_text(self.security_text, f"[SECURITY ANALYSIS]\n{'='*50}\n")
        
        # VirusTotal check
        vt_result = self.check_virustotal(ip)
        self.append_text(self.security_text, f"VirusTotal: {vt_result}\n")
        
        # AbuseIPDB check
        if CONFIG["abuseipdb_key"] != "YOUR_ABUSEIPDB_KEY":
            abuse_result = self.check_abuseipdb(ip)
            self.append_text(self.security_text, f"AbuseIPDB: {abuse_result}\n")
        
        # SSL Certificate check
        ssl_info = self.get_ssl_certificate(str(ip))
        if ssl_info:
            self.append_text(self.security_text, "\n[SSL CERTIFICATE]\n")
            self.append_text(self.security_text, f"Issuer: {ssl_info.get('issuer', 'N/A')}\n")
            self.append_text(self.security_text, f"Expires: {ssl_info.get('notAfter', 'N/A')}\n")
            self.append_text(self.security_text, f"Subject: {ssl_info.get('subject', 'N/A')}\n")
            self.append_text(self.security_text, f"Serial: {ssl_info.get('serial', 'N/A')}\n")
            self.append_text(self.security_text, f"Version: {ssl_info.get('version', 'N/A')}\n")
            
            # Check certificate expiration
            expire_date = datetime.strptime(ssl_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.now()).days
            self.append_text(self.security_text, f"Days Until Expiration: {days_left}\n")
            if days_left < 30:
                self.append_text(self.security_text, "Warning: Certificate expiring soon!\n")
        
        # Check open ports for common vulnerabilities
        self.append_text(self.security_text, "\n[QUICK SECURITY SCAN]\n")
        common_ports = [21, 22, 23, 80, 443, 3389]
        for port in common_ports:
            if self.is_port_open(str(ip), port):
                self.append_text(self.security_text, f"Port {port} is open - {self.get_port_vulnerability(port)}\n")

    def perform_dns_lookup(self):
        domain = self.dns_entry.get().strip()
        record_type = self.dns_type.get()
        
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return
            
        self.dns_text.config(state=NORMAL)
        self.dns_text.delete(1.0, END)
        
        try:
            self.append_text(self.dns_text, f"[DNS LOOKUP FOR: {domain} ({record_type} RECORDS)]\n{'='*50}\n\n")
            
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    if record_type == 'TXT':
                        self.append_text(self.dns_text, f"  {', '.join([s.decode() for s in rdata.strings])}\n")
                    elif record_type == 'MX':
                        self.append_text(self.dns_text, f"  Preference: {rdata.preference}, Exchange: {rdata.exchange}\n")
                    elif record_type == 'SOA':
                        self.append_text(self.dns_text, f"  MNAME: {rdata.mname}\n")
                        self.append_text(self.dns_text, f"  RNAME: {rdata.rname}\n")
                        self.append_text(self.dns_text, f"  Serial: {rdata.serial}\n")
                        self.append_text(self.dns_text, f"  Refresh: {rdata.refresh}\n")
                        self.append_text(self.dns_text, f"  Retry: {rdata.retry}\n")
                        self.append_text(self.dns_text, f"  Expire: {rdata.expire}\n")
                        self.append_text(self.dns_text, f"  Minimum: {rdata.minimum}\n")
                    else:
                        self.append_text(self.dns_text, f"  {rdata.to_text()}\n")
            except dns.resolver.NoAnswer:
                self.append_text(self.dns_text, f"No {record_type} records found\n")
            except dns.resolver.NXDOMAIN:
                self.append_text(self.dns_text, "Domain does not exist\n")
            except Exception as e:
                self.append_text(self.dns_text, f"DNS lookup error: {str(e)}\n")
            
        except Exception as e:
            self.append_text(self.dns_text, f"Error: {str(e)}\n")
        
        self.dns_text.config(state=DISABLED)

    def scan_ports(self):
        target = self.port_target_entry.get().strip()
        port_range = self.port_range_entry.get().strip()
        scan_type = self.scan_type.get()
        
        if not target or not port_range:
            messagebox.showerror("Error", "Please enter target and port range")
            return
            
        self.ports_text.delete(1.0, END)
        self.append_text(self.ports_text, f"Scanning {target} ports {port_range} using {scan_type} scan...\n")
        self.root.update()
        
        try:
            # Parse port range (supports: 80, 1-100, 22,80,443)
            ports = set()
            for part in port_range.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.update(range(start, end+1))
                else:
                    ports.add(int(part))
            
            open_ports = []
            
            if scan_type == "connect":
                # Traditional connect scan
                def check_port(port):
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(1)
                            result = s.connect_ex((target, port))
                            if result == 0:
                                open_ports.append(port)
                                self.append_text(self.ports_text, f"Port {port} is open - {self.get_service_name(port)}\n")
                                self.ports_text.see(END)
                                self.root.update()
                    except:
                        pass
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["scan_threads"]) as executor:
                    executor.map(check_port, sorted(ports))
            
            elif scan_type == "syn":
                # SYN scan using nmap (requires root/admin)
                try:
                    nm = nmap.PortScanner()
                    nm.scan(target, arguments=f'-sS -p {port_range} --max-rate 500')
                    
                    for host in nm.all_hosts():
                        for proto in nm[host].all_protocols():
                            ports = nm[host][proto].keys()
                            for port in sorted(ports):
                                if nm[host][proto][port]['state'] == 'open':
                                    open_ports.append(port)
                                    self.append_text(self.ports_text, f"Port {port} is open - {self.get_service_name(port)}\n")
                except Exception as e:
                    self.append_text(self.ports_text, f"SYN scan failed (requires root/admin): {str(e)}\n")
            
            elif scan_type == "udp":
                # UDP scan
                try:
                    nm = nmap.PortScanner()
                    nm.scan(target, arguments=f'-sU -p {port_range} --max-rate 100')
                    
                    for host in nm.all_hosts():
                        for proto in nm[host].all_protocols():
                            ports = nm[host][proto].keys()
                            for port in sorted(ports):
                                if nm[host][proto][port]['state'] == 'open':
                                    open_ports.append(port)
                                    self.append_text(self.ports_text, f"UDP Port {port} is open - {self.get_service_name(port)}\n")
                except Exception as e:
                    self.append_text(self.ports_text, f"UDP scan failed: {str(e)}\n")
            
            elif scan_type == "os":
                # OS detection scan
                try:
                    nm = nmap.PortScanner()
                    nm.scan(target, arguments='-O')
                    
                    self.append_text(self.ports_text, "\nOS Detection Results:\n")
                    if 'osmatch' in nm[target]:
                        for osmatch in nm[target]['osmatch']:
                            self.append_text(self.ports_text, f"OS: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)\n")
                    else:
                        self.append_text(self.ports_text, "OS detection failed\n")
                except Exception as e:
                    self.append_text(self.ports_text, f"OS detection failed: {str(e)}\n")
            
            self.append_text(self.ports_text, f"\nScan complete. Open ports: {open_ports}\n")
            
        except Exception as e:
            self.append_text(self.ports_text, f"Port scan failed: {str(e)}\n")

    def do_ping(self):
        target = self.ping_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        self.ping_results.delete(1.0, END)
        
        try:
            count = "4" if platform.system().lower() == "windows" else "c"
            cmd = ["ping", f"-{count}", "4", target]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            
            if error:
                self.ping_results.insert(END, f"Error: {error.decode()}")
            else:
                self.ping_results.insert(END, output.decode())
        except Exception as e:
            self.ping_results.insert(END, f"Ping failed: {str(e)}")

    def do_continuous_ping(self):
        target = self.ping_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        self.ping_results.delete(1.0, END)
        
        try:
            count = "t" if platform.system().lower() == "windows" else ""
            cmd = ["ping", f"-{count}", target]
            
            self.ping_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                               universal_newlines=True, bufsize=1)
            
            # Start thread to read output
            import threading
            def read_output():
                while True:
                    line = self.ping_process.stdout.readline()
                    if not line:
                        break
                    self.ping_results.insert(END, line)
                    self.ping_results.see(END)
                    self.root.update()
            
            thread = threading.Thread(target=read_output)
            thread.daemon = True
            thread.start()
            
            # Add stop button
            self.stop_ping_btn = Button(self.ping_results.master, text="Stop", command=self.stop_ping,
                                      bg='#FF5722', fg='white')
            self.stop_ping_btn.pack(side=BOTTOM, pady=5)
            
        except Exception as e:
            self.ping_results.insert(END, f"Continuous ping failed: {str(e)}\n")

    def stop_ping(self):
        if hasattr(self, 'ping_process'):
            self.ping_process.terminate()
        if hasattr(self, 'stop_ping_btn'):
            self.stop_ping_btn.destroy()

    def do_traceroute(self):
        target = self.trace_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        self.trace_results.delete(1.0, END)
        
        try:
            if platform.system() == "Windows":
                cmd = ["tracert", "-d", "-h", "10", target]
            else:
                cmd = ["traceroute", "-m", "10", target]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            
            if error:
                self.trace_results.insert(END, f"Error: {error.decode()}")
            else:
                self.trace_results.insert(END, output.decode())
        except Exception as e:
            self.trace_results.insert(END, f"Traceroute failed: {str(e)}\n")
            self.trace_results.insert(END, "Note: On Linux/macOS, install traceroute first")

    def check_virustotal(self, ip):
        if CONFIG["virustotal_key"] == "YOUR_VIRUSTOTAL_KEY":
            return "API key not configured (Configure in settings)"
            
        headers = {"x-apikey": CONFIG["virustotal_key"]}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        
        try:
            response = requests.get(url, headers=headers, timeout=CONFIG["timeout"])
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Clean: {stats['harmless']}"
        except Exception as e:
            return f"Error: {str(e)}"

    def check_abuseipdb(self, ip):
        if CONFIG["abuseipdb_key"] == "YOUR_ABUSEIPDB_KEY":
            return "API key not configured (Configure in settings)"
            
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {"Key": CONFIG["abuseipdb_key"], "Accept": "application/json"}
        
        try:
            response = requests.get(url, headers=headers, timeout=CONFIG["timeout"])
            data = response.json()
            return (f"Abuse Score: {data['data']['abuseConfidenceScore']}/100, "
                    f"Reports: {data['data']['totalReports']}, "
                    f"ISP: {data['data']['isp']}")
        except Exception as e:
            return f"Error: {str(e)}"

    def get_shodan_info(self, ip):
        if CONFIG["shodan_key"] == "YOUR_SHODAN_KEY":
            return None
            
        url = f"https://api.shodan.io/shodan/host/{ip}?key={CONFIG['shodan_key']}"
        
        try:
            response = requests.get(url, timeout=CONFIG["timeout"])
            return response.json()
        except:
            return None

    def get_whois(self, ip):
        try:
            if ':' in ip:  # IPv6
                whois_server = "whois.iana.org"
            else:  # IPv4
                whois_server = "whois.arin.net"
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((whois_server, 43))
                s.sendall((ip + "\r\n").encode())
                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
            return response.decode()
        except Exception as e:
            return f"WHOIS lookup failed: {str(e)}"

    def get_ssl_certificate(self, host, port=443):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    
                    # Parse certificate with cryptography
                    cert_obj = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'notAfter': cert['notAfter'],
                        'subject': dict(x[0] for x in cert['subject']),
                        'serial': cert_obj.serial_number,
                        'version': cert_obj.version.name
                    }
        except Exception as e:
            self.append_text(self.security_text, f"SSL check failed: {str(e)}\n")
            return None

    def is_tor_exit_node(self, ip):
        try:
            tor_ips = requests.get("https://check.torproject.org/torbulkexitlist", timeout=CONFIG["timeout"]).text.split('\n')
            return str(ip) in tor_ips
        except:
            return False

    def check_spamhaus(self, ip):
        try:
            reversed_ip = '.'.join(str(ip).split('.')[::-1])
            query = f"{reversed_ip}.zen.spamhaus.org"
            socket.gethostbyname(query)
            return "Listed in Spamhaus (Possible spam source)"
        except:
            return "Not listed in Spamhaus"

    def is_port_open(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                return s.connect_ex((host, port)) == 0
        except:
            return False

    def get_service_name(self, port):
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP Proxy"
        }
        return common_services.get(port, "Unknown service")

    def get_port_vulnerability(self, port):
        vulnerabilities = {
            21: "FTP - Vulnerable to brute force, anonymous login",
            22: "SSH - Vulnerable to brute force if weak credentials",
            23: "Telnet - Unencrypted, very vulnerable",
            25: "SMTP - Open relay possible",
            80: "HTTP - Check for web vulnerabilities",
            110: "POP3 - Unencrypted email access",
            143: "IMAP - Unencrypted email access",
            443: "HTTPS - Check certificate and TLS version",
            445: "SMB - Vulnerable to EternalBlue (CVE-2017-0144)",
            3389: "RDP - Vulnerable to BlueKeep (CVE-2019-0708) if not patched",
            5900: "VNC - Weak authentication possible",
            8080: "HTTP Proxy - Open proxy possible"
        }
        return vulnerabilities.get(port, "No known critical vulnerabilities")

    def run_full_security_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "No target specified")
            return
            
        self.append_text(self.security_text, "\n[FULL SECURITY SCAN INITIATED]\n")
        
        # Check if target is a domain and resolve it
        if not self.is_valid_ip(target):
            try:
                target = socket.gethostbyname(target)
                self.append_text(self.security_text, f"Resolved to IP: {target}\n")
            except:
                self.append_text(self.security_text, "Could not resolve domain\n")
                return
        
        # Run all security checks
        self.append_text(self.security_text, "\nRunning comprehensive security checks...\n")
        self.root.update()
        
        # 1. Check blacklists
        self.append_text(self.security_text, "\n[BLACKLIST CHECKS]\n")
        self.append_text(self.security_text, f"Spamhaus: {self.check_spamhaus(target)}\n")
        
        # 2. Check for open vulnerable ports
        self.append_text(self.security_text, "\n[VULNERABLE PORT SCAN]\n")
        vulnerable_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5900, 8080]
        for port in vulnerable_ports:
            if self.is_port_open(target, port):
                self.append_text(self.security_text, f"Port {port} ({self.get_service_name(port)}) is open - {self.get_port_vulnerability(port)}\n")
        
        # 3. Check SSL/TLS (if HTTPS open)
        if self.is_port_open(target, 443):
            self.append_text(self.security_text, "\n[SSL/TLS ANALYSIS]\n")
            cert_info = self.get_ssl_certificate(target)
            if cert_info:
                self.append_text(self.security_text, f"Issuer: {cert_info.get('issuer', {}).get('organizationName', 'Unknown')}\n")
                self.append_text(self.security_text, f"Expires: {cert_info.get('notAfter', 'Unknown')}\n")
                self.append_text(self.security_text, f"Serial: {cert_info.get('serial', 'Unknown')}\n")
                
                # Check for weak protocols
                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((target, 443)) as sock:
                        with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                            self.append_text(self.security_text, f"Protocol: {ssock.version()}\n")
                            if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                                self.append_text(self.security_text, "Warning: Using outdated/weak protocol\n")
                except Exception as e:
                    self.append_text(self.security_text, f"Protocol check failed: {str(e)}\n")
        
        self.append_text(self.security_text, "\n[SECURITY SCAN COMPLETE]\n")

    def run_speed_test(self):
        self.append_text(self.tools_text, "\n[SPEED TEST]\n")
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            
            self.append_text(self.tools_text, "Testing download speed...\n")
            download_speed = st.download() / 1000000  # Convert to Mbps
            self.append_text(self.tools_text, f"Download: {download_speed:.2f} Mbps\n")
            
            self.append_text(self.tools_text, "Testing upload speed...\n")
            upload_speed = st.upload() / 1000000  # Convert to Mbps
            self.append_text(self.tools_text, f"Upload: {upload_speed:.2f} Mbps\n")
            
            self.append_text(self.tools_text, "Testing ping...\n")
            ping = st.results.ping
            self.append_text(self.tools_text, f"Ping: {ping:.2f} ms\n")
            
            self.append_text(self.tools_text, "\nSpeed test completed\n")
        except Exception as e:
            self.append_text(self.tools_text, f"\nSpeed test failed: {str(e)}\n")

    def packet_loss_test(self):
        target = self.ping_entry.get().strip() or "google.com"
        self.append_text(self.tools_text, f"\n[PACKET LOSS TEST TO {target}]\n")
        
        try:
            count = "10" if platform.system().lower() == "windows" else "c"
            cmd = ["ping", f"-{count}", "10", target]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            
            if error:
                self.append_text(self.tools_text, f"Error: {error.decode()}")
            else:
                output = output.decode()
                self.append_text(self.tools_text, output)
                
                # Parse packet loss on Windows
                if "Packet loss" in output:
                    loss = re.search(r"Lost = (\d+)", output).group(1)
                    total = re.search(r"Sent = (\d+)", output).group(1)
                    self.append_text(self.tools_text, f"\nPacket loss: {int(loss)/int(total)*100:.1f}%")
        except Exception as e:
            self.append_text(self.tools_text, f"Packet loss test failed: {str(e)}\n")

    def start_sniffer(self):
        if not hasattr(self, 'sniffer_window') or not self.sniffer_window.winfo_exists():
            self.sniffer_window = Toplevel(self.root)
            self.sniffer_window.title("Network Sniffer")
            self.sniffer_window.geometry("800x600")
            
            # Sniffer controls
            controls = Frame(self.sniffer_window)
            controls.pack(fill=X, padx=5, pady=5)
            
            Label(controls, text="Interface:").pack(side=LEFT)
            self.interface_var = StringVar()
            interfaces = scapy.get_if_list()
            if not interfaces:
                interfaces = ["No interfaces found"]
            self.interface_var.set(interfaces[0])
            OptionMenu(controls, self.interface_var, *interfaces).pack(side=LEFT, padx=5)
            
            Label(controls, text="Filter:").pack(side=LEFT)
            self.filter_entry = Entry(controls, width=30)
            self.filter_entry.pack(side=LEFT, padx=5)
            self.filter_entry.insert(0, "tcp or udp")
            
            Button(controls, text="Start", command=self.start_sniffing, 
                  bg='#4CAF50', fg='white').pack(side=LEFT, padx=5)
            Button(controls, text="Stop", command=self.stop_sniffing, 
                  bg='#FF5722', fg='white').pack(side=LEFT, padx=5)
            
            # Packet display
            self.packet_text = Text(self.sniffer_window, wrap=WORD, font=("Consolas", 10))
            scroll = Scrollbar(self.sniffer_window, command=self.packet_text.yview)
            self.packet_text.configure(yscrollcommand=scroll.set)
            
            scroll.pack(side=RIGHT, fill=Y)
            self.packet_text.pack(fill=BOTH, expand=True)
            
            self.sniffer_running = False
        else:
            self.sniffer_window.lift()

    def start_sniffing(self):
        if hasattr(self, 'sniffer_running') and self.sniffer_running:
            return
            
        interface = self.interface_var.get()
        filter = self.filter_entry.get()
        
        if interface == "No interfaces found":
            messagebox.showerror("Error", "No network interfaces available")
            return
            
        self.packet_text.delete(1.0, END)
        self.append_text(self.packet_text, f"Starting sniffer on {interface} with filter: {filter}\n")
        
        def sniff_thread():
            self.sniffer_running = True
            try:
                scapy.sniff(iface=interface, filter=filter, prn=self.process_packet, store=0)
            except Exception as e:
                self.append_text(self.packet_text, f"Sniffer error: {str(e)}\n")
            self.sniffer_running = False
        
        import threading
        thread = threading.Thread(target=sniff_thread)
        thread.daemon = True
        thread.start()

    def process_packet(self, packet):
        if not hasattr(self, 'packet_text'):
            return
            
        summary = packet.summary()
        self.packet_text.insert(END, f"{summary}\n")
        self.packet_text.see(END)
        self.sniffer_window.update()

    def stop_sniffing(self):
        if hasattr(self, 'sniffer_running') and self.sniffer_running:
            scapy.sniff(stop_filter=lambda x: True)
            self.sniffer_running = False
            self.append_text(self.packet_text, "\nSniffer stopped\n")

    def wifi_analyzer(self):
        if platform.system() != "Windows":
            messagebox.showinfo("Info", "Wi-Fi analyzer is currently only available on Windows")
            return
            
        try:
            result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], 
                                   capture_output=True, text=True)
            
            window = Toplevel(self.root)
            window.title("Wi-Fi Analyzer")
            window.geometry("800x600")
            
            text = Text(window, wrap=WORD, font=("Consolas", 10))
            text.insert(END, result.stdout)
            text.config(state=DISABLED)
            text.pack(fill=BOTH, expand=True)
        except Exception as e:
            messagebox.showerror("Error", f"Wi-Fi analyzer failed: {str(e)}")

    def generate_report(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "No target specified")
            return
            
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")],
                initialfile=f"network_report_{target.replace('.', '_')}.pdf"
            )
            if not filename:
                return
                
            c = canvas.Canvas(filename, pagesize=letter)
            width, height = letter
            
            # Header
            c.setFont("Helvetica-Bold", 16)
            c.drawString(100, height-50, "Network Analysis Report")
            c.setFont("Helvetica", 12)
            c.drawString(100, height-80, f"Target: {target}")
            c.drawString(100, height-100, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.line(100, height-110, width-100, height-110)
            
            # Overview
            c.setFont("Helvetica-Bold", 14)
            c.drawString(100, height-140, "Overview")
            c.setFont("Helvetica", 10)
            
            # Get text from overview tab
            overview = self.overview_text.get("1.0", END)
            y_pos = height-160
            for line in overview.split('\n'):
                if y_pos < 100:
                    c.showPage()
                    y_pos = height-50
                c.drawString(110, y_pos, line)
                y_pos -= 15
            
            # Save PDF
            c.save()
            messagebox.showinfo("Success", f"Report saved as {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")

    def export_data(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "No target specified")
            return
            
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
                initialfile=f"network_data_{target.replace('.', '_')}.json"
            )
            if not filename:
                return
                
            data = {
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "overview": self.overview_text.get("1.0", END),
                "geolocation": self.geo_text.get("1.0", END),
                "network": self.network_text.get("1.0", END),
                "security": self.security_text.get("1.0", END),
                "dns": self.dns_text.get("1.0", END),
                "ports": self.ports_text.get("1.0", END)
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
                
            messagebox.showinfo("Success", f"Data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {str(e)}")

    def open_settings(self):
        settings_window = Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("500x500")
        
        Label(settings_window, text="API Keys Configuration", font=("Helvetica", 14)).pack(pady=10)
        
        # VirusTotal
        Frame(settings_window, height=2, bg="black").pack(fill=X, padx=10, pady=5)
        Label(settings_window, text="VirusTotal API Key:").pack(anchor=W, padx=20)
        vt_entry = Entry(settings_window, width=50)
        vt_entry.pack(padx=20)
        vt_entry.insert(0, CONFIG["virustotal_key"])
        
        # AbuseIPDB
        Frame(settings_window, height=2, bg="black").pack(fill=X, padx=10, pady=5)
        Label(settings_window, text="AbuseIPDB API Key:").pack(anchor=W, padx=20)
        abuse_entry = Entry(settings_window, width=50)
        abuse_entry.pack(padx=20)
        abuse_entry.insert(0, CONFIG["abuseipdb_key"])
        
        # Shodan
        Frame(settings_window, height=2, bg="black").pack(fill=X, padx=10, pady=5)
        Label(settings_window, text="Shodan API Key:").pack(anchor=W, padx=20)
        shodan_entry = Entry(settings_window, width=50)
        shodan_entry.pack(padx=20)
        shodan_entry.insert(0, CONFIG["shodan_key"])
        
        # MaxMind GeoIP
        Frame(settings_window, height=2, bg="black").pack(fill=X, padx=10, pady=5)
        Label(settings_window, text="MaxMind GeoIP DB Path:").pack(anchor=W, padx=20)
        geoip_entry = Entry(settings_window, width=50)
        geoip_entry.pack(padx=20)
        geoip_entry.insert(0, CONFIG["geoip_db_path"])
        
        # Save button
        Button(settings_window, text="Save Settings", command=lambda: self.save_settings(
            vt_entry.get(),
            abuse_entry.get(),
            shodan_entry.get(),
            geoip_entry.get()
        )).pack(pady=20)

    def save_settings(self, vt_key, abuse_key, shodan_key, geoip_path):
        CONFIG["virustotal_key"] = vt_key
        CONFIG["abuseipdb_key"] = abuse_key
        CONFIG["shodan_key"] = shodan_key
        CONFIG["geoip_db_path"] = geoip_path
        messagebox.showinfo("Success", "Settings saved successfully")

    def load_targets(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Select targets file"
        )
        if filename:
            try:
                with open(filename) as f:
                    targets = [line.strip() for line in f if line.strip()]
                if targets:
                    self.target_entry.delete(0, END)
                    self.target_entry.insert(0, targets[0])
                    messagebox.showinfo("Loaded", f"{len(targets)} targets loaded. First target populated.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load targets: {str(e)}")

    def focus_port_scanner(self):
        self.notebook.select(self.ports_tab)

    def set_port_range(self, ports):
        self.port_range_entry.delete(0, END)
        self.port_range_entry.insert(0, ports)

    def change_theme(self, theme):
        CONFIG["theme"] = theme
        messagebox.showinfo("Info", f"Theme changed to {theme}. Restart the application to apply changes.")

    def check_updates(self):
        try:
            response = requests.get("https://api.github.com/repos/yourusername/ultimate-network-analyzer/releases/latest", 
                                 timeout=5)
            latest_version = response.json()['tag_name']
            if latest_version > "v3.0":
                messagebox.showinfo("Update Available", 
                                  f"New version {latest_version} is available!\nPlease visit the GitHub page to download.")
            else:
                messagebox.showinfo("Up to Date", "You have the latest version.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check for updates: {str(e)}")

    def show_docs(self):
        webbrowser.open("https://github.com/yourusername/ultimate-network-analyzer/wiki")

    def show_about(self):
        about_window = Toplevel(self.root)
        about_window.title("About Ultimate Network Analyzer")
        about_window.geometry("400x300")
        
        Label(about_window, text="Ultimate Network Analyzer Pro", font=("Helvetica", 16)).pack(pady=20)
        Label(about_window, text="Version 3.0").pack()
        Label(about_window, text="© 2023 Network Security Tools").pack(pady=10)
        Label(about_window, text="A comprehensive network analysis tool").pack()
        Label(about_window, text="for security professionals and IT teams").pack()
        
        Button(about_window, text="Close", command=about_window.destroy).pack(pady=20)

    def is_valid_ip(self, address):
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def append_text(self, widget, text):
        widget.config(state=NORMAL)
        widget.insert(END, text)
        widget.config(state=DISABLED)
        widget.see(END)

    def clear_results(self):
        for widget in [self.overview_text, self.geo_text, self.network_text, 
                      self.security_text, self.dns_text, self.ports_text, self.vuln_text]:
            if widget:
                widget.config(state=NORMAL)
                widget.delete(1.0, END)
                widget.config(state=DISABLED)
        
        if self.ping_results:
            self.ping_results.delete(1.0, END)
        if self.trace_results:
            self.trace_results.delete(1.0, END)
        if self.map_label:
            self.map_label.config(text="Map will be generated here")
            self.map_label.unbind("<Button-1>")

if __name__ == "__main__":
    root = Tk()
    app = UltimateNetworkAnalyzer(root)
    root.mainloop()