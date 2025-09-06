import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import threading
import webbrowser
from datetime import datetime
import json
from PIL import Image, ImageTk, ImageDraw
import os
from io import BytesIO
import concurrent.futures
from functools import lru_cache
import subprocess
import platform
import uuid
import time
import sys
import ctypes
import base64
import re
from pathlib import Path

try:
    import pydivert
    import socket
    HAS_PYDIVERT = True
except ImportError:
    HAS_PYDIVERT = False
    print("Warning: PyDivert not installed. Subplace joining will not work.")

if sys.platform == "win32":
    try:
        import win32crypt
        HAS_WIN32CRYPT = True
    except ImportError:
        HAS_WIN32CRYPT = False
else:
    HAS_WIN32CRYPT = False

COOKIE_FILE = "roblox_cookie.txt"
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class GameJoinBlocker:
    def __init__(self, parent_app):
        self.parent_app = parent_app
        self.blocked_ips = set()
        self.blocked_count = 0
        self.connections = {}
        self.firewall_blocked = set()
        self.running = False
        self.blocker_thread = None
        self.resolver_thread = None
        self.first_firewall_block = False
        self.auto_stop_timer = None
        self.firewall_unblock_complete = threading.Event()
        
    def resolve_gamejoin_ips_continuous(self):
        domains = [
            "gamejoin.roblox.com",
            "gamejoin.na.roblox.com",
            "gamejoin.eu.roblox.com"
        ]
        
        while self.running:
            for domain in domains:
                try:
                    ips = socket.gethostbyname_ex(domain)[2]
                    for ip in ips:
                        if ip not in self.blocked_ips:
                            self.blocked_ips.add(ip)
                            self.parent_app.debug_log(f"📍 Added IP for blocking: {ip} ({domain})", "BLOCKER")
                except:
                    pass
            time.sleep(10)
    
    def force_disconnect_roblox(self):
        self.parent_app.debug_log("🔌 FORCING disconnect of ALL Roblox connections...", "BLOCKER")
        
        result = subprocess.run('wmic process where "name=\'RobloxPlayerBeta.exe\'" get ProcessId', 
                              shell=True, capture_output=True, text=True)
        
        roblox_pids = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.isdigit():
                roblox_pids.append(line)
        
        if not roblox_pids:
            self.parent_app.debug_log("   No Roblox processes found", "BLOCKER")
            return
            
        self.parent_app.debug_log(f"   Found Roblox processes: {roblox_pids}", "BLOCKER")
        
        for pid in roblox_pids:
            exe_result = subprocess.run(f'wmic process where ProcessId={pid} get ExecutablePath', 
                                      shell=True, capture_output=True, text=True)
            exe_path = None
            for line in exe_result.stdout.split('\n'):
                line = line.strip()
                if line and 'RobloxPlayerBeta.exe' in line:
                    exe_path = line
                    break
            
            if exe_path:
                rule_name = f"FORCE_DISCONNECT_ROBLOX_{pid}"
                
                cmd_add = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block program="{exe_path}" enable=yes'
                subprocess.run(cmd_add, shell=True, capture_output=True)
                self.parent_app.debug_log(f"   🔴 Blocked ALL outgoing connections for PID {pid}", "BLOCKER")
                
                time.sleep(0.5)
                
                cmd_del = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                subprocess.run(cmd_del, shell=True, capture_output=True)
                self.parent_app.debug_log(f"   🟢 Unblocked connections for PID {pid}", "BLOCKER")
        
        self.parent_app.debug_log("   Resetting TCP connections...", "BLOCKER")
        subprocess.run('netsh int tcp reset', shell=True, capture_output=True)
        
        time.sleep(0.5)
        self.parent_app.debug_log("   ✅ All Roblox connections forcefully disconnected", "BLOCKER")
    
    def is_roblox_running(self):
        try:
            result = subprocess.run('tasklist', shell=True, capture_output=True, text=True)
            return "RobloxPlayerBeta.exe" in result.stdout
        except Exception as e:
            self.parent_app.debug_log(f"Error checking if Roblox is running: {e}", "ERROR")
            return False
    
    def temporary_firewall_block(self, ip_address):
        if ip_address not in self.firewall_blocked:
            self.firewall_blocked.add(ip_address)
            self.firewall_unblock_complete.clear()
            
            rule_name = f"TEMP_GAMEJOIN_{ip_address}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip_address}'
            subprocess.run(cmd, shell=True, capture_output=True)
            self.parent_app.debug_log(f"🔥 Firewall: temporarily blocked {ip_address}", "BLOCKER")
            
            if not self.first_firewall_block:
                self.first_firewall_block = True
                self.parent_app.debug_log("📌 First Firewall block - stopping blocker", "BLOCKER")
                
                self.running = False
                self.parent_app.after(0, lambda: self.parent_app.update_status("✅ Blocker stopped after gamejoin block"))
            
            def unblock():
                subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', 
                            shell=True, capture_output=True)
                self.firewall_blocked.discard(ip_address)
                self.parent_app.debug_log(f"✅ Firewall: unblocked {ip_address}", "BLOCKER")
                self.firewall_unblock_complete.set()
            
            threading.Timer(2.5, unblock).start()
    
    def start_blocking(self):
        if not HAS_PYDIVERT:
            self.parent_app.debug_log("PyDivert not available", "ERROR")
            return False
        
        self.parent_app.debug_log("🔄 Resetting blocker state...", "BLOCKER")
        
        if self.running:
            self.parent_app.debug_log("⚠️ Previous blocker still running, stopping...", "BLOCKER")
            self.stop_blocking()
            time.sleep(1)
        
        self.blocked_count = 0
        self.connections = {}
        self.firewall_blocked = set()
        self.first_firewall_block = False
        self.firewall_unblock_complete.set()
        
        if self.auto_stop_timer and hasattr(self.auto_stop_timer, 'cancel'):
            try:
                self.auto_stop_timer.cancel()
            except:
                pass
        self.auto_stop_timer = None
        
        self.parent_app.debug_log(f"Saved IPs for blocking: {self.blocked_ips}", "BLOCKER")
        
        self.parent_app.debug_log("🧹 Cleaning old firewall rules...", "BLOCKER")
        subprocess.run('netsh advfirewall firewall delete rule name="TEMP_GAMEJOIN_*"', 
                      shell=True, capture_output=True)
        subprocess.run('netsh advfirewall firewall delete rule name="FORCE_DISCONNECT_*"', 
                      shell=True, capture_output=True)
        
        self.force_disconnect_roblox()
        
        self.running = True
        self.blocker_thread = threading.Thread(target=self._blocking_worker, daemon=True)
        self.blocker_thread.start()
        
        time.sleep(0.5)
        
        self.parent_app.debug_log("✅ Blocker started successfully", "BLOCKER")
        return True
    
    def stop_blocking(self):
        if not self.running:
            return
            
        self.running = False
        
        if self.auto_stop_timer and hasattr(self.auto_stop_timer, 'cancel'):
            try:
                self.auto_stop_timer.cancel()
            except:
                pass
        
        self.parent_app.debug_log(f"Blocking stopped. Total blocked: {self.blocked_count}", "BLOCKER")
        
        self.parent_app.debug_log("🧹 Cleaning firewall rules...", "BLOCKER")
        subprocess.run('netsh advfirewall firewall delete rule name="TEMP_GAMEJOIN_*"', 
                    shell=True, capture_output=True)
        subprocess.run('netsh advfirewall firewall delete rule name="FORCE_DISCONNECT_*"', 
                    shell=True, capture_output=True)
    
    def _blocking_worker(self):
        try:
            self.parent_app.debug_log("🎮 ENHANCED gamejoin.roblox.com BLOCKING", "BLOCKER")
            self.parent_app.debug_log("="*50, "BLOCKER")
            self.parent_app.debug_log("✅ Works even if Roblox is already running", "BLOCKER")
            self.parent_app.debug_log("✅ Blocks ONLY join requests", "BLOCKER")
            self.parent_app.debug_log("✅ Uses temporary Firewall blocking", "BLOCKER")
            self.parent_app.debug_log("✅ Instant stop after first block\n", "BLOCKER")
            
            if not hasattr(self, 'resolver_thread') or not self.resolver_thread or not self.resolver_thread.is_alive():
                self.resolver_thread = threading.Thread(target=self.resolve_gamejoin_ips_continuous, daemon=True)
                self.resolver_thread.start()
                time.sleep(2)
            
            if self.blocked_ips:
                self.parent_app.debug_log(f"🎯 Known gamejoin IPs: {self.blocked_ips}", "BLOCKER")
            
            ip_packet_count = {}
            
            with pydivert.WinDivert("tcp") as w:
                for packet in w:
                    if not self.running:
                        break
                        
                    block = False
                    reason = ""
                    
                    if packet.payload:
                        payload_lower = packet.payload.lower()
                        
                        gamejoin_patterns = [
                            b"gamejoin.roblox.com",
                            b"gamejoin",
                            b"\x08gamejoin\x06roblox\x03com",
                            b"/v1/join-game",
                            b"join-game",
                        ]
                        
                        for pattern in gamejoin_patterns:
                            if pattern in payload_lower:
                                block = True
                                reason = "GameJoin pattern in payload"
                                self.blocked_ips.add(packet.dst_addr)
                                break
                    
                    if not block and packet.dst_port == 443 and packet.payload:
                        if len(packet.payload) > 5 and packet.payload[0] == 0x16:
                            if b"gamejoin" in packet.payload:
                                block = True
                                reason = "GameJoin in TLS SNI"
                                self.blocked_ips.add(packet.dst_addr)
                    
                    if not block and packet.dst_addr in self.blocked_ips:
                        if packet.dst_addr not in ip_packet_count:
                            ip_packet_count[packet.dst_addr] = 0
                        
                        ip_packet_count[packet.dst_addr] += 1
                        
                        if ip_packet_count[packet.dst_addr] <= 5:
                            if packet.tcp.syn or len(packet.payload) > 100:
                                block = True
                                reason = f"Known gamejoin IP (packet #{ip_packet_count[packet.dst_addr]})"
                    
                    conn_key = (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
                    if block and b"gamejoin" in packet.payload.lower() if packet.payload else False:
                        self.connections[conn_key] = True
                    elif conn_key in self.connections:
                        block = True
                        reason = "Known gamejoin connection"
                    
                    if block:
                        self.blocked_count += 1
                        if self.blocked_count <= 10 or self.blocked_count % 10 == 0:
                            self.parent_app.debug_log(
                                f"🚫 [{datetime.now():%H:%M:%S}] BLOCKED #{self.blocked_count}", 
                                "BLOCKER"
                            )
                            self.parent_app.debug_log(f"   ├─ Reason: {reason}", "BLOCKER")
                            self.parent_app.debug_log(
                                f"   └─ Connection: {packet.src_addr}:{packet.src_port} → {packet.dst_addr}:{packet.dst_port}", 
                                "BLOCKER"
                            )
                            
                            if (self.blocked_count == 1 and "gamejoin" in reason.lower()) or \
                            (packet.payload and b"gamejoin" in packet.payload.lower()):
                                if packet.dst_addr not in self.firewall_blocked:
                                    self.temporary_firewall_block(packet.dst_addr)
                        
                        continue
                    
                    w.send(packet)
                    
        except Exception as e:
            if self.running:
                self.parent_app.debug_log(f"Blocking error: {e}", "ERROR")
        finally:
            self.parent_app.debug_log("Blocker thread ended", "BLOCKER")

def is_admin():
    if sys.platform != "win32":
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if sys.platform != "win32":
        return
    
    if is_admin():
        return 
    
    try:
        if getattr(sys, 'frozen', False):
            executable = sys.executable
        else:
            executable = sys.executable
            
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, None, 1
        )
        sys.exit(0)
    except Exception as e:
        result = messagebox.askyesno(
            "Administrator Rights Required",
            "This application requires administrator rights to block Roblox's internet connection temporarily.\n\n"
            "Would you like to continue without this feature?\n\n"
            "Note: You won't be able to join subplaces without admin rights.",
            icon='warning'
        )
        if not result:
            sys.exit(0)

class RobloxSubplaceExplorer(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.geometry("1100x850")
        self.minsize(400, 850)
        
        self.title("Untitled Subplace Tool")
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.colors = {
            "primary": "#3B3B3B",
            "primary_hover": "#2D2D2D",
            "success": "#4A4A4A",
            "success_hover": "#383838",
            "bg_secondary": "#1A1A1A",
            "text_primary": "#E0E0E0",
            "text_secondary": "#9A9A9A",
            "border": "#2A2A2A",
            "error": "#B84444",
            "warning": "#B87A44",
            "card_bg": "#242424",
            "input_bg": "#1E1E1E"
        }
        
        self.configure(fg_color="#121212")
        
        self.debug_mode = True
        self.debug_logs = []
        self.max_logs = 100
        self.current_places = []
        self.root_place_id = None
        self.current_universe_id = None
        self.place_icons = {}
        self.default_icon = None
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.current_width = 1100
        self.place_cards = []
        self.cookie = ""
        self.is_admin = is_admin()
        self.cookie_auto_obtained = False
        self.join_attempts = 0
        
        self.gamejoin_blocker = GameJoinBlocker(self)
        
        self.create_default_icon()
        
        self.extract_cookie_automatically()
        
        self.create_ui()
        self.update()
        self.center_window()
        
        self.bind("<Configure>", self.on_window_resize)
        
        if not self.cookie_auto_obtained:
            self.load_cookie()
            
        if not HAS_PYDIVERT and self.is_admin:
            self.after(1000, lambda: messagebox.showwarning(
                "PyDivert Not Installed",
                "PyDivert is not installed. Subplace joining will not work properly.\n\n"
                "Install it with: pip install pydivert\n"
                "Also download WinDivert driver from https://www.reqrypt.org/windivert.html",
                icon='warning'
            ))
            
    def debug_log(self, message, log_type="INFO"):
        if not self.debug_mode:
            return
            
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] [{log_type}] {message}"
        
        print(log_entry) 
        
        self.debug_logs.append(log_entry)
        if len(self.debug_logs) > self.max_logs:
            self.debug_logs.pop(0)
            
    def get_cookie_file_path(self):
        username = os.environ.get('USERNAME')
        return Path(f"C:/Users/{username}/AppData/Local/Roblox/LocalStorage/RobloxCookies.dat")
    
    def decrypt_cookies(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as f:
                file_content = f.read()
        
        if file_content.strip().startswith('{'):
            data = json.loads(file_content)
            encrypted = data.get('CookiesData', '')
        else:
            encrypted = file_content
        
        encrypted_bytes = base64.b64decode(encrypted)
        decrypted = win32crypt.CryptUnprotectData(encrypted_bytes, None, None, None, 0)
        
        return decrypted[1].decode('utf-8')
    
    def extract_roblosecurity(self, cookie_data):
        pattern = r'\.ROBLOSECURITY\s+(_\|WARNING[^;]+)'
        match = re.search(pattern, cookie_data)
        
        if match:
            return match.group(1)
        
        start = cookie_data.find('_|WARNING:-DO-NOT-SHARE-THIS')
        if start != -1:
            end = cookie_data.find(';', start)
            if end == -1:
                end = len(cookie_data)
            return cookie_data[start:end].strip()
        
        return None
    
    def extract_cookie_automatically(self):
        if not HAS_WIN32CRYPT or sys.platform != "win32":
            return
        
        try:
            cookie_file = self.get_cookie_file_path()
            if not cookie_file.exists():
                return
            
            decrypted = self.decrypt_cookies(cookie_file)
            roblosecurity = self.extract_roblosecurity(decrypted)
            
            if roblosecurity:
                self.cookie = roblosecurity
                self.cookie_auto_obtained = True
                print("Cookie automatically extracted successfully")
        except Exception as e:
            print(f"Failed to auto-extract cookie: {e}")
            self.cookie_auto_obtained = False
    
    def join_place(self, place_id, is_root=False):
        try:
            if is_root:
                self.debug_log(f"Joining ROOT place {place_id} directly", "INFO")
                self.launch_roblox(place_id)
            else:
                self.debug_log(f"Joining SUBPLACE {place_id}", "INFO")

                if not self.gamejoin_blocker.is_roblox_running():
                    self.debug_log("Roblox is not running - cannot join subplace", "ERROR")
                    messagebox.showerror(
                        "Roblox Not Running",
                        "Roblox must be running to join a subplace.\n\n"
                        "Please launch Roblox first.",
                        icon='error'
                    )
                    return
                if not self.is_admin:
                    self.debug_log("No admin rights - showing warning", "WARNING")
                    messagebox.showwarning(
                        "Admin Rights Required",
                        "Administrator rights are required to join subplaces.\n\n"
                        "Please restart the application as administrator.",
                        icon='warning'
                    )
                    return
                
                if not HAS_PYDIVERT:
                    self.debug_log("PyDivert not available - cannot join subplace", "ERROR")
                    messagebox.showerror(
                        "PyDivert Required",
                        "PyDivert is required to join subplaces.\n\n"
                        "Install it with: pip install pydivert",
                        icon='error'
                    )
                    return
                    
                cookie = self.get_cookie()
                if not cookie:
                    self.show_error("Cookie is required to join subplaces")
                    return
                
                if not self.root_place_id:
                    self.show_error("No root place found")
                    return
                
                self.show_join_progress_window(place_id)
                
                def on_allowance_result(success, message):
                    if success:
                        self.debug_log("Got teleport allowance - starting join process", "SUCCESS")
                        self.update_status("✅ Got teleport allowance! Starting blocker...")
                        
                        self.debug_log("Starting GameJoin blocker BEFORE launching Roblox", "INFO")
                        if self.gamejoin_blocker.start_blocking():

                            time.sleep(1)
                            
                            self.update_status("Blocker active - launching Roblox...")
                            
                            self.debug_log(f"Launching Roblox for place {place_id}", "INFO")
                            self.launch_roblox(place_id)
                            
                            self.show_blocking_window(place_id)
                            
                            self.debug_log("Blocker will auto-stop after first successful block", "INFO")
                        else:
                            self.show_error("Failed to start blocker")
                    else:
                        self.debug_log(f"Failed to get allowance: {message}", "ERROR")
                        self.show_error(f"Failed to get allowance: {message}")
                        if hasattr(self, 'progress_window') and self.progress_window:
                            self.progress_window.destroy()
                            self.progress_window = None
                        
                self.get_teleport_allowance(self.root_place_id, place_id, on_allowance_result)

        except Exception as e:
            self.debug_log(f"Join place error: {str(e)}", "ERROR")
            self.show_error(f"Failed to join place: {str(e)}")
            
    def show_join_progress_window(self, place_id):
        self.progress_window = ctk.CTkToplevel(self)
        self.progress_window.title("Joining Subplace")
        self.progress_window.geometry("450x280")
        
        self.progress_window.transient(self)
        self.progress_window.grab_set()
        self.progress_window.attributes('-topmost', True)
        self.progress_window.protocol("WM_DELETE_WINDOW", lambda: None) 
        self.progress_window.resizable(False, False)
        self.progress_window.configure(fg_color="#1A1A1A")
        
        self.progress_window.update_idletasks()
        width = self.progress_window.winfo_width()
        height = self.progress_window.winfo_height()
        x = (self.progress_window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.progress_window.winfo_screenheight() // 2) - (height // 2)
        self.progress_window.geometry(f'{width}x{height}+{x}+{y}')
        
        main_frame = ctk.CTkFrame(self.progress_window, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=30, pady=25)
        
        title_label = ctk.CTkLabel(
            main_frame,
            text="ESTABLISHING CONNECTION",
            font=ctk.CTkFont(size=14, weight="bold", family="Consolas"),
            text_color=self.colors["text_primary"]
        )
        title_label.pack(pady=(0, 5))
        
        place_label = ctk.CTkLabel(
            main_frame,
            text=f"Place ID: {place_id}",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=self.colors["text_secondary"]
        )
        place_label.pack(pady=(0, 20))
        
        attempts_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["card_bg"], corner_radius=8)
        attempts_frame.pack(fill="x", pady=(0, 15))
        
        self.attempts_label = ctk.CTkLabel(
            attempts_frame,
            text="ATTEMPT: 0",
            font=ctk.CTkFont(size=24, weight="bold", family="Consolas"),
            text_color=self.colors["text_primary"]
        )
        self.attempts_label.pack(pady=15)
        
        self.status_text_label = ctk.CTkLabel(
            main_frame,
            text="Requesting teleport allowance...",
            font=ctk.CTkFont(size=11),
            text_color=self.colors["text_secondary"]
        )
        self.status_text_label.pack(pady=(0, 15), padx=10, fill="x")
        
        progress = ctk.CTkProgressBar(
            main_frame,
            width=300,
            height=6,
            corner_radius=3,
            fg_color=self.colors["border"],
            progress_color=self.colors["primary"],
            mode="indeterminate"
        )
        progress.pack(pady=(0, 15))
        progress.start()
        
        info_label = ctk.CTkLabel(
            main_frame,
            text="Do not close this window",
            font=ctk.CTkFont(size=10),
            text_color=self.colors["text_secondary"]
        )
        info_label.pack()
        
        self.join_attempts = 0
        
        def update_attempts():
            if hasattr(self, 'progress_window') and self.progress_window and self.progress_window.winfo_exists():
                if hasattr(self, 'attempts_label'):
                    self.attempts_label.configure(text=f"ATTEMPT: {self.join_attempts}")
                self.progress_window.after(100, update_attempts)
        
        update_attempts()
        
    def show_blocking_window(self, place_id):
        if hasattr(self, 'progress_window') and self.progress_window:
            self.progress_window.destroy()
            self.progress_window = None
            
        blocking_window = ctk.CTkToplevel(self)
        blocking_window.title("Blocking Connection")
        blocking_window.geometry("400x220")
        blocking_window.configure(fg_color="#1A1A1A")
        
        blocking_window.transient(self)
        blocking_window.grab_set()
        blocking_window.attributes('-topmost', True)
        blocking_window.protocol("WM_DELETE_WINDOW", lambda: None) 
        blocking_window.resizable(False, False)
        
        blocking_window.update_idletasks()
        width = blocking_window.winfo_width()
        height = blocking_window.winfo_height()
        x = (blocking_window.winfo_screenwidth() // 2) - (width // 2)
        y = (blocking_window.winfo_screenheight() // 2) - (height // 2)
        blocking_window.geometry(f'{width}x{height}+{x}+{y}')
        
        main_frame = ctk.CTkFrame(blocking_window, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=40, pady=30)
        
        title_label = ctk.CTkLabel(
            main_frame,
            text="BLOCKING GAMEJOIN",
            font=ctk.CTkFont(size=14, weight="bold", family="Consolas"),
            text_color=self.colors["text_primary"]
        )
        title_label.pack(pady=(0, 15))
        
        desc_label = ctk.CTkLabel(
            main_frame,
            text="Please wait. Do not interact with Roblox.",
            font=ctk.CTkFont(size=11),
            text_color=self.colors["text_secondary"]
        )
        desc_label.pack(pady=(0, 20))
        
        progress = ctk.CTkProgressBar(
            main_frame,
            width=250,
            height=6,
            corner_radius=3,
            fg_color=self.colors["border"],
            progress_color=self.colors["primary"]
        )
        progress.pack(pady=(0, 15))
        progress.set(0)
        
        timer_label = ctk.CTkLabel(
            main_frame,
            text="2.5s",
            font=ctk.CTkFont(size=28, weight="bold", family="Consolas"),
            text_color=self.colors["text_primary"]
        )
        timer_label.pack()
        
        start_time = time.time()
        duration = 2.5
        
        def update_timer():
            elapsed = time.time() - start_time
            remaining = max(0, duration - elapsed)
            
            if remaining > 0:
        
                progress.set(elapsed / duration)
                
                timer_label.configure(text=f"{remaining:.1f}s")
                
                blocking_window.lift()
                blocking_window.attributes('-topmost', True)
                
                blocking_window.after(50, update_timer)
            else:

                progress.set(1.0)
                timer_label.configure(text="DONE", text_color=self.colors["success"])
                
                def wait_and_close():
                    self.gamejoin_blocker.firewall_unblock_complete.wait(timeout=1.0)
                    self.after(0, lambda: self.close_blocking_window(blocking_window))
                
                threading.Thread(target=wait_and_close, daemon=True).start()
        
        update_timer()
        
        return blocking_window
        
    def close_blocking_window(self, window):

        window.grab_release()
        window.destroy()
        
        messagebox.showinfo(
            "Ready",
            "Connection blocked successfully.\n\n"
            "In Roblox, click Retry to join the subplace."
        )
        
    def save_cookie(self):

        if not self.cookie_auto_obtained and hasattr(self, 'cookie_entry'):
            try:
                with open(COOKIE_FILE, "w", encoding="utf-8") as f:
                    f.write(self.cookie_entry.get())
            except Exception as e:
                print("Failed to save cookie:", e)

    def load_cookie(self):

        if hasattr(self, 'cookie_entry'):
            try:
                if os.path.exists(COOKIE_FILE):
                    with open(COOKIE_FILE, "r", encoding="utf-8") as f:
                        self.cookie_entry.delete(0, tk.END)
                        self.cookie_entry.insert(0, f.read().strip())
            except Exception as e:
                print("Failed to load cookie:", e)    
    
    def create_default_icon(self):
        try:
            size = 48
            img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            
            draw.rounded_rectangle((0, 0, size, size), radius=10, fill="#2A2A2A")
            
            self.default_icon = ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))
        except:
            self.default_icon = None
        
    def center_window(self):
        width = self.winfo_reqwidth()
        height = self.winfo_reqheight()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
        
    def on_window_resize(self, event):
        if event.widget == self and hasattr(self, 'main_container'):
            new_width = self.winfo_width()
            if abs(new_width - self.current_width) > 50:
                self.current_width = new_width
                self.update_layout()
                
    def update_layout(self):
        if not hasattr(self, 'main_container'):
            return
            
        width = self.winfo_width()
        
        if width < 600:
            self.main_container.grid(padx=10, pady=10)
        elif width < 900:
            self.main_container.grid(padx=20, pady=20)
        else:
            self.main_container.grid(padx=40, pady=30)
            
        if hasattr(self, 'title_label'):
            if width < 600:
                self.title_label.configure(font=ctk.CTkFont(size=18, weight="bold"))
                self.subtitle_label.configure(font=ctk.CTkFont(size=11))
            else:
                self.title_label.configure(font=ctk.CTkFont(size=24, weight="bold"))
                self.subtitle_label.configure(font=ctk.CTkFont(size=13))
                
        if hasattr(self, 'search_entry'):
            if width < 600:
                self.search_entry.configure(height=38, font=ctk.CTkFont(size=13))
                self.search_button.configure(width=80, height=32)
            else:
                self.search_entry.configure(height=45, font=ctk.CTkFont(size=14))
                self.search_button.configure(width=100, height=38)
                
        if hasattr(self, 'place_cards') and self.place_cards:
            self.rearrange_places()
        
    def create_ui(self):
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=0, sticky="nsew", padx=40, pady=30)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(3, weight=1)
        
        self.create_header()
        
        if not self.cookie_auto_obtained:
            self.create_cookie_section()
        
        self.create_search_section()
        
        self.create_results_section()
        
        self.create_status_bar()
        
    def create_header(self):
        header_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header_frame.grid_columnconfigure(0, weight=1)
        
        self.title_label = ctk.CTkLabel(
            header_frame,
            text="UNTITLED SUBPLACE TOOL",
            font=ctk.CTkFont(size=24, weight="bold", family="Segoe UI"),
            text_color=self.colors["text_primary"]
        )
        self.title_label.grid(row=0, column=0)
        
        subtitle_text = "Made by Bezna"
        if not self.is_admin:
            subtitle_text += " | LIMITED MODE"
        
        self.subtitle_label = ctk.CTkLabel(
            header_frame,
            text=subtitle_text,
            font=ctk.CTkFont(size=13),
            text_color=self.colors["warning"] if not self.is_admin else self.colors["text_secondary"]
        )
        self.subtitle_label.grid(row=1, column=0, pady=(5, 0))
    
    
    def create_cookie_section(self):
        cookie_frame = ctk.CTkFrame(self.main_container, corner_radius=8, fg_color=self.colors["card_bg"])
        cookie_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        cookie_frame.grid_columnconfigure(1, weight=1)
        
        cookie_label = ctk.CTkLabel(
            cookie_frame,
            text="COOKIE:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=self.colors["text_secondary"]
        )
        cookie_label.grid(row=0, column=0, padx=(20, 10), pady=15, sticky="w")
        
        self.cookie_entry = ctk.CTkEntry(
            cookie_frame,
            placeholder_text="Enter .ROBLOSECURITY cookie",
            height=38,
            border_width=1,
            border_color=self.colors["border"],
            fg_color=self.colors["input_bg"],
            font=ctk.CTkFont(size=11, family="Consolas"),
            show="*"
        )
        self.cookie_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10), pady=15)
        
        self.setup_cookie_entry_bindings()
        
        self.show_cookie_button = ctk.CTkButton(
            cookie_frame,
            text="VIEW",
            width=60,
            height=38,
            corner_radius=6,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            text_color=self.colors["text_primary"],
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self.toggle_cookie_visibility
        )
        self.show_cookie_button.grid(row=0, column=2, padx=(0, 20), pady=15)
        
        cookie_info = ctk.CTkLabel(
            cookie_frame,
            text="Required for subplace access. Extract from browser cookies.",
            font=ctk.CTkFont(size=10),
            text_color=self.colors["text_secondary"],
            wraplength=800
        )
        cookie_info.grid(row=1, column=0, columnspan=3, padx=20, pady=(0, 15), sticky="w")
        
    def setup_cookie_entry_bindings(self):
        self.cookie_entry.bind('<Control-a>', lambda e: self.select_all_cookie())
        self.cookie_entry.bind('<Control-A>', lambda e: self.select_all_cookie())
        self.cookie_entry.bind('<Control-c>', lambda e: self.copy_cookie())
        self.cookie_entry.bind('<Control-C>', lambda e: self.copy_cookie())
        self.cookie_entry.bind('<Control-v>', lambda e: self.paste_to_cookie())
        self.cookie_entry.bind('<Control-V>', lambda e: self.paste_to_cookie())
        self.cookie_entry.bind('<Control-x>', lambda e: self.cut_cookie())
        self.cookie_entry.bind('<Control-X>', lambda e: self.cut_cookie())
        self.cookie_entry.bind('<Button-3>', lambda e: self.show_cookie_context_menu(e))
        self.cookie_entry.bind('<FocusOut>', lambda e: self.save_cookie())
        self.cookie_entry.bind('<Return>', lambda e: self.save_cookie())

    def select_all_cookie(self):
        self.cookie_entry.focus_set()
        self.cookie_entry.select_range(0, tk.END)
        return 'break'

    def copy_cookie(self):
        try:
            if self.cookie_entry.selection_present():
                text = self.cookie_entry.selection_get()
            else:
                text = self.cookie_entry.get()
            self.clipboard_clear()
            self.clipboard_append(text)
        except:
            pass
        return 'break'

    def paste_to_cookie(self):
        try:
            text = self.clipboard_get()
            
            try:
                if self.cookie_entry.selection_present():
                    start = self.cookie_entry.index(tk.SEL_FIRST)
                    end = self.cookie_entry.index(tk.SEL_LAST)
                    self.cookie_entry.delete(start, end)
            except:
                pass
            
            position = self.cookie_entry.index(tk.INSERT)
            self.cookie_entry.insert(position, text)
        except:
            pass
        return 'break'

    def cut_cookie(self):
        try:
            if self.cookie_entry.selection_present():
                text = self.cookie_entry.selection_get()
                self.clipboard_clear()
                self.clipboard_append(text)
                start = self.cookie_entry.index(tk.SEL_FIRST)
                end = self.cookie_entry.index(tk.SEL_LAST)
                self.cookie_entry.delete(start, end)
        except:
            pass
        return 'break'

    def show_cookie_context_menu(self, event):
        context_menu = tk.Menu(self, tearoff=0, bg="#2A2A2A", fg="#E0E0E0", activebackground="#3B3B3B")
        
        context_menu.add_command(label="Cut", command=lambda: self.cut_cookie())
        context_menu.add_command(label="Copy", command=lambda: self.copy_cookie())
        context_menu.add_command(label="Paste", command=lambda: self.paste_to_cookie())
        context_menu.add_separator()
        context_menu.add_command(label="Select All", command=lambda: self.select_all_cookie())
        
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    def toggle_cookie_visibility(self):
        if self.cookie_entry.cget("show") == "*":
            self.cookie_entry.configure(show="")
            self.show_cookie_button.configure(text="HIDE")
        else:
            self.cookie_entry.configure(show="*")
            self.show_cookie_button.configure(text="VIEW")
    
    def get_cookie(self):
        if self.cookie_auto_obtained:
            return self.cookie
        elif hasattr(self, 'cookie_entry'):
            return self.cookie_entry.get().strip()
        return ""
        
    def create_search_section(self):
        search_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        search_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        search_frame.grid_columnconfigure(0, weight=1)
        
        search_container = ctk.CTkFrame(
            search_frame,
            corner_radius=8,
            fg_color=self.colors["card_bg"],
            border_width=1,
            border_color=self.colors["border"]
        )
        search_container.grid(row=0, column=0, sticky="ew")
        search_container.grid_columnconfigure(0, weight=1)
        
        self.search_entry = ctk.CTkEntry(
            search_container,
            placeholder_text="Enter Place ID",
            height=45,
            border_width=0,
            fg_color="transparent",
            font=ctk.CTkFont(size=14)
        )
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(20, 0), pady=2)
        self.search_entry.bind("<Return>", lambda e: self.search_places())
        
        self.setup_search_entry_bindings()
        
        self.search_button = ctk.CTkButton(
            search_container,
            text="SEARCH",
            height=38,
            width=100,
            corner_radius=6,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self.search_places
        )
        self.search_button.grid(row=0, column=1, padx=5, pady=5)
        
        self.error_label = ctk.CTkLabel(
            search_frame,
            text="",
            text_color=self.colors["error"],
            font=ctk.CTkFont(size=12)
        )
        self.error_label.grid(row=1, column=0, pady=(8, 0))
        
    def setup_search_entry_bindings(self):
        def bind_entry_events(entry_widget):
            entry_widget.bind('<Control-v>', lambda e: self.paste_to_search_entry(e))
            entry_widget.bind('<Command-v>', lambda e: self.paste_to_search_entry(e))
            entry_widget.bind('<Button-3>', lambda e: self.show_search_context_menu(e))
        
        self.after(100, lambda: bind_entry_events(self.search_entry))

    def paste_to_search_entry(self, event):
        try:
            text = self.clipboard_get()
            try:
                start = self.search_entry.index("sel.first")
                end = self.search_entry.index("sel.last")
                self.search_entry.delete(start, end)
            except:
                pass
            self.search_entry.insert(self.search_entry.index("insert"), text)
            return 'break'
        except Exception as e:
            print(f"Paste error: {e}")

    def show_search_context_menu(self, event):
        context_menu = tk.Menu(self, tearoff=0, bg="#2A2A2A", fg="#E0E0E0", activebackground="#3B3B3B")
        
        def do_cut():
            try:
                self.search_entry.event_generate('<<Cut>>')
            except:
                text = self.search_entry.get()
                self.clipboard_clear()
                self.clipboard_append(text)
                self.search_entry.delete(0, 'end')
        
        def do_copy():
            try:
                self.search_entry.event_generate('<<Copy>>')
            except:
                text = self.search_entry.get()
                self.clipboard_clear()
                self.clipboard_append(text)
        
        def do_paste():
            self.paste_to_search_entry(None)
        
        def do_select_all():
            self.search_entry.select_range(0, 'end')
        
        context_menu.add_command(label="Cut", command=do_cut)
        context_menu.add_command(label="Copy", command=do_copy)
        context_menu.add_command(label="Paste", command=do_paste)
        context_menu.add_separator()
        context_menu.add_command(label="Select All", command=do_select_all)
        
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    def create_results_section(self):
        self.results_frame = ctk.CTkFrame(
            self.main_container,
            fg_color="transparent"
        )
        self.results_frame.grid(row=3, column=0, sticky="nsew", pady=(0, 10))
        self.results_frame.grid_columnconfigure(0, weight=1)
        self.results_frame.grid_rowconfigure(1, weight=1)
        
        self.game_info_frame = ctk.CTkFrame(
            self.results_frame,
            corner_radius=8,
            fg_color=self.colors["card_bg"]
        )
        self.game_info_frame.grid_columnconfigure(0, weight=1)
        
        info_content = ctk.CTkFrame(self.game_info_frame, fg_color="transparent")
        info_content.grid(row=0, column=0, sticky="ew", padx=20, pady=15)
        info_content.grid_columnconfigure(0, weight=1)
        
        self.game_name_label = ctk.CTkLabel(
            info_content,
            text="",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.colors["text_primary"],
            wraplength=600,
            anchor="w",
            justify="left"
        )
        self.game_name_label.grid(row=0, column=0, sticky="w", pady=(0, 5))
        
        self.info_stats = ctk.CTkLabel(
            info_content,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_secondary"],
            anchor="w"
        )
        self.info_stats.grid(row=1, column=0, sticky="w")
        
        self.game_info_frame.grid_forget()
        
        self.places_scroll = ctk.CTkScrollableFrame(
            self.results_frame,
            fg_color="transparent",
            scrollbar_button_color=self.colors["border"],
            scrollbar_button_hover_color=self.colors["text_secondary"]
        )
        self.places_scroll.grid(row=1, column=0, sticky="nsew")
        self.places_scroll.grid_columnconfigure(0, weight=1)
        
        self.loading_frame = ctk.CTkFrame(self.places_scroll, fg_color="transparent")
        self.loading_label = ctk.CTkLabel(
            self.loading_frame,
            text="LOADING...",
            font=ctk.CTkFont(size=14, family="Consolas"),
            text_color=self.colors["text_secondary"]
        )
        self.loading_label.pack(pady=50)
        
        self.places_grid = ctk.CTkFrame(self.places_scroll, fg_color="transparent")
        self.places_grid.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.places_grid.grid_columnconfigure(0, weight=1)
        
        self.loading_frame.grid_forget()
        
    def show_debug_window(self):
        debug_window = ctk.CTkToplevel(self)
        debug_window.title("Debug Logs")
        debug_window.geometry("800x600")
        debug_window.configure(fg_color="#1A1A1A")
        
        header = ctk.CTkLabel(
            debug_window,
            text="DEBUG LOGS",
            font=ctk.CTkFont(size=18, weight="bold", family="Consolas"),
            text_color=self.colors["text_primary"]
        )
        header.pack(pady=(20, 10))
        
        log_text = ctk.CTkTextbox(
            debug_window,
            font=ctk.CTkFont(family="Consolas", size=10),
            wrap="none",
            fg_color=self.colors["input_bg"],
            text_color=self.colors["text_primary"]
        )
        log_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        for log in self.debug_logs:
            log_text.insert("end", log + "\n")
        
        log_text.see("end")
        
        button_frame = ctk.CTkFrame(debug_window, fg_color="transparent")
        button_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        clear_button = ctk.CTkButton(
            button_frame,
            text="CLEAR",
            width=100,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            command=lambda: self.clear_debug_logs(log_text)
        )
        clear_button.pack(side="left", padx=(0, 10))
        
        copy_button = ctk.CTkButton(
            button_frame,
            text="COPY ALL",
            width=100,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            command=lambda: self.copy_debug_logs()
        )
        copy_button.pack(side="left")
        
        def update_logs():
            if debug_window.winfo_exists():
                current_position = log_text.yview()[1]
                log_text.delete("1.0", "end")
                for log in self.debug_logs:
                    log_text.insert("end", log + "\n")
                if current_position == 1.0: 
                    log_text.see("end")
                debug_window.after(1000, update_logs)
        
        update_logs()

    def clear_debug_logs(self, log_text=None):

        self.debug_logs.clear()
        if log_text:
            log_text.delete("1.0", "end")

    def copy_debug_logs(self):
        all_logs = "\n".join(self.debug_logs)
        self.clipboard_clear()
        self.clipboard_append(all_logs)
        self.update_status("Logs copied")        
    def create_status_bar(self):
        status_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        status_frame.grid(row=4, column=0, sticky="ew", pady=(5, 0))
        status_frame.grid_columnconfigure(0, weight=1)
        
        status_text = "READY"
        if not self.is_admin:
            status_text = "LIMITED MODE - NO ADMIN"
            
        self.status_label = ctk.CTkLabel(
            status_frame,
            text=status_text,
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=self.colors["warning"] if not self.is_admin else self.colors["text_secondary"]
        )
        self.status_label.grid(row=0, column=0, sticky="w")
        
        if self.debug_mode:
            debug_button = ctk.CTkButton(
                status_frame,
                text="LOGS",
                width=80,
                height=24,
                corner_radius=4,
                fg_color=self.colors["primary"],
                hover_color=self.colors["primary_hover"],
                text_color=self.colors["text_primary"],
                font=ctk.CTkFont(size=10, weight="bold"),
                command=self.show_debug_window
            )
            debug_button.grid(row=0, column=1, sticky="e", padx=(10, 0))
        
    def format_cookie(self, cookie):
        if not cookie:
            return ""
        if cookie.startswith(".ROBLOSECURITY="):
            return f"{cookie};"
        return f".ROBLOSECURITY={cookie};"
        
    def game_join_request(self, place_id):
        try:
            self.join_attempts += 1
            
            cookie = self.get_cookie()
            if not cookie:
                raise Exception("Cookie is required")
                
            formatted_cookie = self.format_cookie(cookie)
            
            url = "https://gamejoin.roblox.com/v1/join-game"
            
            data = {
                "placeId": place_id,
                "gameJoinAttemptId": str(uuid.uuid4()).upper(),
                "IsTeleport": True,
                "isQueueAllowedOverride": True
            }
            
            headers = {
                "Host": "gamejoin.roblox.com",
                "User-Agent": "Roblox/Linux",
                "Requester": "Client",
                "Content-Type": "application/json",
                "Cookie": formatted_cookie,
            }
            
            self.debug_log(f"Sending POST request to: {url}", "REQUEST")
            self.debug_log(f"Request data: {json.dumps(data, indent=2)}", "REQUEST")
            self.debug_log(f"Cookie length: {len(formatted_cookie)} chars", "REQUEST")
            
            start_time = time.time()
            response = requests.post(url, headers=headers, json=data, timeout=10)
            elapsed_time = time.time() - start_time
            
            self.debug_log(f"Response status code: {response.status_code}", "RESPONSE")
            self.debug_log(f"Response time: {elapsed_time:.3f} seconds", "RESPONSE")
            self.debug_log(f"Response headers: {json.dumps(dict(response.headers), indent=2)}", "RESPONSE")
            
            response_json = None
            try:
                response_json = response.json()
                self.debug_log(f"Response body: {json.dumps(response_json, indent=2)}", "RESPONSE")
                
                if 'status' in response_json:
                    status_meaning = self.interpret_game_join_status(response_json['status'])
                    self.debug_log(f"Status interpretation: {status_meaning}", "INFO")
                    
                    if hasattr(self, 'status_text_label'):
                        self.status_text_label.configure(text=status_meaning)
                    
            except:
                self.debug_log(f"Response text: {response.text[:500]}", "RESPONSE")
            
            response.raise_for_status()
            
            return response_json if response_json else response.json()
            
        except requests.exceptions.RequestException as e:
            self.debug_log(f"Request error: {str(e)}", "ERROR")
            if hasattr(e, 'response') and e.response is not None:
                self.debug_log(f"Error response: {e.response.text[:500]}", "ERROR")
            raise Exception(f"Failed to get game join allowance: {str(e)}")
        except Exception as e:
            self.debug_log(f"General error: {str(e)}", "ERROR")
            raise Exception(f"Failed to get game join allowance: {str(e)}")
            
    def interpret_game_join_status(self, status):
        status_meanings = {
            0: "Waiting in queue...",
            1: "Loading...",
            2: "Success - Ready to join",
            3: "Server full",
            4: "Unauthorized",
            5: "Error occurred",
            6: "Game not available",
            7: "User left",
            8: "Game ended",
            9: "Game started",
            10: "Place restricted"
        }
        return status_meanings.get(status, f"Unknown status: {status}")    
    def get_teleport_allowance(self, root_place_id, target_place_id, callback):
        def worker():
            try:
                self.after(0, lambda: self.update_status("Getting teleport allowance..."))
                
                max_attempts = 10
                attempts = 0
                
                while attempts < max_attempts:
                    attempts += 1 
                    self.debug_log(f"Attempt {attempts}/{max_attempts} for root place", "INFO")
                    
                    try:
                        response = self.game_join_request(root_place_id)
                        response_status = response.get("status")
                        
                        self.debug_log(f"Root place response status: {response_status}", "INFO")
                        
                        if response_status == 2:
                            self.debug_log("Successfully got root place allowance", "SUCCESS")
                            break
                        elif response_status == 0:

                            self.debug_log("Request queued, waiting...", "INFO")
                            time.sleep(2)
                            continue
                        elif response_status in [3, 4, 5, 6, 10]:

                            status_meaning = self.interpret_game_join_status(response_status)
                            raise Exception(f"Failed with status: {status_meaning}")
                        else:

                            self.debug_log(f"Unknown status {response_status}, retrying...", "WARNING")
                            time.sleep(1)
                        
                    except Exception as req_error:
                        self.debug_log(f"Attempt {attempts} failed: {str(req_error)}", "ERROR")
                        if attempts >= max_attempts:
                            raise Exception(f"Failed to get root place allowance after {max_attempts} attempts: {str(req_error)}")
                        time.sleep(1)
                
                if attempts >= max_attempts:
                    raise Exception(f"Failed to get root place allowance - max attempts reached")
                
                self.after(0, lambda: self.update_status("Getting target place allowance..."))
                
                attempts = 0
                while attempts < max_attempts:
                    attempts += 1
                    self.debug_log(f"Attempt {attempts}/{max_attempts} for target place", "INFO")
                    
                    try:
                        response = self.game_join_request(target_place_id)
                        response_status = response.get("status")
                        
                        self.debug_log(f"Target place response status: {response_status}", "INFO")
                        
                        if response_status == 2:
                            self.debug_log("Successfully got target place allowance", "SUCCESS")
                            break
                        elif response_status == 0:
                            self.debug_log("Status 0 - waiting before retry...", "INFO")
                            time.sleep(1)
                            
                    except Exception as req_error:
                        self.debug_log(f"Attempt {attempts} failed: {str(req_error)}", "ERROR")
                        if attempts >= max_attempts:
                            raise Exception(f"Failed to get target place allowance after {max_attempts} attempts: {str(req_error)}")
                        time.sleep(1)
                
                if attempts >= max_attempts:
                    raise Exception(f"Failed to get target place allowance - max attempts reached")
                
                self.after(0, lambda: callback(True, "Successfully got teleport allowance"))
                
            except Exception as error:
                error_message = str(error)
                self.debug_log(f"Teleport allowance failed: {error_message}", "ERROR")
                self.after(0, lambda msg=error_message: callback(False, msg))
        
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()
        
    def get_grid_columns(self):
        width = self.winfo_width()
        
        if width < 500:
            return 1
        elif width < 800:
            return 2
        elif width < 1200:
            return 3
        else:
            return 4
            
    def create_place_card(self, place, is_root=False):
        width = self.winfo_width()
        padding = 20 if width < 600 else 40 if width < 900 else 80
        columns = self.get_grid_columns()
        card_width = (width - padding - (columns * 16)) // columns
        card_width = max(250, min(card_width, 350))
        
        card = ctk.CTkFrame(
            self.places_grid,
            corner_radius=8,
            fg_color=self.colors["card_bg"],
            border_width=1,
            border_color=self.colors["success"] if is_root else self.colors["border"],
            width=card_width
        )
        
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=16, pady=16)
        content.grid_columnconfigure(0, weight=1)
        
        top_row = ctk.CTkFrame(content, fg_color="transparent")
        top_row.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top_row.grid_columnconfigure(1, weight=1)
        
        icon_size = 40 if width < 600 else 48
        icon_frame = ctk.CTkFrame(
            top_row,
            width=icon_size,
            height=icon_size,
            corner_radius=8,
            fg_color=self.colors["bg_secondary"]
        )
        icon_frame.grid(row=0, column=0, padx=(0, 10))
        icon_frame.grid_propagate(False)
        
        icon_label = ctk.CTkLabel(
            icon_frame,
            text="▣",
            font=ctk.CTkFont(size=icon_size//2),
            text_color=self.colors["text_secondary"]
        )
        icon_label.place(relx=0.5, rely=0.5, anchor="center")
        
        place_id = place.get('id')
        self.executor.submit(self._load_icon_async, place_id, icon_label, icon_size)
        
        name_frame = ctk.CTkFrame(top_row, fg_color="transparent")
        name_frame.grid(row=0, column=1, sticky="ew")
        
        font_size = 12 if width < 600 else 14
        name_label = ctk.CTkLabel(
            name_frame,
            text=place.get("name", "Unknown Place"),
            font=ctk.CTkFont(size=font_size, weight="bold"),
            text_color=self.colors["text_primary"],
            anchor="w",
            wraplength=card_width - 100
        )
        name_label.pack(anchor="w")
        
        if is_root:
            badge = ctk.CTkFrame(
                name_frame,
                corner_radius=3,
                fg_color=self.colors["success"],
                height=16
            )
            badge.pack(anchor="w", pady=(4, 0))
            
            badge_label = ctk.CTkLabel(
                badge,
                text="ROOT",
                font=ctk.CTkFont(size=9, weight="bold"),
                text_color=self.colors["text_primary"]
            )
            badge_label.pack(padx=6, pady=1)
        
        id_label = ctk.CTkLabel(
            content,
            text=f"ID: {place.get('id', 'Unknown')}",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=self.colors["text_secondary"],
            anchor="w"
        )
        id_label.grid(row=1, column=0, sticky="w")
        
        buttons_frame = ctk.CTkFrame(content, fg_color="transparent")
        buttons_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        buttons_frame.grid_columnconfigure(0, weight=1)
        buttons_frame.grid_columnconfigure(1, weight=1)
        
        button_height = 28 if width < 600 else 32
        
        button_disabled = not is_root and not self.is_admin
        button_text = "JOIN" if not button_disabled else "JOIN ⚠"
        button_color = self.colors["success"] if not button_disabled else self.colors["border"]
        
        join_button = ctk.CTkButton(
            buttons_frame,
            text=button_text,
            height=button_height,
            corner_radius=6,
            fg_color=button_color,
            hover_color=self.colors["success_hover"] if not button_disabled else self.colors["border"],
            text_color=self.colors["text_primary"],
            font=ctk.CTkFont(size=11, weight="bold"),
            command=lambda: self.join_place(place.get('id'), is_root),
            state="normal" if not button_disabled else "disabled"
        )
        join_button.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        
        if button_disabled:
            join_button.bind("<Enter>", lambda e: self.show_admin_tooltip())
        
        open_button = ctk.CTkButton(
            buttons_frame,
            text="OPEN",
            height=button_height,
            corner_radius=6,
            fg_color="transparent",
            border_width=1,
            border_color=self.colors["border"],
            hover_color=self.colors["bg_secondary"],
            text_color=self.colors["text_primary"],
            font=ctk.CTkFont(size=11),
            command=lambda: self.open_place(place.get('id'))
        )
        open_button.grid(row=0, column=1, sticky="ew", padx=(4, 0))
        
        def on_enter(e):
            card.configure(border_width=2)
            
        def on_leave(e):
            card.configure(border_width=1)
            
        card.bind("<Enter>", on_enter)
        card.bind("<Leave>", on_leave)
        
        return card
    
    def show_admin_tooltip(self):
        self.update_status("⚠ Admin rights required")
        
    def rearrange_places(self):
        if not self.place_cards:
            return
            
        columns = self.get_grid_columns()
        
        for i in range(10):
            self.places_grid.grid_columnconfigure(i, weight=0)
            
        for i in range(columns):
            self.places_grid.grid_columnconfigure(i, weight=1)
            
        for idx, (card, place, is_root) in enumerate(self.place_cards):
            card.destroy()
            new_card = self.create_place_card(place, is_root)
            
            row = idx // columns
            col = idx % columns
            new_card.grid(row=row, column=col, padx=8, pady=8, sticky="ew")
            
            self.place_cards[idx] = (new_card, place, is_root)
        
    @lru_cache(maxsize=100)
    def load_place_icon(self, place_id, size=48):
        try:
            response = requests.get(
                f"https://thumbnails.roblox.com/v1/places/gameicons?placeIds={place_id}&size=150x150&format=Png",
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get("data") and data["data"][0].get("imageUrl"):
                img_url = data["data"][0]["imageUrl"]
                img_response = requests.get(img_url, timeout=5)
                img_response.raise_for_status()
                
                img = Image.open(BytesIO(img_response.content))
                img = img.resize((size, size), Image.Resampling.LANCZOS)
                
                mask = Image.new('L', (size, size), 0)
                draw = ImageDraw.Draw(mask)
                draw.rounded_rectangle((0, 0, size, size), radius=8, fill=255)
                
                output = Image.new('RGBA', (size, size), (0, 0, 0, 0))
                output.paste(img, (0, 0))
                output.putalpha(mask)
                
                return ctk.CTkImage(light_image=output, dark_image=output, size=(size, size))
        except:
            pass
        
        return self.default_icon
        
    def _load_icon_async(self, place_id, icon_label, size=48):
        try:
            icon = self.load_place_icon(place_id, size)
            self.after(0, lambda: self._update_icon(icon_label, icon))
        except:
            pass
            
    def _update_icon(self, icon_label, icon):
        try:
            if icon:
                icon_label.configure(image=icon, text="")
                icon_label.image = icon
        except:
            pass
           
    def launch_roblox(self, place_id):
        try:
            roblox_url = f"roblox://experiences/start?placeId={place_id}"
            
            system = platform.system()
            
            if system == "Windows":
                os.startfile(roblox_url)
            elif system == "Darwin":
                subprocess.run(["open", roblox_url])
            elif system == "Linux":
                subprocess.run(["xdg-open", roblox_url])
            else:
                webbrowser.open(roblox_url)
                
            self.show_join_success(place_id)
            
        except Exception as e:
            raise Exception(f"Failed to launch Roblox: {str(e)}")
            
    def show_join_success(self, place_id):
        original_status = self.status_label.cget("text")
        self.status_label.configure(
            text=f"✓ LAUNCHED {place_id}",
            text_color=self.colors["success"]
        )
        
        self.after(3000, lambda: self.status_label.configure(
            text=original_status,
            text_color=self.colors["warning"] if not self.is_admin else self.colors["text_secondary"]
        ))
            
    def search_places(self):
        place_id = self.search_entry.get().strip()
        
        if not place_id:
            self.show_error("Enter a Place ID")
            return
            
        if not place_id.isdigit():
            self.show_error("Place ID must be a number")
            return
            
        self.clear_results()
        self.search_button.configure(state="disabled", text="SEARCHING...")
        self.update_status("Searching...")
        
        thread = threading.Thread(target=self._search_worker, args=(place_id,))
        thread.daemon = True
        thread.start()
        
    def clear_results(self):
        self.error_label.configure(text="")
        self.game_info_frame.grid_forget()
        self.place_cards = []
        
        for widget in self.places_grid.winfo_children():
            widget.destroy()
            
    def _search_worker(self, place_id):
        try:
            self.after(0, self.show_loading)
            
            universe_url = f"https://apis.roblox.com/universes/v1/places/{place_id}/universe"
            self.debug_log(f"Fetching universe for place {place_id}", "REQUEST")
            self.debug_log(f"GET {universe_url}", "REQUEST")
            
            start_time = time.time()
            universe_response = requests.get(universe_url, timeout=10)
            elapsed = time.time() - start_time
            
            self.debug_log(f"Universe response: {universe_response.status_code} in {elapsed:.3f}s", "RESPONSE")
            universe_response.raise_for_status()
            universe_data = universe_response.json()
            self.debug_log(f"Universe data: {json.dumps(universe_data, indent=2)}", "RESPONSE")
            universe_id = universe_data.get("universeId")
            
            self.current_universe_id = universe_id
            
            game_url = f"https://games.roblox.com/v1/games?universeIds={universe_id}"
            self.debug_log(f"Fetching game info for universe {universe_id}", "REQUEST")
            self.debug_log(f"GET {game_url}", "REQUEST")
            
            start_time = time.time()
            game_response = requests.get(game_url, timeout=10)
            elapsed = time.time() - start_time
            
            self.debug_log(f"Game response: {game_response.status_code} in {elapsed:.3f}s", "RESPONSE")
            game_response.raise_for_status()
            game_data = game_response.json()
            self.debug_log(f"Game data: {json.dumps(game_data, indent=2)}", "RESPONSE")
            game = game_data.get("data", [{}])[0]
            
            all_places = []
            cursor = None
            page_count = 0
            
            while True:
                page_count += 1
                url = f"https://develop.roblox.com/v1/universes/{universe_id}/places?limit=100"
                if cursor:
                    url += f"&cursor={cursor}"
                
                self.debug_log(f"Fetching places page {page_count}", "REQUEST")
                self.debug_log(f"GET {url}", "REQUEST")
                
                start_time = time.time()
                places_response = requests.get(url, timeout=10)
                elapsed = time.time() - start_time
                
                self.debug_log(f"Places response: {places_response.status_code} in {elapsed:.3f}s", "RESPONSE")
                places_response.raise_for_status()
                places_data = places_response.json()
                
                places_count = len(places_data.get("data", []))
                self.debug_log(f"Got {places_count} places on page {page_count}", "RESPONSE")
                
                all_places.extend(places_data.get("data", []))
                cursor = places_data.get("nextPageCursor")
                
                if not cursor:
                    self.debug_log(f"No more pages. Total places: {len(all_places)}", "INFO")
                    break
                    
            self.after(0, lambda: self.display_results(game, universe_id, all_places))
        
        except requests.exceptions.RequestException as e:
            self.debug_log(f"Network error: {str(e)}", "ERROR")
            self.after(0, lambda: self.show_error("Network error"))
        except Exception as e:
            self.debug_log(f"General error: {str(e)}", "ERROR")
            self.after(0, lambda: self.show_error(f"Error: {str(e)}"))
        finally:
            self.after(0, self.hide_loading)
            self.after(0, lambda: self.search_button.configure(state="normal", text="SEARCH"))
                
    def display_results(self, game, universe_id, places):
        self.game_info_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        
        game_name = game.get("name", "Unknown Game")
        self.game_name_label.configure(text=game_name.upper())
        
        creator = game.get("creator", {}).get("name", "Unknown")
        width = self.winfo_width()
        
        if width < 600:
            stats_text = f"{len(places)} PLACES • {creator.upper()}"
        else:
            stats_text = f"{len(places)} PLACES • UNIVERSE {universe_id} • {creator.upper()}"
        self.info_stats.configure(text=stats_text)
        
        self.root_place_id = game.get("rootPlaceId")
        root_id = self.root_place_id
        columns = self.get_grid_columns()
        
        for i in range(columns):
            self.places_grid.grid_columnconfigure(i, weight=1)
        
        self.place_cards = []
        for idx, place in enumerate(places):
            is_root = place.get("id") == root_id
            card = self.create_place_card(place, is_root)
            
            row = idx // columns
            col = idx % columns
            card.grid(row=row, column=col, padx=8, pady=8, sticky="ew")
            
            self.place_cards.append((card, place, is_root))
                
        status_text = f"FOUND {len(places)} PLACES"
        if not self.is_admin and any(not is_root for _, _, is_root in self.place_cards):
            status_text += " - ADMIN REQUIRED"
            
        self.update_status(status_text)
        
    def show_loading(self):
        self.places_grid.grid_forget()
        self.loading_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=50)
        
    def hide_loading(self):
        self.loading_frame.grid_forget()
        self.places_grid.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
    def show_error(self, message):
        self.error_label.configure(text=f"⚠ {message}")
        self.update_status("ERROR")
        
        self.after(5000, lambda: self.error_label.configure(text=""))
        
    def update_status(self, message):
        if not self.is_admin and "READY" in message.upper():
            message += " - LIMITED"
        self.status_label.configure(text=message.upper())
        
    def open_place(self, place_id):
        webbrowser.open(f"https://www.roblox.com/games/{place_id}")
        self.update_status(f"OPENING {place_id}")
            
    def __del__(self):
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)
        if hasattr(self, 'gamejoin_blocker'):
            self.gamejoin_blocker.stop_blocking()

if __name__ == "__main__":
    if sys.platform == "win32" and not is_admin():
        run_as_admin()
    
    app = RobloxSubplaceExplorer()
    app.mainloop()
