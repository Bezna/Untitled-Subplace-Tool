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

COOKIE_FILE = "roblox_cookie.txt"
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

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
            "primary": "#2563EB",
            "primary_hover": "#1D4ED8",
            "success": "#10B981",
            "success_hover": "#059669",
            "bg_secondary": "#F9FAFB",
            "text_primary": "#111827",
            "text_secondary": "#6B7280",
            "border": "#E5E7EB",
            "error": "#EF4444",
            "warning": "#F59E0B"
        }
        
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
        
        self.create_default_icon()
        
        self.create_ui()
        self.update()
        self.center_window()
        
        self.bind("<Configure>", self.on_window_resize)
        self.load_cookie()
        
    def save_cookie(self):
        try:
            with open(COOKIE_FILE, "w", encoding="utf-8") as f:
                f.write(self.cookie_entry.get())
        except Exception as e:
            print("Failed to save cookie:", e)

    def load_cookie(self):
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
            
            draw.rounded_rectangle((0, 0, size, size), radius=10, fill="#E5E7EB")
            
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
                self.title_label.configure(font=ctk.CTkFont(size=20, weight="bold"))
                self.subtitle_label.configure(font=ctk.CTkFont(size=12))
            else:
                self.title_label.configure(font=ctk.CTkFont(size=28, weight="bold"))
                self.subtitle_label.configure(font=ctk.CTkFont(size=16))
                
        if hasattr(self, 'search_entry'):
            if width < 600:
                self.search_entry.configure(height=40, font=ctk.CTkFont(size=14))
                self.search_button.configure(width=80, height=34)
            else:
                self.search_entry.configure(height=50, font=ctk.CTkFont(size=16))
                self.search_button.configure(width=100, height=40)
                
        if hasattr(self, 'place_cards') and self.place_cards:
            self.rearrange_places()
        
    def create_ui(self):
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=0, sticky="nsew", padx=40, pady=30)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(3, weight=1)
        
        self.create_header()
        
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
            text="Untitled Subplace Tool",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        self.title_label.grid(row=0, column=0)
        
        subtitle_text = "Join any subplace of a game with ease."
        if not self.is_admin:
            subtitle_text += " (Limited Mode - Admin rights required for subplaces)"
        
        self.subtitle_label = ctk.CTkLabel(
            header_frame,
            text=subtitle_text,
            font=ctk.CTkFont(size=16),
            text_color=self.colors["warning"] if not self.is_admin else self.colors["text_secondary"]
        )
        self.subtitle_label.grid(row=1, column=0, pady=(5, 0))
        
    def create_cookie_section(self):
        cookie_frame = ctk.CTkFrame(self.main_container, corner_radius=12)
        cookie_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        cookie_frame.grid_columnconfigure(1, weight=1)
        
        cookie_label = ctk.CTkLabel(
            cookie_frame,
            text="Cookie:",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        cookie_label.grid(row=0, column=0, padx=(20, 10), pady=15, sticky="w")
        
        self.cookie_entry = ctk.CTkEntry(
            cookie_frame,
            placeholder_text="Enter your .ROBLOSECURITY cookie (required for subplace joining)",
            height=40,
            border_width=1,
            border_color=self.colors["border"],
            font=ctk.CTkFont(size=12),
            show="*"
        )
        self.cookie_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10), pady=15)
        
        self.setup_cookie_entry_bindings()
        
        self.show_cookie_button = ctk.CTkButton(
            cookie_frame,
            text="View",
            width=40,
            height=40,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=self.colors["border"],
            hover_color=self.colors["bg_secondary"],
            text_color=self.colors["text_primary"],
            command=self.toggle_cookie_visibility
        )
        self.show_cookie_button.grid(row=0, column=2, padx=(0, 20), pady=15)
        
        cookie_info = ctk.CTkLabel(
            cookie_frame,
            text="Cookie is required to join non-root places. Get it from browser. You can use EditThisCookie extension or from Storage -> Cookies -> .ROBLOSECURITY",
            font=ctk.CTkFont(size=11),
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
        context_menu = tk.Menu(self, tearoff=0)
        
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
            self.show_cookie_button.configure(text="Unview")
        else:
            self.cookie_entry.configure(show="*")
            self.show_cookie_button.configure(text="View")
        
    def create_search_section(self):
        search_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        search_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        search_frame.grid_columnconfigure(0, weight=1)
        
        search_container = ctk.CTkFrame(
            search_frame,
            corner_radius=12,
            fg_color="white",
            border_width=1,
            border_color=self.colors["border"]
        )
        search_container.grid(row=0, column=0, sticky="ew")
        search_container.grid_columnconfigure(0, weight=1)
        
        self.search_entry = ctk.CTkEntry(
            search_container,
            placeholder_text="Enter Place ID",
            height=50,
            border_width=0,
            fg_color="transparent",
            font=ctk.CTkFont(size=16)
        )
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(20, 0), pady=2)
        self.search_entry.bind("<Return>", lambda e: self.search_places())
        
        self.setup_search_entry_bindings()
        
        self.search_button = ctk.CTkButton(
            search_container,
            text="Search",
            height=40,
            width=100,
            corner_radius=8,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.search_places
        )
        self.search_button.grid(row=0, column=1, padx=5, pady=5)
        
        self.error_label = ctk.CTkLabel(
            search_frame,
            text="",
            text_color=self.colors["error"],
            font=ctk.CTkFont(size=13)
        )
        self.error_label.grid(row=1, column=0, pady=(8, 0))
        
    def setup_search_entry_bindings(self):
        def bind_entry_events(entry_widget):
            entry_widget.bind('<Control-v>', lambda e: self.paste_to_search_entry(e))
            entry_widget.bind('<Command-v>', lambda e: self.paste_to_search_entry(e))  # macOS
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
        context_menu = tk.Menu(self, tearoff=0)
        
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
            corner_radius=12,
            fg_color=self.colors["bg_secondary"]
        )
        self.game_info_frame.grid_columnconfigure(0, weight=1)
        
        info_content = ctk.CTkFrame(self.game_info_frame, fg_color="transparent")
        info_content.grid(row=0, column=0, sticky="ew", padx=20, pady=15)
        info_content.grid_columnconfigure(0, weight=1)
        
        self.game_name_label = ctk.CTkLabel(
            info_content,
            text="",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=self.colors["text_primary"],
            wraplength=600,
            anchor="w",
            justify="left"
        )
        self.game_name_label.grid(row=0, column=0, sticky="w", pady=(0, 5))
        
        self.info_stats = ctk.CTkLabel(
            info_content,
            text="",
            font=ctk.CTkFont(size=13),
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
            text="Loading places...",
            font=ctk.CTkFont(size=16),
            text_color=self.colors["text_secondary"]
        )
        self.loading_label.pack(pady=50)
        
        self.places_grid = ctk.CTkFrame(self.places_scroll, fg_color="transparent")
        self.places_grid.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.places_grid.grid_columnconfigure(0, weight=1)
        
        self.loading_frame.grid_forget()
            
    def create_status_bar(self):
        status_text = "Ready"
        if not self.is_admin:
            status_text = "Ready (Limited Mode - No Admin Rights)"
            
        self.status_label = ctk.CTkLabel(
            self.main_container,
            text=status_text,
            font=ctk.CTkFont(size=12),
            text_color=self.colors["warning"] if not self.is_admin else self.colors["text_secondary"]
        )
        self.status_label.grid(row=4, column=0, sticky="w", pady=(5, 0))
        
    def format_cookie(self, cookie):
        if not cookie:
            return ""
        if cookie.startswith(".ROBLOSECURITY="):
            return f"{cookie};"
        return f".ROBLOSECURITY={cookie};"
        
    def game_join_request(self, place_id):
        try:
            cookie = self.cookie_entry.get().strip()
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
            
            response = requests.post(url, headers=headers, json=data, timeout=10)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            raise Exception(f"Failed to get game join allowance: {str(e)}")
        
    def get_teleport_allowance(self, root_place_id, target_place_id, callback):
        def worker():
            try:
                self.after(0, lambda: self.update_status("Getting teleport allowance for root place..."))
                
                max_attempts = 10
                attempts = 0
                
                while attempts < max_attempts:
                    try:
                        response = self.game_join_request(root_place_id)
                        if response.get("status") == 2:
                            break
                        attempts += 1
                        if attempts >= max_attempts:
                            raise Exception("Failed to get root place allowance")
                    except Exception as e:
                        attempts += 1
                        if attempts >= max_attempts:
                            raise e
                
                self.after(0, lambda: self.update_status("Getting teleport allowance for target place..."))
                
                attempts = 0
                while attempts < max_attempts:
                    try:
                        response = self.game_join_request(target_place_id)
                        if response.get("status") == 2:
                            break
                        attempts += 1
                        if attempts >= max_attempts:
                            raise Exception("Failed to get target place allowance")
                    except Exception as e:
                        attempts += 1
                        if attempts >= max_attempts:
                            raise e
                
                self.after(0, lambda: callback(True, "Successfully got teleport allowance"))
                
            except Exception as e:
                self.after(0, lambda: callback(False, str(e)))
        
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
            corner_radius=12,
            fg_color="white",
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
            corner_radius=10,
            fg_color=self.colors["bg_secondary"]
        )
        icon_frame.grid(row=0, column=0, padx=(0, 10))
        icon_frame.grid_propagate(False)
        
        icon_label = ctk.CTkLabel(
            icon_frame,
            text="🎮",
            font=ctk.CTkFont(size=icon_size//3)
        )
        icon_label.place(relx=0.5, rely=0.5, anchor="center")
        
        place_id = place.get('id')
        self.executor.submit(self._load_icon_async, place_id, icon_label, icon_size)
        
        name_frame = ctk.CTkFrame(top_row, fg_color="transparent")
        name_frame.grid(row=0, column=1, sticky="ew")
        
        font_size = 13 if width < 600 else 15
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
                corner_radius=4,
                fg_color=self.colors["success"],
                height=18
            )
            badge.pack(anchor="w", pady=(4, 0))
            
            badge_label = ctk.CTkLabel(
                badge,
                text="ROOT",
                font=ctk.CTkFont(size=9, weight="bold"),
                text_color="white"
            )
            badge_label.pack(padx=6, pady=1)
        
        id_label = ctk.CTkLabel(
            content,
            text=f"ID: {place.get('id', 'Unknown')}",
            font=ctk.CTkFont(size=12, family="Consolas"),
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
        button_text = "Join 🚀" if not button_disabled else "Join ⚠️"
        button_color = self.colors["success"] if not button_disabled else self.colors["text_secondary"]
        
        join_button = ctk.CTkButton(
            buttons_frame,
            text=button_text,
            height=button_height,
            corner_radius=8,
            fg_color=button_color,
            hover_color=self.colors["success_hover"] if not button_disabled else self.colors["text_secondary"],
            text_color="white",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: self.join_place(place.get('id'), is_root),
            state="normal" if not button_disabled else "disabled"
        )
        join_button.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        
        if button_disabled:
            join_button.bind("<Enter>", lambda e: self.show_admin_tooltip())
        
        open_button = ctk.CTkButton(
            buttons_frame,
            text="Open →",
            height=button_height,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=self.colors["border"],
            hover_color=self.colors["bg_secondary"],
            text_color=self.colors["text_primary"],
            font=ctk.CTkFont(size=12),
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
        self.update_status("⚠️ Admin rights required to join subplaces")
        
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
                draw.rounded_rectangle((0, 0, size, size), radius=10, fill=255)
                
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
    
    def block_roblox_internet(self, block=True):
        if platform.system() != "Windows":
            return
        
        if not self.is_admin:
            print("Cannot block Roblox internet: no admin rights")
            return
            
        rule_name = "BlockRobloxPlayerBeta"
        exe_path = self.get_roblox_exe_path()
        if not exe_path:
            return
            
        try:
            if block:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=out", "action=block",
                    f"program={exe_path}",
                    "enable=yes"
                ], check=True, shell=True, capture_output=True)
            else:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ], check=True, shell=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(f"Firewall error: {e}")

    def get_roblox_exe_path(self):
        default_path = os.path.expandvars(r"%LOCALAPPDATA%\Roblox\Versions")
        if os.path.exists(default_path):
            for folder in os.listdir(default_path):
                exe_path = os.path.join(default_path, folder, "RobloxPlayerBeta.exe")
                if os.path.exists(exe_path):
                    return exe_path
        return "RobloxPlayerBeta.exe"
    
    def join_place(self, place_id, is_root=False):
        try:
            if is_root:
                self.launch_roblox(place_id)
            else:
                if not self.is_admin:
                    messagebox.showwarning(
                        "Admin Rights Required",
                        "Administrator rights are required to join subplaces.\n\n"
                        "Please restart the application as administrator.",
                        icon='warning'
                    )
                    return
                    
                cookie = self.cookie_entry.get().strip()
                if not cookie:
                    self.show_error("Cookie is required to join subplaces")
                    return
                
                if not self.root_place_id:
                    self.show_error("No root place found")
                    return
                
                def on_allowance_result(success, message):
                    if success:
                        self.update_status("✅ Got teleport allowance! Launching Roblox...")
                        self.block_roblox_internet(True)
                        self.launch_roblox(place_id)
                        self.after(2000, lambda: self.block_roblox_internet(False)) 
                        messagebox.showinfo(
                            "Ready to Join", 
                            "Teleport allowance acquired!\n\nRoblox will launch now. Once in-game, you can click the 'Retry' or 'Reconnect' button to join the subplace."
                        )
                    else:
                        self.show_error(f"Failed to get allowance: {message}")
                        
                self.get_teleport_allowance(self.root_place_id, place_id, on_allowance_result)

        except Exception as e:
            self.show_error(f"Failed to join place: {str(e)}")
            
    def launch_roblox(self, place_id):
        try:
            roblox_url = f"roblox://experiences/start?placeId={place_id}"
            
            system = platform.system()
            
            if system == "Windows":
                os.startfile(roblox_url)
            elif system == "Darwin":  # macOS
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
            text=f"✅ Launched Roblox for place {place_id}",
            text_color=self.colors["success"]
        )
        
        self.after(3000, lambda: self.status_label.configure(
            text=original_status,
            text_color=self.colors["warning"] if not self.is_admin else self.colors["text_secondary"]
        ))
            
    def search_places(self):
        place_id = self.search_entry.get().strip()
        
        if not place_id:
            self.show_error("Please enter a Place ID")
            return
            
        if not place_id.isdigit():
            self.show_error("Place ID must be a number")
            return
            
        self.clear_results()
        self.search_button.configure(state="disabled", text="Searching...")
        self.update_status("Searching for places...")
        
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
            
            universe_response = requests.get(
                f"https://apis.roblox.com/universes/v1/places/{place_id}/universe",
                timeout=10
            )
            universe_response.raise_for_status()
            universe_data = universe_response.json()
            universe_id = universe_data.get("universeId")
            
            self.current_universe_id = universe_id
            
            game_response = requests.get(
                f"https://games.roblox.com/v1/games?universeIds={universe_id}",
                timeout=10
            )
            game_response.raise_for_status()
            game_data = game_response.json()
            game = game_data.get("data", [{}])[0]
            
            all_places = []
            cursor = None
            
            while True:
                url = f"https://develop.roblox.com/v1/universes/{universe_id}/places?limit=100"
                if cursor:
                    url += f"&cursor={cursor}"
                    
                places_response = requests.get(url, timeout=10)
                places_response.raise_for_status()
                places_data = places_response.json()
                
                all_places.extend(places_data.get("data", []))
                cursor = places_data.get("nextPageCursor")
                
                if not cursor:
                    break
                    
            self.after(0, lambda: self.display_results(game, universe_id, all_places))
            
        except requests.exceptions.RequestException:
            self.after(0, lambda: self.show_error("Network error: Check your connection"))
        except Exception as e:
            self.after(0, lambda: self.show_error(f"Error: {str(e)}"))
        finally:
            self.after(0, self.hide_loading)
            self.after(0, lambda: self.search_button.configure(state="normal", text="Search"))
            
    def display_results(self, game, universe_id, places):
        self.game_info_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        
        game_name = game.get("name", "Unknown Game")
        self.game_name_label.configure(text=game_name)
        
        creator = game.get("creator", {}).get("name", "Unknown")
        width = self.winfo_width()
        
        if width < 600:
            stats_text = f"{len(places)} places • by {creator}"
        else:
            stats_text = f"{len(places)} places • Universe {universe_id} • by {creator}"
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
                
        status_text = f"Found {len(places)} places"
        if not self.is_admin and any(not is_root for _, _, is_root in self.place_cards):
            status_text += " (Admin rights required for subplaces)"
            
        self.update_status(status_text)
        
    def show_loading(self):
        self.places_grid.grid_forget()
        self.loading_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=50)
        
    def hide_loading(self):
        self.loading_frame.grid_forget()
        self.places_grid.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
    def show_error(self, message):
        self.error_label.configure(text=f"⚠️ {message}")
        self.update_status("Error")
        
        self.after(5000, lambda: self.error_label.configure(text=""))
        
    def update_status(self, message):
        if not self.is_admin and "Ready" in message:
            message += " (Limited Mode)"
        self.status_label.configure(text=message)
        
    def open_place(self, place_id):
        webbrowser.open(f"https://www.roblox.com/games/{place_id}")
        self.update_status(f"Opening place {place_id} in browser...")
            
    def __del__(self):
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)

if __name__ == "__main__":
    if sys.platform == "win32" and not is_admin():
        run_as_admin()
    
    app = RobloxSubplaceExplorer()
    app.mainloop()