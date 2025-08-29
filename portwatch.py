# -*- coding: utf-8 -*-
# PortWatch GUI – Windows için Metro/Fluent hissiyatlı koyu tema port/bağlantı izleyici
# Özellikler:
# - TCP/UDP dinleyen portlar ve aktif bağlantılar (ESTABLISHED vb.) izleme
# - Sağ tık: program↔IP engelle / programı tamamen engelle / engel kaldır / tüm PortWatch engellerini kaldır
# - Snapshot (anlık yeniden tarayıp tabloları günceller)
# - CSV log
# - Hücre ve kolon kopyalama (sağ tıkla)
# - Otomatik yönetici yükseltmesi (UAC ile)
#
# Gereksinimler: pip install customtkinter psutil win10toast
# EXE (her zaman admin ister): pyinstaller -F -w --uac-admin portwatch_gui.py

import sys, os, platform, ctypes
from ctypes import wintypes
import threading
import time
import csv
import datetime as dt
import socket
import psutil
import queue
import subprocess
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

APP_NAME = "PortWatch GUI"
HTTP_PORTS = {80, 443, 8080, 8000, 8443, 8888, 3000, 5000}
IS_WINDOWS = platform.system().lower().startswith("win")

# -------------------- Yönetici yükseltmesi (self-elevate) --------------------
def _quote(arg: str) -> str:
    if not arg:
        return '""'
    if any(ch in arg for ch in ' \t"'):
        return '"' + arg.replace('"', r'\"') + '"'
    return arg

def ensure_admin():
    """Yönetici değilse UAC ile kendini admin olarak yeniden başlatır."""
    if not IS_WINDOWS:
        return
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if is_admin:
        return

    # Hedef/parametreler
    if getattr(sys, "frozen", False):
        target = sys.executable
        params = " ".join(_quote(a) for a in sys.argv[1:])
    else:
        target = sys.executable
        script = os.path.abspath(sys.argv[0])
        params = " ".join([_quote(script)] + [_quote(a) for a in sys.argv[1:]])

    ShellExecuteW = ctypes.windll.shell32.ShellExecuteW
    ShellExecuteW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                              wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int]
    ShellExecuteW.restype  = wintypes.HINSTANCE

    ret = ShellExecuteW(None, "runas", target, params, None, 1)
    if int(ret) <= 32:
        # Kullanıcı reddettiyse vs. çık
        sys.exit(1)
    sys.exit(0)

# -------------------- Toast bildirimi --------------------
HAS_TOAST = False
_toaster = None
if IS_WINDOWS:
    try:
        from win10toast import ToastNotifier
        _toaster = ToastNotifier()
        HAS_TOAST = True
    except Exception:
        HAS_TOAST = False

def notify(title: str, msg: str):
    if HAS_TOAST and IS_WINDOWS:
        try:
            _toaster.show_toast(title, msg, duration=4, threaded=True)
            return
        except Exception:
            pass
    print(f"[BİLDİRİM] {title}: {msg}")

# -------------------- Yardımcılar --------------------
def proc_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "?"

def proc_exe(pid: int):
    try:
        return psutil.Process(pid).exe()
    except Exception:
        return None

def iter_inet_connections():
    return psutil.net_connections(kind="inet")

def to_laddr(c):
    if not c.laddr:
        return ("", None)
    try:
        return (c.laddr.ip, c.laddr.port)
    except Exception:
        return (c.laddr[0], c.laddr[1])

def to_raddr(c):
    if not c.raddr:
        return ("", None)
    try:
        return (c.raddr.ip, c.raddr.port)
    except Exception:
        return (c.raddr[0], c.raddr[1])

# -------------------- Snapshot çıkarıcılar --------------------
class PortKeyListen(tuple):
    __slots__ = ()
    def __new__(cls, proto, ip, port, pid, name):
        return super().__new__(cls, (proto, ip, port, pid, name))

class ConnKeyActive(tuple):
    __slots__ = ()
    def __new__(cls, proto, lip, lport, rip, rport, pid, name, state):
        return super().__new__(cls, (proto, lip, lport, rip, rport, pid, name, state))

def filter_match_port(port, only_set, ignore_set):
    if port is None:
        return False
    if only_set and port not in only_set:
        return False
    if ignore_set and port in ignore_set:
        return False
    return True

def snapshot_listening(protocols=("TCP","UDP"), only_set=None, ignore_set=None):
    s = set()
    for c in iter_inet_connections():
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        if proto not in protocols:
            continue
        lip, lport = to_laddr(c)
        if lport is None:
            continue
        is_listen = (proto == "TCP" and c.status == psutil.CONN_LISTEN) or (proto == "UDP" and not c.raddr)
        if not is_listen:
            continue
        if (only_set or ignore_set) and not filter_match_port(lport, only_set, ignore_set):
            continue
        pid = c.pid or 0
        name = proc_name(pid)
        s.add(PortKeyListen(proto, lip, lport, pid, name))
    return s

def snapshot_active(protocols=("TCP","UDP"), only_set=None, ignore_set=None):
    s = set()
    for c in iter_inet_connections():
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        if proto not in protocols:
            continue
        lip, lport = to_laddr(c)
        rip, rport = to_raddr(c)
        if lport is None:
            continue
        is_active = (proto == "TCP" and c.status != psutil.CONN_LISTEN) or (proto == "UDP" and c.raddr)
        if not is_active:
            continue
        passes = True
        if (only_set or ignore_set):
            passes = filter_match_port(lport, only_set, ignore_set) or filter_match_port(rport, only_set, ignore_set)
        if not passes:
            continue
        pid = c.pid or 0
        name = proc_name(pid)
        state = c.status
        s.add(ConnKeyActive(proto, lip, lport, rip, rport or 0, pid, name, state))
    return s

# -------------------- Firewall yardımcıları --------------------
def _ps_quote(s: str) -> str:
    return '"' + s.replace('"', '`"') + '"'

def run_pwsh(command: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True, text=True
    )

def rule_id(program_path: str | None, remote_ip: str | None) -> str:
    base = f"{program_path or 'ANYPROG'}|{remote_ip or 'ANYIP'}"
    h = hashlib.sha1(base.encode("utf-8")).hexdigest()[:8]
    return f"PortWatch {h}"

def fw_block_program_ip(program_path: str | None, remote_ip: str | None):
    if not IS_WINDOWS:
        return False, "Sadece Windows desteklenir."
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return False, "Yönetici olarak çalıştırılmalı."
    except Exception:
        return False, "Yönetici kontrolü başarısız."
    name = rule_id(program_path, remote_ip)
    prog = f"-Program {_ps_quote(program_path)}" if program_path else ""
    raddr = f"-RemoteAddress {_ps_quote(remote_ip)}" if remote_ip else ""
    cmd = (
        f"try {{ "
        f"New-NetFirewallRule -DisplayName {_ps_quote(name+' Out')} -Direction Outbound {prog} {raddr} -Action Block -Profile Any -EdgeTraversalPolicy Block -ErrorAction Stop | Out-Null; "
        f"New-NetFirewallRule -DisplayName {_ps_quote(name+' In')}  -Direction Inbound  {prog} {raddr} -Action Block -Profile Any -EdgeTraversalPolicy Block -ErrorAction Stop | Out-Null; "
        f"$true }} catch {{ $_.Exception.Message; $false }}"
    )
    res = run_pwsh(cmd)
    ok = res.returncode == 0 and "True" in (res.stdout.strip() or res.stderr.strip() or "")
    if ok:
        return True, f"Engel eklendi: {name}"
    else:
        msg = res.stdout.strip() or res.stderr.strip() or "Bilinmeyen hata"
        return False, f"Hata: {msg}"

def fw_unblock_program_ip(program_path: str | None, remote_ip: str | None):
    if not IS_WINDOWS:
        return False, "Sadece Windows desteklenir."
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return False, "Yönetici olarak çalıştırılmalı."
    except Exception:
        return False, "Yönetici kontrolü başarısız."
    name = rule_id(program_path, remote_ip)
    cmd = (
        f"try {{ "
        f"$r = Get-NetFirewallRule -DisplayName {_ps_quote(name+'*')} -ErrorAction SilentlyContinue; "
        f"if ($r) {{ $r | Remove-NetFirewallRule -Confirm:$false; $true }} else {{ $true }} "
        f"}} catch {{ $_.Exception.Message; $false }}"
    )
    res = run_pwsh(cmd)
    ok = res.returncode == 0 and "True" in (res.stdout.strip() or res.stderr.strip() or "")
    if ok:
        return True, f"Engel kaldırıldı: {name}"
    else:
        msg = res.stdout.strip() or res.stderr.strip() or "Bilinmeyen hata"
        return False, f"Hata: {msg}"

def fw_unblock_all_portwatch():
    if not IS_WINDOWS:
        return False, "Sadece Windows desteklenir."
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return False, "Yönetici olarak çalıştırılmalı."
    except Exception:
        return False, "Yönetici kontrolü başarısız."
    cmd = (
        f"try {{ "
        f"$r = Get-NetFirewallRule -DisplayName {_ps_quote('PortWatch*')} -ErrorAction SilentlyContinue; "
        f"if ($r) {{ $r | Remove-NetFirewallRule -Confirm:$false; $true }} else {{ $true }} "
        f"}} catch {{ $_.Exception.Message; $false }}"
    )
    res = run_pwsh(cmd)
    ok = res.returncode == 0 and "True" in (res.stdout.strip() or res.stderr.strip() or "")
    if ok:
        return True, "Tüm PortWatch engelleri kaldırıldı."
    else:
        msg = res.stdout.strip() or res.stderr.strip() or "Bilinmeyen hata"
        return False, f"Hata: {msg}"

# -------------------- Watcher Thread --------------------
class WatcherThread(threading.Thread):
    def __init__(self, cfg_getter, event_queue: queue.Queue):
        super().__init__(daemon=True)
        self.cfg_getter = cfg_getter
        self.event_queue = event_queue
        self._stop_evt = threading.Event()
        self.prev_listen = set()
        self.prev_active = set()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        cfg = self.cfg_getter()
        if cfg["watch_listen"]:
            self.prev_listen = snapshot_listening(cfg["protocols"], cfg["only_set"], cfg["ignore_set"])
        if cfg["watch_active"]:
            self.prev_active = snapshot_active(cfg["protocols"], cfg["only_set"], cfg["ignore_set"])

        while not self._stop_evt.is_set():
            t0 = time.time()
            cfg = self.cfg_getter()

            if cfg["watch_listen"]:
                cur = snapshot_listening(cfg["protocols"], cfg["only_set"], cfg["ignore_set"])
                opened = cur - self.prev_listen
                closed = self.prev_listen - cur
                if opened or closed:
                    self.event_queue.put(("listen_changes", opened, closed))
                self.prev_listen = cur

            if cfg["watch_active"]:
                cur = snapshot_active(cfg["protocols"], cfg["only_set"], cfg["ignore_set"])
                opened = cur - self.prev_active
                closed = self.prev_active - cur
                if opened or closed:
                    self.event_queue.put(("active_changes", opened, closed))
                self.prev_active = cur

            elapsed = time.time() - t0
            sleep_for = max(0.1, cfg["interval"] - elapsed)
            self._stop_evt.wait(timeout=sleep_for)

# -------------------- GUI --------------------
class PortWatchGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.title(APP_NAME)
        self.geometry("1150x740")
        try:
            self.iconbitmap(default="")
        except Exception:
            pass

        self.event_queue = queue.Queue()
        self.watcher = None
        self.log_path = None

        # ---------- Sol Panel ----------
        left = ctk.CTkFrame(self, corner_radius=16)
        left.pack(side="left", fill="y", padx=(12, 6), pady=12)
        title = ctk.CTkLabel(left, text="PortWatch", font=("Segoe UI Semibold", 20))
        title.pack(padx=16, pady=(16, 6), anchor="w")

        self.chk_listen = ctk.CTkCheckBox(left, text="Dinleyen Portları İzle (Server)")
        self.chk_listen.select()
        self.chk_listen.pack(padx=16, pady=6, anchor="w")

        self.chk_active = ctk.CTkCheckBox(left, text="Aktif Bağlantıları İzle (ESTABLISHED)")
        self.chk_active.pack(padx=16, pady=6, anchor="w")

        ctk.CTkLabel(left, text="Protokoller", font=("Segoe UI", 13)).pack(padx=16, pady=(12, 4), anchor="w")
        proto_frame = ctk.CTkFrame(left)
        proto_frame.pack(padx=12, pady=4, fill="x")
        self.var_tcp = tk.BooleanVar(value=True)
        self.var_udp = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(proto_frame, text="TCP", variable=self.var_tcp, width=120).pack(side="left", padx=6, pady=6)
        ctk.CTkCheckBox(proto_frame, text="UDP", variable=self.var_udp, width=120).pack(side="left", padx=6, pady=6)

        ctk.CTkLabel(left, text="Hızlı Filtreler", font=("Segoe UI", 13)).pack(padx=16, pady=(12, 4), anchor="w")
        self.chk_http = ctk.CTkCheckBox(left, text="HTTP/HTTPS (80, 443, 8080, 8000, 8443, 8888, 3000, 5000)")
        self.chk_http.pack(padx=16, pady=4, anchor="w")

        ctk.CTkLabel(left, text="Özel Portlar (virgüllü)", font=("Segoe UI", 13)).pack(padx=16, pady=(12, 4), anchor="w")
        self.entry_only = ctk.CTkEntry(left, placeholder_text="örn: 22,80,443")
        self.entry_only.pack(padx=16, pady=4, fill="x")

        ctk.CTkLabel(left, text="Yoksay (virgüllü)", font=("Segoe UI", 13)).pack(padx=16, pady=(12, 4), anchor="w")
        self.entry_ignore = ctk.CTkEntry(left, placeholder_text="örn: 5353,1900")
        self.entry_ignore.pack(padx=16, pady=4, fill="x")

        ctk.CTkLabel(left, text="Tarama Aralığı (saniye)", font=("Segoe UI", 13)).pack(padx=16, pady=(12, 4), anchor="w")
        self.slider_interval = ctk.CTkSlider(left, from_=0.5, to=10, number_of_steps=95)
        self.slider_interval.set(2.0)
        self.slider_interval.pack(padx=16, pady=(4, 2), fill="x")
        self.lbl_interval = ctk.CTkLabel(left, text="2.0 s")
        self.lbl_interval.pack(padx=16, pady=(0, 8), anchor="w")
        self.slider_interval.bind("<B1-Motion>", lambda e: self.lbl_interval.configure(text=f"{self.slider_interval.get():.1f} s"))
        self.slider_interval.bind("<ButtonRelease-1>", lambda e: self.lbl_interval.configure(text=f"{self.slider_interval.get():.1f} s"))

        self.chk_toast = ctk.CTkCheckBox(left, text="Windows Bildirimleri")
        if HAS_TOAST:
            self.chk_toast.select()
        self.chk_toast.pack(padx=16, pady=6, anchor="w")

        btn_frame = ctk.CTkFrame(left)
        btn_frame.pack(padx=12, pady=12, fill="x")
        self.btn_start = ctk.CTkButton(btn_frame, text="Başlat", command=self.start_watch)
        self.btn_start.pack(side="left", expand=True, fill="x", padx=(0, 6))
        self.btn_stop = ctk.CTkButton(btn_frame, text="Durdur", command=self.stop_watch, state="disabled")
        self.btn_stop.pack(side="left", expand=True, fill="x", padx=(6, 0))

        export_frame = ctk.CTkFrame(left)
        export_frame.pack(padx=12, pady=8, fill="x")
        ctk.CTkButton(export_frame, text="CSV Log Kaydet...", command=self.choose_log).pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(export_frame, text="Snapshot Al", command=self.snapshot_now).pack(side="left", expand=True, fill="x", padx=(6, 0))

        self.lbl_status = ctk.CTkLabel(left, text="Hazır.", text_color=("gray80","gray70"))
        self.lbl_status.pack(padx=16, pady=(6, 12), anchor="w")

        # ---------- Sağ Panel ----------
        right = ctk.CTkFrame(self, corner_radius=16)
        right.pack(side="left", fill="both", expand=True, padx=(6, 12), pady=12)

        self.tabs = ctk.CTkTabview(right, segmented_button_selected_color="#2563eb", segmented_button_fg_color="#0b1220")
        self.tabs.pack(fill="both", expand=True, padx=12, pady=12)

        tab_monitor = self.tabs.add("Canlı Olaylar")
        tab_listen  = self.tabs.add("Dinleyen Portlar")
        tab_active  = self.tabs.add("Aktif Bağlantılar")

        self.txt_events = ctk.CTkTextbox(tab_monitor, wrap="none")
        self.txt_events.pack(fill="both", expand=True, padx=8, pady=8)

        self.tree_listen = self._make_tree(tab_listen, ["Proto", "IP", "Port", "PID", "Process"])
        self.tree_active = self._make_tree(tab_active, ["Proto", "L-Addr", "L-Port", "R-Addr", "R-Port", "State", "PID", "Process"])

        # Sağ tık menüleri: Dinleyen ve Aktif
        self._bind_copy_menu(self.tree_listen, table="listen")
        self._bind_active_menu()  # engelle + kopyala

        # UI loop
        self.after(300, self._drain_events)
        self.refresh_tables()

    # ------------- UI yardımcıları -------------
    def _make_tree(self, parent, cols):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background="#0b1220", fieldbackground="#0b1220",
                        foreground="#e5e7eb", rowheight=26, borderwidth=0)
        style.map("Treeview", background=[("selected", "#1f2937")])
        style.configure("Treeview.Heading", background="#111827", foreground="#93c5fd", relief="flat")

        frame = ctk.CTkFrame(parent)
        frame.pack(fill="both", expand=True, padx=8, pady=8)
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            tree.heading(c, text=c)
            width = 100
            if c in ("Process", "L-Addr", "R-Addr"): width = 220
            if c in ("PID", "Port", "L-Port", "R-Port"): width = 80
            tree.column(c, width=width, anchor="w")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        return tree

    def _append_event(self, text):
        timestamp = dt.datetime.now().strftime("%H:%M:%S")
        self.txt_events.insert("end", f"[{timestamp}] {text}\n")
        self.txt_events.see("end")

    # ------------- Copy menüleri (dinleyen tablosu) -------------
    def _bind_copy_menu(self, tree: ttk.Treeview, table: str):
        # table paramı sadece debug için; işlev aynı
        def on_right_click(ev):
            iid = tree.identify_row(ev.y)
            col_id = tree.identify_column(ev.x)  # "#1", "#2"...
            if not iid or not col_id:
                return
            tree.selection_set(iid)
            idx = int(col_id.replace("#", "")) - 1
            cols = tree["columns"]
            if idx < 0 or idx >= len(cols):
                return
            col_name = cols[idx]
            values = tree.item(iid, "values")
            cell_value = values[idx] if idx < len(values) else ""

            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label=f"Hücreyi kopyala ({col_name})", command=lambda: self._copy_to_clipboard(cell_value))
            menu.add_command(label=f"Bu kolonu kopyala (tüm satırlar) [{col_name}]",
                             command=lambda: self._copy_column_all(tree, idx, header=False))
            menu.add_command(label=f"Bu kolonu CSV kopyala [{col_name}]",
                             command=lambda: self._copy_column_all(tree, idx, header=True))
            menu.tk_popup(ev.x_root, ev.y_root)
        tree.bind("<Button-3>", on_right_click)

    def _copy_to_clipboard(self, text: str):
        try:
            self.clipboard_clear()
            self.clipboard_append(text if text is not None else "")
            self._append_event("Kopyalandı.")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Kopyalanamadı:\n{e}")

    def _copy_column_all(self, tree: ttk.Treeview, idx: int, header: bool):
        cols = list(tree["columns"])
        col_name = cols[idx]
        lines = []
        if header:
            lines.append(col_name)
        for iid in tree.get_children():
            vals = tree.item(iid, "values")
            lines.append(str(vals[idx]) if idx < len(vals) else "")
        text = "\n".join(lines)
        self._copy_to_clipboard(text)

    # ------------- Aktif menü (engelle + kopyala) -------------
    def _bind_active_menu(self):
        def on_right_click(ev):
            iid = self.tree_active.identify_row(ev.y)
            col_id = self.tree_active.identify_column(ev.x)
            if not iid or not col_id:
                return
            self.tree_active.selection_set(iid)
            idx = int(col_id.replace("#", "")) - 1
            cols = self.tree_active["columns"]
            if idx < 0 or idx >= len(cols):
                return
            col_name = cols[idx]
            values = self.tree_active.item(iid, "values")
            # order: Proto, L-Addr, L-Port, R-Addr, R-Port, State, PID, Process
            try:
                proto, laddr, lport, raddr, rport, state, pid, proc = values
            except Exception:
                return
            try:
                lport_i = int(lport)
            except Exception:
                lport_i = 0
            try:
                rport_i = int(rport)
            except Exception:
                rport_i = 0
            try:
                pid_i = int(pid)
            except Exception:
                pid_i = 0

            exe = proc_exe(pid_i)
            cell_value = values[idx] if idx < len(values) else ""

            menu = tk.Menu(self, tearoff=0)
            # Kopyalama
            menu.add_command(label=f"Hücreyi kopyala ({col_name})", command=lambda: self._copy_to_clipboard(cell_value))
            menu.add_command(label=f"Bu kolonu kopyala (tüm satırlar) [{col_name}]",
                             command=lambda: self._copy_column_all(self.tree_active, idx, header=False))
            menu.add_command(label=f"Bu kolonu CSV kopyala [{col_name}]",
                             command=lambda: self._copy_column_all(self.tree_active, idx, header=True))
            menu.add_separator()
            # Engelleme
            menu.add_command(
                label="Engelle (program ↔ bu IP)",
                command=lambda: self._block_prog_ip(exe, raddr)
            )
            menu.add_command(
                label="Programı tamamen engelle (tüm IP’ler)",
                command=lambda: self._block_prog_ip(exe, None, confirm_all=True)
            )
            menu.add_separator()
            menu.add_command(
                label="Engeli kaldır (bu IP)",
                command=lambda: self._unblock_prog_ip(exe, raddr)
            )
            menu.add_command(
                label="Tüm PortWatch engellerini kaldır",
                command=self._unblock_all
            )
            menu.tk_popup(ev.x_root, ev.y_root)
        self.tree_active.bind("<Button-3>", on_right_click)

    # ---- Engelleme işlemleri ----
    def _block_prog_ip(self, exe_path, remote_ip, confirm_all=False):
        if confirm_all:
            if exe_path is None:
                messagebox.showerror(APP_NAME, "Program yoluna erişilemedi; program bazlı engel eklenemiyor.")
                return
            if not messagebox.askyesno(APP_NAME, f"{exe_path}\n\nBu programın tüm IP’lere giden/gelen trafiğini engellemek istiyor musunuz?"):
                return
        else:
            if remote_ip is None:
                if not messagebox.askyesno(APP_NAME, "Uzak IP boş görünüyor. Programı tüm IP’lere karşı engellemek ister misiniz?"):
                    return
        ok, msg = fw_block_program_ip(exe_path, remote_ip)
        self._append_event(("✅ " if ok else "❌ ") + msg)
        if ok:
            notify("Engel eklendi", msg)

    def _unblock_prog_ip(self, exe_path, remote_ip):
        ok, msg = fw_unblock_program_ip(exe_path, remote_ip)
        self._append_event(("✅ " if ok else "❌ ") + msg)
        if ok:
            notify("Engel kaldırıldı", msg)

    def _unblock_all(self):
        if not messagebox.askyesno(APP_NAME, "Tüm PortWatch engelleri kaldırılacak. Emin misiniz?"):
            return
        ok, msg = fw_unblock_all_portwatch()
        self._append_event(("✅ " if ok else "❌ ") + msg)
        if ok:
            notify("Engeller kaldırıldı", msg)

    # ------------- Config okuma -------------
    def _get_cfg(self):
        protocols = []
        if self.var_tcp.get():
            protocols.append("TCP")
        if self.var_udp.get():
            protocols.append("UDP")
        if not protocols:
            protocols = ["TCP","UDP"]

        only_set = set()
        if self.chk_http.get():
            only_set |= HTTP_PORTS

        only_txt = self.entry_only.get().strip()
        if only_txt:
            for p in only_txt.split(","):
                p = p.strip()
                if p.isdigit():
                    only_set.add(int(p))

        ignore_set = set()
        ign_txt = self.entry_ignore.get().strip()
        if ign_txt:
            for p in ign_txt.split(","):
                p = p.strip()
                if p.isdigit():
                    ignore_set.add(int(p))

        if not only_set:
            only_set = None
        if not ignore_set:
            ignore_set = None

        return dict(
            watch_listen=bool(self.chk_listen.get()),
            watch_active=bool(self.chk_active.get()),
            protocols=tuple(protocols),
            only_set=only_set,
            ignore_set=ignore_set,
            interval=float(self.slider_interval.get()),
            toast=bool(self.chk_toast.get())
        )

    # ------------- Watcher kontrol -------------
    def start_watch(self):
        if self.watcher and self.watcher.is_alive():
            return
        self._append_event("İzleme başlatılıyor…")
        self.lbl_status.configure(text="Çalışıyor…")
        self.watcher = WatcherThread(self._get_cfg, self.event_queue)
        self.watcher.start()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")

    def stop_watch(self):
        if self.watcher:
            self.watcher.stop()
            self.watcher.join(timeout=2.0)
            self.watcher = None
        self.lbl_status.configure(text="Durduruldu.")
        self._append_event("İzleme durduruldu.")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    # ------------- Olay kuyruğu -------------
    def _drain_events(self):
        try:
            while True:
                kind, opened, closed = self.event_queue.get_nowait()
                if kind == "listen_changes":
                    for pk in sorted(opened, key=lambda x: (x[0], x[2], x[4])):
                        msg = f"PORT AÇILDI -> {pk[0]} {pk[1]}:{pk[2]}  pid={pk[3]} {pk[4]}"
                        self._append_event(msg)
                        if self._get_cfg()["toast"]:
                            notify("Port Açıldı", f"{pk[0]} {pk[1]}:{pk[2]} (pid {pk[3]}, {pk[4]})")
                        self._log_csv("OPEN_LISTEN", pk)
                    for pk in sorted(closed, key=lambda x: (x[0], x[2], x[4])):
                        msg = f"PORT KAPANDI -> {pk[0]} {pk[1]}:{pk[2]}  pid={pk[3]} {pk[4]}"
                        self._append_event(msg)
                        if self._get_cfg()["toast"]:
                            notify("Port Kapandı", f"{pk[0]} {pk[1]}:{pk[2]} (pid {pk[3]}, {pk[4]})")
                        self._log_csv("CLOSE_LISTEN", pk)
                    self.refresh_listen_table()
                elif kind == "active_changes":
                    for ck in sorted(opened, key=lambda x: (x[0], x[2], x[6])):
                        msg = (f"BAĞLANTI OLUŞTU -> {ck[0]} {ck[1]}:{ck[2]} -> {ck[3]}:{ck[4]} "
                               f"[{ck[7]}] pid={ck[5]} {ck[6]}")
                        self._append_event(msg)
                        if self._get_cfg()["toast"]:
                            notify("Bağlantı Oluştu",
                                   f"{ck[0]} {ck[1]}:{ck[2]} -> {ck[3]}:{ck[4]} ({ck[7]})")
                        self._log_csv("OPEN_ACTIVE", ck)
                    for ck in sorted(closed, key=lambda x: (x[0], x[2], x[6])):
                        msg = (f"BAĞLANTI KAPANDI -> {ck[0]} {ck[1]}:{ck[2]} -> {ck[3]}:{ck[4]} "
                               f"[{ck[7]}] pid={ck[5]} {ck[6]}")
                        self._append_event(msg)
                        if self._get_cfg()["toast"]:
                            notify("Bağlantı Kapandı",
                                   f"{ck[0]} {ck[1]}:{ck[2]} -> {ck[3]}:{ck[4]} ({ck[7]})")
                        self._log_csv("CLOSE_ACTIVE", ck)
                    self.refresh_active_table()
                self.event_queue.task_done()
        except queue.Empty:
            pass
        self.after(300, self._drain_events)

    # ------------- Tabloları yenile -------------
    def refresh_tables(self):
        self.refresh_listen_table()
        self.refresh_active_table()

    def refresh_listen_table(self):
        for i in self.tree_listen.get_children():
            self.tree_listen.delete(i)
        cfg = self._get_cfg()
        data = snapshot_listening(cfg["protocols"], cfg["only_set"], cfg["ignore_set"])
        for pk in sorted(data, key=lambda x: (x[0], x[2], x[4])):
            self.tree_listen.insert("", "end", values=(pk[0], pk[1], pk[2], pk[3], pk[4]))

    def refresh_active_table(self):
        for i in self.tree_active.get_children():
            self.tree_active.delete(i)
        cfg = self._get_cfg()
        data = snapshot_active(cfg["protocols"], cfg["only_set"], cfg["ignore_set"])
        for ck in sorted(data, key=lambda x: (x[0], x[2], x[6])):
            laddr = ck[1]; lport = ck[2]; raddr = ck[3]; rport = ck[4]; state = ck[7]
            self.tree_active.insert("", "end", values=(ck[0], laddr, lport, raddr, rport, state, ck[5], ck[6]))

    # ------------- Snapshot butonu -------------
    def snapshot_now(self):
        self._append_event("Manuel snapshot alındı.")
        self.refresh_tables()

    # ------------- Loglama -------------
    def choose_log(self):
        fp = filedialog.asksaveasfilename(
            title="CSV log dosyası",
            defaultextension=".csv",
            filetypes=[("CSV Files","*.csv"), ("All Files","*.*")]
        )
        if not fp:
            return
        self.log_path = fp
        try:
            with open(self.log_path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["timestamp", "event", "proto", "l-ip", "l-port", "r-ip", "r-port", "pid", "process", "state"])
            self._append_event(f"Log dosyası ayarlandı: {self.log_path}")
            self.lbl_status.configure(text=f"Log: {os.path.basename(self.log_path)}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Log dosyası açılamadı:\n{e}")

    def _log_csv(self, event, row):
        if not self.log_path:
            return
        try:
            ts = dt.datetime.now().isoformat(timespec="seconds")
            if event.endswith("LISTEN"):
                proto, lip, lport, pid, name = row
                with open(self.log_path, "a", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow([ts, event, proto, lip, lport, "", "", pid, name, "LISTEN"])
            else:
                proto, lip, lport, rip, rport, pid, name, state = row
                with open(self.log_path, "a", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow([ts, event, proto, lip, lport, rip, rport, pid, name, state])
        except Exception:
            pass

# -------------------- Çalıştır --------------------
if __name__ == "__main__":
    ensure_admin()  # Yönetici değilse UAC ile yeniden başlatır
    app = PortWatchGUI()
    app.mainloop()
