"""
ui.py - Tkinter UI for Secure File Locker (updated)

Changes in this file:
- Added a Vault 3 Settings view that allows changing Vault 1 and Vault 2 settings (in the same style as their Setup screens).
  - Vault 1 Settings: select format preset and save.
  - Vault 2 Settings: edit base format, choose city (dropdown), pick additional factors (>=1 required), show preview and require user review before save.
- When Vault 1 settings are changed and saved, Vault 3's config is updated to follow Vault 1 format automatically.
- vault_settings(level) now opens the combined Vault 3 Settings view when level == 3.
- All other UI behavior remains the same.

Run: python ui.py
"""
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import backend
import traceback

class SecureFileLockerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Locker")
        self.root.geometry("1000x650")
        self.vault_unlocked = {1: False, 2: False, 3: False}
        self.build_header()
        self.content = ttk.Frame(self.root)
        self.content.pack(fill='both', expand=True, padx=12, pady=8)
        self.current_view = None
        self.show_main_view()

    def build_header(self):
        header = ttk.Frame(self.root)
        header.pack(fill='x', padx=12, pady=6)
        ttk.Label(header, text="Secure File Locker", font=("Segoe UI", 16, "bold")).pack(side='left')
        ttk.Button(header, text="Refresh", command=self.master_refresh).pack(side='left', padx=6)
        ttk.Button(header, text="Audit Log", command=self.open_audit_log).pack(side='right', padx=6)

    def master_refresh(self):
        # re-render manager if open; silent otherwise
        if self.current_view and self.current_view.startswith("vault_"):
            lv = int(self.current_view.split("_")[1])
            self.manage_vault(lv)

    def open_audit_log(self):
        try:
            if sys.platform.startswith("win"):
                os.startfile(backend.AUDIT_LOG)
            else:
                import subprocess
                subprocess.Popen(["xdg-open", backend.AUDIT_LOG])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open audit log: {e}")

    def show_main_view(self):
        for w in self.content.winfo_children(): w.destroy()
        self.current_view = "main"
        frame = ttk.Frame(self.content); frame.pack(fill='both', expand=True)
        ttk.Label(frame, text="Vaults", font=("Segoe UI", 14, "bold")).pack(pady=8)
        cards = ttk.Frame(frame); cards.pack(fill='both', expand=True); cards.columnconfigure((0,1,2), weight=1)
        for i, lv in enumerate((1,2,3)):
            card = ttk.Labelframe(cards, text=f"Vault {lv}", padding=12); card.grid(row=0, column=i, sticky='nsew', padx=6, pady=12)
            cfg = backend.get_vault_config(lv)
            status = "Configured" if cfg else "Not Configured"
            ttk.Label(card, text=status).pack(pady=6)
            if cfg:
                ttk.Button(card, text="Access Vault", command=lambda l=lv: self.access_vault(l)).pack(pady=6)
            else:
                ttk.Button(card, text="Setup Vault", command=lambda l=lv: self.setup_vault(l)).pack(pady=6)

    def setup_vault(self, level):
        if level == 1:
            self.setup_vault1()
        elif level == 2:
            if not backend.get_vault_config(1):
                messagebox.showwarning("Setup required","Please configure Vault 1 first."); return
            self.setup_vault2()
        else:
            if not backend.get_vault_config(2):
                messagebox.showwarning("Setup required","Please configure Vault 2 first."); return
            self.setup_vault3()

    def access_vault(self, level):
        for w in self.content.winfo_children(): w.destroy()
        self.current_view = f"access_{level}"
        frame = ttk.Frame(self.content); frame.pack(fill='both', expand=True, padx=12, pady=12)
        ttk.Label(frame, text=f"Vault {level} - Enter password", font=("Segoe UI", 13, "bold")).pack(pady=8)
        if level == 3:
            # Defensive check: wrap verify call in try/except
            try:
                present = backend.verify_physical_key(3)
            except Exception as e:
                backend.log_event("ERROR", "UI_VERIFY_PHYSICAL_KEY", str(e))
                present = False
            status_label = ttk.Label(frame, text=("Key present" if present else "Key NOT present"), foreground=("green" if present else "red"))
            status_label.pack(pady=4)
            def recheck():
                try:
                    pres = backend.verify_physical_key(3)
                except Exception as e:
                    backend.log_event("ERROR", "UI_RECHECK_PHYSICAL_KEY", str(e))
                    pres = False
                status_label.config(text=("Key present" if pres else "Key NOT present"), foreground=("green" if pres else "red"))
                if pres:
                    pw_entry.config(state='normal')
            ttk.Button(frame, text="Refresh Key", command=recheck).pack(pady=4)
        pw_var = tk.StringVar()
        pw_entry = ttk.Entry(frame, textvariable=pw_var, show="*")
        if level == 3 and not backend.verify_physical_key(3):
            pw_entry.config(state='disabled')
        pw_entry.pack(pady=6)
        btnf = ttk.Frame(frame); btnf.pack(pady=8)
        def try_auth():
            ok, msg = backend.authenticate_vault(level, pw_var.get())
            if ok:
                self.vault_unlocked[level] = True
                self.manage_vault(level)
            else:
                messagebox.showerror("Auth failed", msg)
        ttk.Button(btnf, text="Unlock", command=try_auth).pack(side='left', padx=6)
        ttk.Button(btnf, text="Cancel", command=self.show_main_view).pack(side='left', padx=6)

    # -- Setup views --
    def setup_vault1(self):
        for w in self.content.winfo_children(): w.destroy()
        self.current_view = "setup_1"
        frame = ttk.Frame(self.content); frame.pack(fill='both', expand=True, padx=12, pady=12)
        ttk.Label(frame, text="Vault 1 - Setup", font=("Segoe UI", 13, "bold")).pack(pady=8)
        presets = ["HDMY","HMDY","DHMY","MDHY"]
        fmt_var = tk.StringVar(value=(backend.get_vault_config(1) or {}).get('format','HDMY'))
        ttk.Label(frame, text="Choose format:").pack(anchor='w', padx=6)
        cb = ttk.Combobox(frame, values=presets, textvariable=fmt_var, state='readonly'); cb.pack(anchor='w', padx=6, pady=6)
        def save1():
            fmt = fmt_var.get().strip().upper()
            if len(fmt)!=4 or not all(c in 'HDMY' for c in fmt):
                messagebox.showerror("Invalid", "Format must be 4 chars composed of H,D,M,Y"); return
            cfg = {'level':1,'format':fmt,'timezone':'Local System','additional_factors':[],'description':'Level1','auto_lock_minutes':0}
            if backend.save_vault_config(1, cfg):
                # ensure Vault3 follows Vault1: update Vault3 config format too (if Vault3 configured)
                v3 = backend.get_vault_config(3)
                if v3:
                    v3_out = {'level':3, 'format': fmt, 'timezone': v3.get('timezone','Local System'), 'additional_factors': [], 'description': v3.get('description','Level3'), 'auto_lock_minutes': v3.get('auto_lock_minutes',0)}
                    backend.save_vault_config(3, v3_out)
                messagebox.showinfo("Saved", "Vault 1 saved")
                self.master_refresh()
                self.show_main_view()
            else:
                messagebox.showerror("Error", "Save failed")
        btnf = ttk.Frame(frame); btnf.pack(pady=8)
        ttk.Button(btnf, text="Save", command=save1).pack(side='left', padx=6)
        ttk.Button(btnf, text="Back", command=self.show_main_view).pack(side='left', padx=6)

    def setup_vault2(self):
        for w in self.content.winfo_children(): w.destroy()
        self.current_view = "setup_2"
        frame = ttk.Frame(self.content); frame.pack(fill='both', expand=True, padx=12, pady=12)
        ttk.Label(frame, text="Vault 2 - Setup", font=("Segoe UI", 13, "bold")).pack(pady=8)
        lvl1 = backend.get_vault_config(1)
        default_fmt = (lvl1['format'] if lvl1 else 'HDMY')
        fmt_var = tk.StringVar(value=default_fmt)
        ttk.Label(frame, text="Base format (editable):").pack(anchor='w', padx=6)
        ttk.Entry(frame, textvariable=fmt_var, width=12).pack(anchor='w', padx=6, pady=4)
        city_values = [f"{c['display_name']} ({c['timezone']})" for c in backend.CITIES]
        city_var = tk.StringVar()
        ttk.Label(frame, text="Select city/timezone:").pack(anchor='w', padx=6)
        city_cb = ttk.Combobox(frame, values=city_values, textvariable=city_var, state='readonly', width=60)
        city_cb.pack(fill='x', padx=6, pady=4)
        battery_var = tk.BooleanVar(); cpu_var = tk.BooleanVar(); ram_var = tk.BooleanVar()
        ttk.Label(frame, text="Select at least one additional factor:").pack(anchor='w', padx=6)
        ttk.Checkbutton(frame, text="Battery %", variable=battery_var).pack(anchor='w', padx=12)
        ttk.Checkbutton(frame, text="CPU Usage", variable=cpu_var).pack(anchor='w', padx=12)
        ttk.Checkbutton(frame, text="RAM Size", variable=ram_var).pack(anchor='w', padx=12)
        preview_label = ttk.Label(frame, text="Password preview: -", font=("Consolas", 12))
        preview_label.pack(pady=6)
        reviewed_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="I have reviewed the preview", variable=reviewed_var).pack(anchor='w', padx=6)
        def show_preview():
            sel = city_var.get()
            if not sel:
                messagebox.showerror("City", "Select a city"); return
            tz = sel.split('(')[-1].strip(')')
            add = []
            if battery_var.get(): add.append('battery')
            if cpu_var.get(): add.append('cpu')
            if ram_var.get(): add.append('ram_size')
            cfg_example = {'format':fmt_var.get().strip().upper(), 'timezone':tz, 'additional_factors':add}
            try:
                preview = backend.generate_level2_password(cfg_example)
            except Exception as e:
                backend.log_event("ERROR","UI_PREVIEW", str(e))
                preview = "ERROR"
            preview_label.config(text=f"Password preview: {preview}")
        def save2():
            if not city_var.get(): messagebox.showerror("City","Select a city"); return
            add=[]
            if battery_var.get(): add.append('battery')
            if cpu_var.get(): add.append('cpu')
            if ram_var.get(): add.append('ram_size')
            if not add: messagebox.showerror("Required","Select at least one additional factor"); return
            if not reviewed_var.get(): messagebox.showerror("Preview","Please review preview before saving"); return
            tz = city_var.get().split('(')[-1].strip(')')
            cfg = {'level':2, 'format': fmt_var.get().strip().upper(), 'timezone': tz, 'additional_factors': add, 'description': 'Level2', 'auto_lock_minutes':0}
            if backend.save_vault_config(2, cfg):
                messagebox.showinfo("Saved", "Vault 2 saved"); self.master_refresh(); self.show_main_view()
            else:
                messagebox.showerror("Error", "Save failed")
        btnf = ttk.Frame(frame); btnf.pack(pady=8)
        ttk.Button(btnf, text="Show Preview", command=show_preview).pack(side='left', padx=6)
        ttk.Button(btnf, text="Save", command=save2).pack(side='left', padx=6)
        ttk.Button(btnf, text="Back", command=self.show_main_view).pack(side='left', padx=6)

    def setup_vault3(self):
        for w in self.content.winfo_children(): w.destroy()
        self.current_view = "setup_3"
        frame = ttk.Frame(self.content); frame.pack(fill='both', expand=True, padx=12, pady=12)
        ttk.Label(frame, text="Vault 3 - Physical Key Setup", font=("Segoe UI", 13, "bold")).pack(pady=8)
        method = tk.StringVar(value='usb')
        ttk.Radiobutton(frame, text="USB Drive", variable=method, value='usb').pack(anchor='w', padx=6)
        ttk.Radiobutton(frame, text="Bluetooth Device", variable=method, value='bluetooth').pack(anchor='w', padx=6)
        drives_list = tk.Listbox(frame, height=6); drives_list.pack(fill='x', padx=6, pady=4)
        def refresh_drives():
            drives_list.delete(0,'end'); drives = backend.get_removable_drives()
            if not drives: drives_list.insert('end', "No removable drives detected"); drives_list.drives=[]
            else:
                for d in drives: drives_list.insert('end', f"{d['mountpoint']} ({d.get('fstype','')})")
                drives_list.drives = drives
        refresh_drives()
        ttk.Button(frame, text="Refresh Drives", command=refresh_drives).pack(pady=4)
        bt_list = tk.Listbox(frame, height=4); bt_list.pack(fill='x', padx=6, pady=4)
        def scan_bt():
            bt_list.delete(0,'end'); res = backend.scan_bluetooth_connected(timeout=5)
            if not res: bt_list.insert('end', "No connected devices"); bt_list.devices=[]
            else:
                for a,n in res: bt_list.insert('end', f"{a} - {n}")
                bt_list.devices = res
        ttk.Button(frame, text="Scan Bluetooth", command=scan_bt).pack(pady=4)

        def test_key():
            try:
                if method.get()=='usb':
                    if not hasattr(drives_list,'drives') or not drives_list.drives:
                        messagebox.showerror("USB","Select drive"); return
                    sel = drives_list.curselection()
                    if not sel: messagebox.showerror("USB","Select drive"); return
                    drive = drives_list.drives[sel[0]]['mountpoint']
                    kd, err = backend.create_usb_key_on_drive(drive)
                    if not kd:
                        messagebox.showerror("Test Failed", err); return
                    ok = backend.verify_usb_key_direct(kd)
                    try:
                        os.remove(os.path.join(kd['drive_mountpoint'], kd['key_file']))
                    except Exception:
                        pass
                    if ok: messagebox.showinfo("Test Passed","USB key created and verified")
                    else: messagebox.showerror("Test Failed","Verification failed")
                else:
                    messagebox.showinfo("Info","Select a discovered BT device and Save; verification occurs at access time")
            except Exception as e:
                backend.log_event("ERROR", "UI_TEST_KEY", str(e))
                messagebox.showerror("Error", f"Test failed: {e}")

        ttk.Button(frame, text="Test Physical Key", command=test_key).pack(pady=6)

        def save3():
            try:
                if method.get()=='usb':
                    if not hasattr(drives_list,'drives') or not drives_list.drives:
                        messagebox.showerror("USB","Select drive"); return
                    sel = drives_list.curselection()
                    if not sel: messagebox.showerror("USB","Select drive"); return
                    drive = drives_list.drives[sel[0]]['mountpoint']
                    kd, err = backend.create_usb_key_on_drive(drive)
                    if not kd:
                        messagebox.showerror("Error", err); return
                    if backend.store_physical_key(3, 'usb', kd):
                        lvl1 = backend.get_vault_config(1) or {'format':'HDMY','timezone':'Local System'}
                        cfg3 = {'level':3,'format':lvl1['format'],'timezone':lvl1.get('timezone','Local System'),'additional_factors':[],'description':'Level3','auto_lock_minutes':0}
                        backend.save_vault_config(3, cfg3)
                        messagebox.showinfo("Saved", "Vault 3 saved"); self.master_refresh(); self.show_main_view()
                    else:
                        messagebox.showerror("Error","Store key failed")
                else:
                    sel = bt_list.curselection()
                    if sel and hasattr(bt_list,'devices') and bt_list.devices:
                        addr,name = bt_list.devices[sel[0]]
                        keydata = backend.create_bluetooth_key(addr, name)
                        if not keydata: messagebox.showerror("Error","Failed to create BT key"); return
                        if backend.store_physical_key(3, 'bluetooth', keydata):
                            lvl1 = backend.get_vault_config(1) or {'format':'HDMY','timezone':'Local System'}
                            cfg3 = {'level':3,'format':lvl1['format'],'timezone':lvl1.get('timezone','Local System'),'additional_factors':[],'description':'Level3','auto_lock_minutes':0}
                            backend.save_vault_config(3, cfg3)
                            messagebox.showinfo("Saved","Vault 3 saved"); self.master_refresh(); self.show_main_view()
                            return
                    addr = simpledialog.askstring("BT address","Enter BT address:")
                    if not addr: return
                    keydata = backend.create_bluetooth_key(addr, None)
                    if backend.store_physical_key(3, 'bluetooth', keydata):
                        lvl1 = backend.get_vault_config(1) or {'format':'HDMY','timezone':'Local System'}
                        cfg3 = {'level':3,'format':lvl1['format'],'timezone':lvl1.get('timezone','Local System'),'additional_factors':[],'description':'Level3','auto_lock_minutes':0}
                        backend.save_vault_config(3, cfg3)
                        messagebox.showinfo("Saved","Vault 3 saved"); self.master_refresh(); self.show_main_view()
                    else:
                        messagebox.showerror("Error","Store BT key failed")
            except Exception as e:
                backend.log_event("ERROR","UI_SAVE_V3", str(e))
                messagebox.showerror("Error", f"Save failed: {e}")

        btnf = ttk.Frame(frame); btnf.pack(pady=8)
        ttk.Button(btnf, text="Save", command=save3).pack(side='left', padx=6)
        ttk.Button(btnf, text="Back", command=self.show_main_view).pack(side='left', padx=6)

    # -- Manager and operations (unchanged behavior, defensive) --
    def manage_vault(self, level):
        self.vault_unlocked[level] = True
        for w in self.content.winfo_children(): w.destroy()
        self.current_view = f"vault_{level}"
        frame = ttk.Frame(self.content); frame.pack(fill='both', expand=True, padx=8, pady=8)
        ttk.Label(frame, text=f"Vault {level} - Unlocked", font=("Segoe UI", 13, "bold")).pack(pady=8)

        action = ttk.Frame(frame); action.pack(fill='x')
        ttk.Button(action, text="Add Files", command=lambda: self.add_files_to_vault(level, frame)).pack(side='left', padx=6)
        ttk.Button(action, text="Add Folder", command=lambda: self.add_folder_to_vault(level, frame)).pack(side='left', padx=6)
        if level==2: ttk.Button(action, text="Add Application", command=lambda: self.add_application_to_vault(level, frame)).pack(side='left', padx=6)
        ttk.Button(action, text="Switch Vault", command=lambda: self.inline_switch_vault(level)).pack(side='left', padx=6)
        ttk.Button(action, text="Settings", command=lambda: self.vault_settings(level)).pack(side='left', padx=6)
        ttk.Button(action, text="Lock Vault", command=lambda: self.lock_vault(level)).pack(side='right', padx=6)
        ttk.Button(action, text="Back to Locker", command=lambda: [self.lock_vault(level), self.show_main_view()]).pack(side='right', padx=6)
        ttk.Button(action, text="Refresh", command=self.master_refresh).pack(side='right', padx=6)

        cols = ('ID','Name','Type','Size','Locked At')
        tree = ttk.Treeview(frame, columns=cols, show='headings')
        for c in cols: tree.heading(c, text=c)
        tree.pack(fill='both', expand=True, padx=8, pady=8)
        def refresh_list():
            for it in tree.get_children(): tree.delete(it)
            files = backend.list_vault_files(level)
            for f in files:
                tree.insert('', 'end', values=(f['id'], f['name'], f['type'], backend.human_size(f['size']), f['locked_at']))
        refresh_list()

        ops = ttk.Frame(frame); ops.pack(fill='x', padx=8, pady=6)
        ttk.Button(ops, text="Unlock Selected", command=lambda: self.unlock_selected(tree, level, refresh_list)).pack(side='left', padx=6)
        ttk.Button(ops, text="Delete Selected", command=lambda: self.delete_selected(tree, level, refresh_list)).pack(side='left', padx=6)
        ttk.Button(ops, text="Transfer Selected", command=lambda: self.transfer_from_manager(tree, level, refresh_list)).pack(side='left', padx=6)

    def lock_vault(self, level):
        self.vault_unlocked[level] = False
        backend.log_event("SYSTEM", "VAULT_LOCK", f"Vault {level} locked")

    def add_files_to_vault(self, level, parent):
        files = filedialog.askopenfilenames(title=f"Select files to add to vault {level}")
        if not files: return
        succeeded = 0
        for f in files:
            if backend.lock_file(f, level, item_type="file"):
                succeeded += 1
        messagebox.showinfo("Done", f"Added {succeeded}/{len(files)} files")
        self.master_refresh()

    def add_folder_to_vault(self, level, parent):
        folder = filedialog.askdirectory(title=f"Select folder to add to vault {level}")
        if not folder: return
        if not messagebox.askyesno("Confirm", f"Add folder {os.path.basename(folder)}?"): return
        if backend.lock_file(folder, level, item_type="folder"):
            messagebox.showinfo("Success", "Folder added"); self.master_refresh()
        else:
            messagebox.showerror("Error", "Failed to add folder")

    def add_application_to_vault(self, level, parent):
        app = filedialog.askopenfilename(title="Select application", filetypes=[("Executables","*.exe"),("All files","*.*")])
        if not app: return
        if not messagebox.askyesno("Confirm", f"Add {os.path.basename(app)}?"): return
        if backend.lock_file(app, level, item_type="application"):
            messagebox.showinfo("Success", "Application added"); self.master_refresh()
        else:
            messagebox.showerror("Error","Failed to add application")

    def unlock_selected(self, tree, level, refresh_cb):
        sel = tree.selection()
        if not sel: messagebox.showwarning("Select","Select item"); return
        item = tree.item(sel[0]); item_id = item['values'][0]; name = item['values'][1]
        if not messagebox.askyesno("Unlock", f"Unlock '{name}'?"): return
        restored = backend.unlock_file(item_id)
        if restored:
            messagebox.showinfo("Restored", f"Restored to: {restored}"); refresh_cb(); self.master_refresh()
        else:
            messagebox.showerror("Error", "Unlock failed")

    def delete_selected(self, tree, level, refresh_cb):
        sel = tree.selection()
        if not sel: messagebox.showwarning("Select","Select item"); return
        item = tree.item(sel[0]); item_id = item['values'][0]; name = item['values'][1]
        if not messagebox.askyesno("Delete", f"Permanently delete '{name}'?"): return
        if backend.delete_locked_item(item_id):
            messagebox.showinfo("Deleted","Item removed"); refresh_cb(); self.master_refresh()
        else:
            messagebox.showerror("Error","Delete failed")

    def transfer_from_manager(self, tree, source_vault, refresh_cb):
        sel = tree.selection()
        if not sel: messagebox.showwarning("Select","Select items"); return
        ids = [tree.item(s)['values'][0] for s in sel]
        target = simpledialog.askinteger("Target Vault", "Enter target vault number (1/2/3):")
        if not target or target==source_vault or target not in (1,2,3): messagebox.showwarning("Invalid","Invalid target"); return
        pw = simpledialog.askstring("Authenticate", f"Enter password for Vault {target}:", show='*')
        if pw is None: return
        ok,msg = backend.authenticate_vault(target, pw)
        if not ok: messagebox.showerror("Auth failed", msg); return
        transferred = backend.transfer_items_between_vaults(ids, target)
        messagebox.showinfo("Done", f"Transferred {len(transferred)}/{len(ids)} items")
        refresh_cb(); self.master_refresh()

    def inline_switch_vault(self, current_vault):
        target = simpledialog.askinteger("Switch Vault", "Enter target vault number (1/2/3):")
        if not target or target==current_vault or target not in (1,2,3): return
        pw = simpledialog.askstring("Authenticate", f"Enter password for Vault {target}:", show='*')
        if pw is None: return
        ok,msg = backend.authenticate_vault(target, pw)
        if not ok: messagebox.showerror("Auth failed", msg); return
        self.vault_unlocked[target] = True
        self.manage_vault(target)

    def vault_settings(self, level):
        # If Vault 3, open combined settings that let user change Vault1 and Vault2 settings in-place
        if level == 3:
            self.vault3_settings()
        else:
            # Reuse setup screens as "settings" for Vault1 and Vault2
            self.setup_vault(level)

    def vault3_settings(self):
        """Combined settings view for Vault 3 that allows editing Vault 1 and Vault 2 settings."""
        for w in self.content.winfo_children(): w.destroy()
        self.current_view = "settings_v3"
        frame = ttk.Frame(self.content); frame.pack(fill='both', expand=True, padx=12, pady=12)
        ttk.Label(frame, text="Vault 3 Settings - Manage Vault 1 & Vault 2", font=("Segoe UI", 14, "bold")).pack(pady=8)

        notebook = ttk.Notebook(frame)
        notebook.pack(fill='both', expand=True, padx=6, pady=6)

        # --- Vault 1 tab (format presets) ---
        tab1 = ttk.Frame(notebook)
        notebook.add(tab1, text="Vault 1 Settings")
        ttk.Label(tab1, text="Vault 1 - Format", font=("Segoe UI", 12)).pack(anchor='w', padx=8, pady=6)
        presets = ["HDMY","HMDY","DHMY","MDHY"]
        v1_cfg = backend.get_vault_config(1) or {'format':'HDMY'}
        v1_fmt_var = tk.StringVar(value=v1_cfg.get('format','HDMY'))
        ttk.Label(tab1, text="Choose format:").pack(anchor='w', padx=8)
        v1_cb = ttk.Combobox(tab1, values=presets, textvariable=v1_fmt_var, state='readonly'); v1_cb.pack(anchor='w', padx=8, pady=6)

        def save_v1_from_v3():
            fmt = v1_fmt_var.get().strip().upper()
            if len(fmt)!=4 or not all(c in 'HDMY' for c in fmt):
                messagebox.showerror("Invalid", "Format must be 4 chars composed of H,D,M,Y"); return
            cfg = {'level':1,'format':fmt,'timezone':'Local System','additional_factors':[],'description':'Level1','auto_lock_minutes':0}
            if backend.save_vault_config(1, cfg):
                # update Vault3 to follow Vault1 format (if Vault3 configured)
                v3 = backend.get_vault_config(3)
                if v3:
                    v3_out = {'level':3, 'format': fmt, 'timezone': v3.get('timezone','Local System'), 'additional_factors': [], 'description': v3.get('description','Level3'), 'auto_lock_minutes': v3.get('auto_lock_minutes',0)}
                    backend.save_vault_config(3, v3_out)
                messagebox.showinfo("Saved", "Vault 1 updated; Vault 3 now follows Vault 1 format")
                self.master_refresh()
            else:
                messagebox.showerror("Error", "Failed to save Vault 1 settings")

        ttk.Button(tab1, text="Save Vault 1", command=save_v1_from_v3).pack(padx=8, pady=8, anchor='w')

        # --- Vault 2 tab (same as setup) ---
        tab2 = ttk.Frame(notebook)
        notebook.add(tab2, text="Vault 2 Settings")
        ttk.Label(tab2, text="Vault 2 - Format & Timezone", font=("Segoe UI", 12)).pack(anchor='w', padx=8, pady=6)
        v2_cfg = backend.get_vault_config(2) or {'format': (v1_cfg.get('format') if v1_cfg else 'HDMY'), 'timezone':'Local System', 'additional_factors':[]}
        v2_fmt_var = tk.StringVar(value=v2_cfg.get('format', (v1_cfg.get('format') if v1_cfg else 'HDMY')))
        ttk.Label(tab2, text="Base format:").pack(anchor='w', padx=8)
        ttk.Entry(tab2, textvariable=v2_fmt_var, width=12).pack(anchor='w', padx=8, pady=4)

        city_values = [f"{c['display_name']} ({c['timezone']})" for c in backend.CITIES]
        v2_city_var = tk.StringVar()
        # preselect existing timezone if available
        prev2 = v2_cfg.get('timezone','Local System')
        found = next((cv for cv in city_values if prev2 in cv), '')
        v2_city_var.set(found)
        ttk.Label(tab2, text="Select city/timezone:").pack(anchor='w', padx=8)
        v2_city_cb = ttk.Combobox(tab2, values=city_values, textvariable=v2_city_var, state='readonly', width=60)
        v2_city_cb.pack(fill='x', padx=8, pady=4)

        v2_battery = tk.BooleanVar(value=('battery' in v2_cfg.get('additional_factors',[])))
        v2_cpu = tk.BooleanVar(value=('cpu' in v2_cfg.get('additional_factors',[])))
        v2_ram = tk.BooleanVar(value=('ram_size' in v2_cfg.get('additional_factors',[])))
        ttk.Label(tab2, text="Additional factors (at least one required):").pack(anchor='w', padx=8)
        ttk.Checkbutton(tab2, text="Battery %", variable=v2_battery).pack(anchor='w', padx=12)
        ttk.Checkbutton(tab2, text="CPU Usage", variable=v2_cpu).pack(anchor='w', padx=12)
        ttk.Checkbutton(tab2, text="RAM Size", variable=v2_ram).pack(anchor='w', padx=12)

        v2_preview_lbl = ttk.Label(tab2, text="Password preview: -", font=("Consolas",12))
        v2_preview_lbl.pack(padx=8, pady=6)
        v2_reviewed = tk.BooleanVar()
        ttk.Checkbutton(tab2, text="I have reviewed the preview", variable=v2_reviewed).pack(anchor='w', padx=8)

        def v2_show_preview():
            sel = v2_city_var.get()
            if not sel:
                messagebox.showerror("City", "Select a city"); return
            tz = sel.split('(')[-1].strip(')')
            add = []
            if v2_battery.get(): add.append('battery')
            if v2_cpu.get(): add.append('cpu')
            if v2_ram.get(): add.append('ram_size')
            cfg_example = {'format': v2_fmt_var.get().strip().upper(), 'timezone': tz, 'additional_factors': add}
            try:
                preview = backend.generate_level2_password(cfg_example)
            except Exception as e:
                backend.log_event("ERROR","V3_UI_V2_PREVIEW", str(e))
                preview = "ERROR"
            v2_preview_lbl.config(text=f"Password preview: {preview}")

        def save_v2_from_v3():
            fmt = v2_fmt_var.get().strip().upper()
            if len(fmt)!=4 or not all(c in 'HDMY' for c in fmt):
                messagebox.showerror("Invalid","Format must be 4 chars H/D/M/Y"); return
            if not v2_city_var.get():
                messagebox.showerror("City","Select a city"); return
            add=[]
            if v2_battery.get(): add.append('battery')
            if v2_cpu.get(): add.append('cpu')
            if v2_ram.get(): add.append('ram_size')
            if not add: messagebox.showerror("Invalid","Vault2 requires at least one additional factor"); return
            if not v2_reviewed.get(): messagebox.showerror("Preview","Please confirm you reviewed the preview"); return
            tz = v2_city_var.get().split('(')[-1].strip(')')
            cfg = {'level':2,'format':fmt,'timezone':tz,'additional_factors':add,'description':'Level2','auto_lock_minutes':0}
            if backend.save_vault_config(2, cfg):
                messagebox.showinfo("Saved","Vault 2 updated")
                self.master_refresh()
            else:
                messagebox.showerror("Error","Failed to save Vault 2 settings")

        v2_btns = ttk.Frame(tab2); v2_btns.pack(pady=8)
        ttk.Button(v2_btns, text="Show Preview", command=v2_show_preview).pack(side='left', padx=6)
        ttk.Button(v2_btns, text="Save Vault 2", command=save_v2_from_v3).pack(side='left', padx=6)

        # Back button for combined settings
        ttk.Button(frame, text="Back to Vault Manager", command=lambda: self.manage_vault(3)).pack(pady=8)

    # -- Remaining UI methods unchanged from previous implementation --
    def add_files_to_vault(self, level, parent):
        files = filedialog.askopenfilenames(title=f"Select files to add to vault {level}")
        if not files: return
        succeeded = 0
        for f in files:
            if backend.lock_file(f, level, item_type="file"):
                succeeded += 1
        messagebox.showinfo("Done", f"Added {succeeded}/{len(files)} files")
        self.master_refresh()

    def add_folder_to_vault(self, level, parent):
        folder = filedialog.askdirectory(title=f"Select folder to add to vault {level}")
        if not folder: return
        if not messagebox.askyesno("Confirm", f"Add folder {os.path.basename(folder)}?"): return
        if backend.lock_file(folder, level, item_type="folder"):
            messagebox.showinfo("Success", "Folder added"); self.master_refresh()
        else:
            messagebox.showerror("Error", "Failed to add folder")

    def add_application_to_vault(self, level, parent):
        app = filedialog.askopenfilename(title="Select application", filetypes=[("Executables","*.exe"),("All files","*.*")])
        if not app: return
        if not messagebox.askyesno("Confirm", f"Add {os.path.basename(app)}?"): return
        if backend.lock_file(app, level, item_type="application"):
            messagebox.showinfo("Success", "Application added"); self.master_refresh()
        else:
            messagebox.showerror("Error","Failed to add application")

    def unlock_selected(self, tree, level, refresh_cb):
        sel = tree.selection()
        if not sel: messagebox.showwarning("Select","Select item"); return
        item = tree.item(sel[0]); item_id = item['values'][0]; name = item['values'][1]
        if not messagebox.askyesno("Unlock", f"Unlock '{name}'?"): return
        restored = backend.unlock_file(item_id)
        if restored:
            messagebox.showinfo("Restored", f"Restored to: {restored}"); refresh_cb(); self.master_refresh()
        else:
            messagebox.showerror("Error", "Unlock failed")

    def delete_selected(self, tree, level, refresh_cb):
        sel = tree.selection()
        if not sel: messagebox.showwarning("Select","Select item"); return
        item = tree.item(sel[0]); item_id = item['values'][0]; name = item['values'][1]
        if not messagebox.askyesno("Delete", f"Permanently delete '{name}'?"): return
        if backend.delete_locked_item(item_id):
            messagebox.showinfo("Deleted","Item removed"); refresh_cb(); self.master_refresh()
        else:
            messagebox.showerror("Error","Delete failed")

    def transfer_from_manager(self, tree, source_vault, refresh_cb):
        sel = tree.selection()
        if not sel: messagebox.showwarning("Select","Select items"); return
        ids = [tree.item(s)['values'][0] for s in sel]
        target = simpledialog.askinteger("Target Vault", "Enter target vault number (1/2/3):")
        if not target or target==source_vault or target not in (1,2,3): messagebox.showwarning("Invalid","Invalid target"); return
        pw = simpledialog.askstring("Authenticate", f"Enter password for Vault {target}:", show='*')
        if pw is None: return
        ok,msg = backend.authenticate_vault(target, pw)
        if not ok: messagebox.showerror("Auth failed", msg); return
        transferred = backend.transfer_items_between_vaults(ids, target)
        messagebox.showinfo("Done", f"Transferred {len(transferred)}/{len(ids)} items")
        refresh_cb(); self.master_refresh()

    def inline_switch_vault(self, current_vault):
        target = simpledialog.askinteger("Switch Vault", "Enter target vault number (1/2/3):")
        if not target or target==current_vault or target not in (1,2,3): return
        pw = simpledialog.askstring("Authenticate", f"Enter password for Vault {target}:", show='*')
        if pw is None: return
        ok,msg = backend.authenticate_vault(target, pw)
        if not ok: messagebox.showerror("Auth failed", msg); return
        self.vault_unlocked[target] = True
        self.manage_vault(target)

def main():
    root = tk.Tk()
    app = SecureFileLockerUI(root)
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        messagebox.showerror("Fatal Error", "An unexpected error occurred. See security_audit.log.")