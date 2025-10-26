# backend.py
"""
Secure File Locker core logic (robustified for Vault3 key checks and test-key flows).
"""
import os
import sys
import sqlite3
import shutil
import zipfile
import hashlib
import logging
import json
import base64
import time
import platform
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Optional imports
try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except Exception:
    Fernet = None
    InvalidToken = Exception
    CRYPTO_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    psutil = None
    PSUTIL_AVAILABLE = False

try:
    import pytz
    PYTZ_AVAILABLE = True
except Exception:
    pytz = None
    PYTZ_AVAILABLE = False

try:
    import bluetooth
    BLUETOOTH_AVAILABLE = True
except Exception:
    bluetooth = None
    BLUETOOTH_AVAILABLE = False

# Paths and logging
APP_NAME = "SecureFileLocker"
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

DB_FILE = os.path.join(APP_DIR, "secure_file_locker.db")
VAULT_STORAGE = os.path.join(APP_DIR, "vault_storage")
AUDIT_LOG = os.path.join(APP_DIR, "security_audit.log")
os.makedirs(VAULT_STORAGE, exist_ok=True)

logging.basicConfig(filename=AUDIT_LOG, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_event(category, action, status):
    logging.info(f"{category} - {action} - {status}")

# DB init (same as before)
def init_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS vault_configs (
            vault_level INTEGER PRIMARY KEY,
            format_string TEXT NOT NULL,
            timezone TEXT DEFAULT 'Local System',
            additional_factors TEXT DEFAULT '[]',
            description TEXT,
            auto_lock_minutes INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS physical_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vault_level INTEGER UNIQUE,
            key_type TEXT NOT NULL,
            key_data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_verified TIMESTAMP,
            verification_count INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS locked_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            original_path TEXT NOT NULL,
            vault_path TEXT NOT NULL,
            vault_level INTEGER NOT NULL,
            item_type TEXT NOT NULL,
            encryption_key BLOB NOT NULL,
            file_hash TEXT,
            file_size INTEGER,
            locked_at TIMESTAMP NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    log_event("SYSTEM", "DATABASE_INIT", "DB initialized")

init_database()

# Minimal city list (used elsewhere)
CITIES = [
    {"name":"New York","timezone":"America/New_York","utc_offset":-5,"display_name":"New York, United States"},
    {"name":"London","timezone":"Europe/London","utc_offset":0,"display_name":"London, United Kingdom"},
    {"name":"Tokyo","timezone":"Asia/Tokyo","utc_offset":9,"display_name":"Tokyo, Japan"},
    {"name":"Sydney","timezone":"Australia/Sydney","utc_offset":10,"display_name":"Sydney, Australia"},
    {"name":"Paris","timezone":"Europe/Paris","utc_offset":1,"display_name":"Paris, France"},
    {"name":"Berlin","timezone":"Europe/Berlin","utc_offset":1,"display_name":"Berlin, Germany"},
    {"name":"Mumbai","timezone":"Asia/Kolkata","utc_offset":5.5,"display_name":"Mumbai, India"},
    {"name":"Beijing","timezone":"Asia/Shanghai","utc_offset":8,"display_name":"Beijing, China"}
]

# Utility helpers
def ensure_dir(p):
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        pass

def human_size(size_bytes):
    try:
        if not size_bytes:
            return "0 B"
        size = float(size_bytes)
        for unit in ["B","KB","MB","GB","TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    except Exception:
        return "0 B"

# Vault config helpers
def get_vault_config(vault_level):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT format_string, timezone, additional_factors, description, auto_lock_minutes FROM vault_configs WHERE vault_level = ?", (vault_level,))
        r = c.fetchone()
        conn.close()
        if r:
            return {
                'format': r[0],
                'timezone': r[1] or 'Local System',
                'additional_factors': json.loads(r[2]) if r[2] else [],
                'description': r[3],
                'auto_lock_minutes': r[4] or 0
            }
        return None
    except Exception as e:
        log_event("ERROR", f"GET_VAULT_CONFIG_{vault_level}", str(e))
        return None

def save_vault_config(vault_level, config):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO vault_configs
            (vault_level, format_string, timezone, additional_factors, description, auto_lock_minutes, last_modified)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (vault_level, config['format'], config.get('timezone','Local System'),
              json.dumps(config.get('additional_factors',[])), config.get('description',''), config.get('auto_lock_minutes',0)))
        conn.commit()
        conn.close()
        log_event("CONFIG", f"SAVE_VAULT_{vault_level}", "Saved")
        return True
    except Exception as e:
        log_event("ERROR", f"SAVE_VAULT_{vault_level}", str(e))
        return False

# Physical key DB helpers
def store_physical_key(vault_level, key_type, key_data):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            INSERT INTO physical_keys (vault_level, key_type, key_data)
            VALUES (?, ?, ?)
            ON CONFLICT(vault_level) DO UPDATE SET key_type=excluded.key_type, key_data=excluded.key_data, last_verified=NULL
        ''', (vault_level, key_type, json.dumps(key_data)))
        conn.commit()
        conn.close()
        log_event("CONFIG", f"PHYSICAL_KEY_{vault_level}_SAVE", f"{key_type}")
        return True
    except Exception as e:
        log_event("ERROR", f"PHYSICAL_KEY_{vault_level}_SAVE", str(e))
        return False

def get_physical_key(vault_level):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT key_type, key_data FROM physical_keys WHERE vault_level = ?", (vault_level,))
        r = c.fetchone()
        conn.close()
        if r:
            return r[0], json.loads(r[1])
        return None, None
    except Exception as e:
        log_event("ERROR", f"GET_PHYSICAL_KEY_{vault_level}", str(e))
        return None, None

def update_key_verified(vault_level):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            UPDATE physical_keys SET last_verified=CURRENT_TIMESTAMP, verification_count = verification_count + 1 WHERE vault_level = ?
        ''', (vault_level,))
        conn.commit()
        conn.close()
    except Exception as e:
        log_event("ERROR", f"UPDATE_KEY_VERIFIED_{vault_level}", str(e))

# Crypto helpers
def generate_fernet_key():
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography package required")
    return Fernet.generate_key()

def encrypt_bytes(key, data):
    return Fernet(key).encrypt(data)

def decrypt_bytes(key, data):
    return Fernet(key).decrypt(data)

# Vault file operations - unchanged except for robust deletes
def get_vault_dir(level):
    p = os.path.join(VAULT_STORAGE, f"vault_{level}")
    ensure_dir(p)
    return p

def lock_file(file_path, vault_level, item_type="file"):
    try:
        if not os.path.exists(file_path):
            log_event("ERROR", "LOCK_FILE", f"not found: {file_path}")
            return False

        original_name = os.path.basename(file_path)
        original_path = os.path.abspath(file_path)
        vault_dir = get_vault_dir(vault_level)

        temp_zip = None
        if item_type == "folder":
            temp_zip = os.path.join(vault_dir, f"temp_{abs(hash(file_path))}.zip")
            with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(file_path):
                    for f in files:
                        fp = os.path.join(root, f)
                        arc = os.path.relpath(fp, file_path)
                        zf.write(fp, arc)
            file_to_encrypt = temp_zip
            original_name = f"{original_name}.zip"
        else:
            file_to_encrypt = file_path

        with open(file_to_encrypt, 'rb') as f:
            data = f.read()

        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography package required")
        key = generate_fernet_key()
        encrypted = encrypt_bytes(key, data)

        hashpart = hashlib.sha256(original_name.encode()).hexdigest()[:16]
        vault_filename = f"{hashpart}_{int(time.time())}.enc"
        vault_path = os.path.join(vault_dir, vault_filename)
        with open(vault_path, 'wb') as f:
            f.write(encrypted)

        if item_type == "folder":
            try:
                shutil.rmtree(original_path)
            except Exception:
                pass
            try:
                os.remove(temp_zip)
            except Exception:
                pass
        else:
            try:
                os.remove(original_path)
            except Exception:
                pass

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            INSERT INTO locked_items (name, original_path, vault_path, vault_level, item_type, encryption_key, file_hash, file_size, locked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (original_name, original_path, vault_path, vault_level, item_type, key, hashlib.sha256(data).hexdigest(), len(data), datetime.now()))
        conn.commit()
        conn.close()

        log_event("FILE", f"LOCK_V{vault_level}", original_name)
        return True
    except Exception as e:
        log_event("ERROR", "LOCK_FILE", str(e))
        return False

def list_vault_files(vault_level):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, name, locked_at, file_size, item_type FROM locked_items WHERE vault_level = ? ORDER BY locked_at DESC", (vault_level,))
        rows = c.fetchall()
        conn.close()
        out = []
        for r in rows:
            out.append({'id': r[0], 'name': r[1], 'locked_at': r[2], 'size': r[3], 'type': r[4]})
        return out
    except Exception as e:
        log_event("ERROR", f"LIST_VFILES_{vault_level}", str(e))
        return []

def unlock_file(item_id):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT name, original_path, vault_path, encryption_key, item_type FROM locked_items WHERE id = ?", (item_id,))
        r = c.fetchone()
        if not r:
            conn.close()
            return False
        name, orig_path, vault_path, key_blob, item_type = r
        if not os.path.exists(vault_path):
            c.execute("DELETE FROM locked_items WHERE id = ?", (item_id,))
            conn.commit()
            conn.close()
            log_event("ERROR", "UNLOCK", f"missing encrypted file {vault_path}")
            return False

        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography package required")
        try:
            data = open(vault_path, 'rb').read()
            decrypted = decrypt_bytes(key_blob, data)
        except InvalidToken:
            conn.close()
            log_event("ERROR", "UNLOCK", "Invalid encryption key / token")
            return False

        restore_path = orig_path
        if os.path.exists(restore_path):
            base, ext = os.path.splitext(restore_path)
            i = 1
            while os.path.exists(f"{base}_{i}{ext}"):
                i += 1
            restore_path = f"{base}_{i}{ext}"

        d = os.path.dirname(restore_path)
        if d:
            ensure_dir(d)

        if item_type == "folder":
            tmp = restore_path + ".zip"
            with open(tmp, 'wb') as f:
                f.write(decrypted)
            with zipfile.ZipFile(tmp, 'r') as zf:
                zf.extractall(restore_path)
            try:
                os.remove(tmp)
            except Exception:
                pass
        else:
            with open(restore_path, 'wb') as f:
                f.write(decrypted)

        try:
            os.remove(vault_path)
        except Exception:
            pass
        c.execute("DELETE FROM locked_items WHERE id = ?", (item_id,))
        conn.commit()
        conn.close()
        log_event("FILE", "UNLOCK", f"{name} -> {restore_path}")
        return restore_path
    except Exception as e:
        log_event("ERROR", "UNLOCK_FILE", str(e))
        return False

def delete_locked_item(item_id):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT vault_path FROM locked_items WHERE id = ?", (item_id,))
        r = c.fetchone()
        if r:
            vp = r[0]
            try:
                os.remove(vp)
            except Exception:
                pass
            c.execute("DELETE FROM locked_items WHERE id = ?", (item_id,))
            conn.commit()
            conn.close()
            log_event("FILE", "DELETE", f"Item {item_id}")
            return True
        conn.close()
        return False
    except Exception as e:
        log_event("ERROR", "DELETE_LOCKED", str(e))
        return False

def transfer_items_between_vaults(item_ids, target_vault):
    transferred = []
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        for item_id in item_ids:
            c.execute("SELECT id, name, vault_path, encryption_key, item_type FROM locked_items WHERE id = ?", (item_id,))
            r = c.fetchone()
            if not r:
                continue
            id_, name, vault_path, key_blob, item_type = r
            if not os.path.exists(vault_path):
                log_event("ERROR", "TRANSFER", f"missing vault file {vault_path}")
                continue
            try:
                data = open(vault_path, 'rb').read()
                plaintext = decrypt_bytes(key_blob, data)
            except Exception as e:
                log_event("ERROR", "TRANSFER_DECRYPT", f"{name} - {e}")
                continue

            new_key = generate_fernet_key()
            new_enc = encrypt_bytes(new_key, plaintext)

            vault_dir = get_vault_dir(target_vault)
            hashpart = hashlib.sha256(name.encode()).hexdigest()[:16]
            new_vault_filename = f"{hashpart}_{int(time.time())}.enc"
            new_vault_path = os.path.join(vault_dir, new_vault_filename)
            with open(new_vault_path, 'wb') as f:
                f.write(new_enc)

            try:
                os.remove(vault_path)
            except Exception:
                pass

            c.execute('''
                UPDATE locked_items SET vault_path = ?, vault_level = ?, encryption_key = ? WHERE id = ?
            ''', (new_vault_path, target_vault, new_key, id_))
            conn.commit()
            transferred.append(id_)
            log_event("TRANSFER", f"{id_}->V{target_vault}", name)
        conn.close()
    except Exception as e:
        log_event("ERROR", "TRANSFER_ITEMS", str(e))
    return transferred

# Removable drives & USB key functions (robust)
def get_removable_drives():
    drives = []
    try:
        if platform.system() == "Windows":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                bitmask = kernel32.GetLogicalDrives()
                for d in range(26):
                    if bitmask & (1 << d):
                        drive = f"{chr(65+d)}:\\"
                        drive_type = kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive))
                        if drive_type == 2:
                            drives.append({'device': drive[0]+':', 'mountpoint': drive, 'fstype': ''})
            except Exception:
                pass
        if PSUTIL_AVAILABLE:
            for p in psutil.disk_partitions(all=False):
                if 'removable' in (p.opts or '').lower():
                    drives.append({'device': p.device, 'mountpoint': p.mountpoint, 'fstype': p.fstype})
    except Exception as e:
        log_event("ERROR", "GET_REMOVABLE_DRIVES", str(e))
    seen = set()
    unique = []
    for d in drives:
        mp = d['mountpoint']
        if platform.system() == "Windows" and mp and not (mp.endswith('\\') or mp.endswith('/')):
            mp = mp + '\\'
            d['mountpoint'] = mp
        if d['mountpoint'] not in seen:
            unique.append(d)
            seen.add(d['mountpoint'])
    return unique

def create_usb_key_on_drive(drive_mountpoint):
    """
    Write encrypted token to drive as .sfl_key.dat.
    Returns (key_data, None) on success or (None, error_message) on failure.
    """
    try:
        if not CRYPTO_AVAILABLE:
            msg = "cryptography package required"
            log_event("ERROR", "CREATE_USB_KEY", msg)
            return None, msg
        mp = drive_mountpoint
        if platform.system() == "Windows" and mp and not (mp.endswith('\\') or mp.endswith('/')):
            mp = mp + '\\'
        if not os.path.isdir(mp):
            msg = f"Mountpoint not directory: {mp}"
            log_event("ERROR", "CREATE_USB_KEY", msg)
            return None, msg
        try:
            test_path = os.path.join(mp, ".sfl_write_test.tmp")
            with open(test_path, "wb") as tf:
                tf.write(b"test")
            os.remove(test_path)
        except Exception as e:
            msg = f"Drive not writable: {mp} - {e}"
            log_event("ERROR", "CREATE_USB_KEY", msg)
            return None, msg

        master_key = generate_fernet_key()
        token = os.urandom(32)
        encrypted = encrypt_bytes(master_key, token)
        key_filename = ".sfl_key.dat"
        key_path = os.path.join(mp, key_filename)
        try:
            tmp = key_path + ".tmp"
            with open(tmp, 'wb') as f:
                f.write(encrypted)
            os.replace(tmp, key_path)
        except PermissionError as pe:
            msg = f"Permission denied writing key to {key_path}: {pe}"
            log_event("ERROR", "CREATE_USB_KEY", msg)
            return None, msg
        except Exception as e:
            msg = f"Failed to write key file: {e}"
            log_event("ERROR", "CREATE_USB_KEY", msg)
            return None, msg

        key_data = {
            'drive_mountpoint': mp,
            'key_file': key_filename,
            'master_key_b64': base64.b64encode(master_key).decode('utf-8'),
            'token_hash': hashlib.sha256(token).hexdigest()
        }
        log_event("SYSTEM", "USB_KEY_CREATED", f"{mp}/{key_filename}")
        return key_data, None
    except Exception as e:
        log_event("ERROR", "CREATE_USB_KEY_TOP", str(e))
        return None, str(e)

def verify_usb_key(vault_level):
    """
    Verify stored usb key for a vault. Returns True/False.
    This function is defensive: it never raises.
    """
    try:
        key_type, key_data = get_physical_key(vault_level)
        if key_type != 'usb' or not key_data:
            return False
        mount = key_data.get('drive_mountpoint')
        fname = key_data.get('key_file', '.sfl_key.dat')
        master_key_b64 = key_data.get('master_key_b64')
        if not mount or not master_key_b64:
            return False
        mp = mount
        if platform.system() == "Windows" and mp and not (mp.endswith('\\') or mp.endswith('/')):
            mp = mp + '\\'
        key_path = os.path.join(mp, fname)
        if not os.path.exists(key_path):
            log_event("SYSTEM", "VERIFY_USB_KEY", f"Key file missing: {key_path}")
            return False
        try:
            encrypted = open(key_path, 'rb').read()
            master_key = base64.b64decode(master_key_b64)
            token = decrypt_bytes(master_key, encrypted)
            if 'token_hash' in key_data and hashlib.sha256(token).hexdigest() != key_data.get('token_hash'):
                log_event("SYSTEM", "VERIFY_USB_KEY", "token hash mismatch")
                return False
            update_key_verified(vault_level)
            return True
        except Exception as e:
            log_event("ERROR", "VERIFY_USB_KEY", str(e))
            return False
    except Exception as e:
        log_event("ERROR", "VERIFY_USB_KEY_TOP", str(e))
        return False

def verify_usb_key_direct(keydata):
    """
    Verify a key dict returned by create_usb_key_on_drive (used by Test Key flow).
    Defensive: never raises.
    """
    try:
        if not keydata:
            return False
        mp = keydata.get('drive_mountpoint')
        fname = keydata.get('key_file')
        key_path = os.path.join(mp, fname)
        if not os.path.exists(key_path):
            return False
        encrypted = open(key_path, 'rb').read()
        master = base64.b64decode(keydata.get('master_key_b64'))
        token = decrypt_bytes(master, encrypted)
        return hashlib.sha256(token).hexdigest() == keydata.get('token_hash')
    except Exception as e:
        log_event("ERROR", "VERIFY_USB_KEY_DIRECT", str(e))
        return False

# Bluetooth helpers (defensive)
def bt_lookup_is_present(addr):
    try:
        if not BLUETOOTH_AVAILABLE:
            return False
        name = bluetooth.lookup_name(addr, timeout=3)
        return bool(name)
    except Exception:
        return False

def scan_bluetooth_connected(timeout=5):
    results = []
    if not BLUETOOTH_AVAILABLE:
        return results
    try:
        discovered = bluetooth.discover_devices(duration=timeout, lookup_names=True)
        for addr, name in discovered:
            if not name:
                continue
            n = name.lower()
            if any(k in n for k in ('phone','android','iphone','pixel','tablet','watch')):
                if bt_lookup_is_present(addr):
                    results.append((addr, name))
            else:
                try:
                    services = bluetooth.find_service(address=addr) or []
                except Exception:
                    services = []
                if services and bt_lookup_is_present(addr):
                    results.append((addr, name))
    except Exception as e:
        log_event("ERROR", "BT_SCAN", str(e))
    return results

def create_bluetooth_key(device_addr, device_name=None):
    try:
        if not CRYPTO_AVAILABLE:
            log_event("ERROR", "CREATE_BT_KEY", "cryptography not available")
            return None
        master_key = generate_fernet_key()
        token = os.urandom(32)
        key_data = {
            'device_address': device_addr,
            'device_name': device_name,
            'master_key_b64': base64.b64encode(master_key).decode('utf-8'),
            'token_hash': hashlib.sha256(token).hexdigest()
        }
        log_event("SYSTEM", "BT_KEY_CREATED", f"{device_addr}")
        return key_data
    except Exception as e:
        log_event("ERROR", "CREATE_BT_KEY", str(e))
        return None

def verify_bluetooth_key(vault_level, timeout=5):
    try:
        key_type, key_data = get_physical_key(vault_level)
        if key_type != 'bluetooth' or not key_data:
            return False
        addr = key_data.get('device_address')
        if not addr:
            return False
        # prefer quick lookup first
        try:
            if bt_lookup_is_present(addr):
                update_key_verified(vault_level)
                return True
        except Exception:
            pass
        # fallback to scan
        try:
            present_list = scan_bluetooth_connected(timeout=timeout)
            for a, _ in present_list:
                if a == addr:
                    update_key_verified(vault_level)
                    return True
        except Exception as e:
            log_event("ERROR", "VERIFY_BT_KEY_SCAN", str(e))
        return False
    except Exception as e:
        log_event("ERROR", "VERIFY_BT_KEY_TOP", str(e))
        return False

def verify_physical_key(vault_level):
    """
    Defensive wrapper to check if a physical key (usb/bluetooth) is present for a vault.
    This will never raise; it logs and returns False on unexpected errors.
    """
    try:
        kt, _ = get_physical_key(vault_level)
        if not kt:
            return False
        if kt == 'usb':
            return verify_usb_key(vault_level)
        if kt == 'bluetooth':
            return verify_bluetooth_key(vault_level)
        return False
    except Exception as e:
        log_event("ERROR", "VERIFY_PHYSICAL_KEY", str(e))
        return False

# Time and password (unchanged from monolith, defensive)
def get_current_time_for_timezone(tz_str):
    try:
        if not tz_str or tz_str in ('Local System',''):
            return datetime.now()
        if tz_str == 'UTC':
            return datetime.utcnow()
        if PYTZ_AVAILABLE:
            try:
                tz = pytz.timezone(tz_str)
                return datetime.now(tz)
            except Exception:
                pass
        city = next((c for c in CITIES if c['timezone'] == tz_str or c['name'] == tz_str or c['display_name'] == tz_str), None)
        if city and 'utc_offset' in city:
            utcnow = datetime.now(timezone.utc)
            return (utcnow + timedelta(hours=city['utc_offset'])).replace(tzinfo=None)
        return datetime.now()
    except Exception:
        return datetime.now()

def generate_password_from_format(format_string, dt: datetime):
    comps = {
        'H': f"{dt.hour:02d}",
        'D': f"{dt.day:02d}",
        'M': f"{dt.month:02d}",
        'Y': f"{dt.year}"
    }
    if not format_string or len(format_string) != 4 or not all(c in 'HDMY' for c in format_string):
        raise ValueError("Invalid format string")
    return ''.join(comps[c] for c in format_string)

def generate_level1_password(format_string, timezone_str='Local System'):
    try:
        dt = get_current_time_for_timezone(timezone_str)
        return generate_password_from_format(format_string, dt)
    except Exception as e:
        log_event("ERROR", "GEN_L1_PW", str(e))
        return "0000000000"

def generate_level2_password(config):
    base = generate_level1_password(config['format'], config.get('timezone','Local System'))
    extra = ""
    for f in config.get('additional_factors', []):
        if f == 'battery':
            try:
                if PSUTIL_AVAILABLE:
                    b = psutil.sensors_battery()
                    if b and b.percent is not None:
                        extra += f"{int(b.percent):02d}"
                    else:
                        extra += "00"
                else:
                    extra += "00"
            except Exception:
                extra += "00"
        elif f == 'cpu':
            try:
                if PSUTIL_AVAILABLE:
                    extra += f"{int(psutil.cpu_percent(interval=0.1)):02d}"
                else:
                    extra += "00"
            except Exception:
                extra += "00"
        elif f == 'ram_size':
            try:
                if PSUTIL_AVAILABLE:
                    ram_gb = psutil.virtual_memory().total // (1024**3)
                    extra += f"{ram_gb:02d}"
                else:
                    extra += "08"
            except Exception:
                extra += "08"
    return base + extra

def authenticate_vault(vault_level, user_input):
    try:
        cfg = get_vault_config(vault_level)
        if not cfg:
            return False, "Vault not configured"
        if vault_level == 1:
            expected = generate_level1_password(cfg['format'], cfg.get('timezone','Local System'))
        elif vault_level == 2:
            expected = generate_level2_password(cfg)
        else:
            expected = generate_level1_password(cfg['format'], cfg.get('timezone','Local System'))
        if user_input != expected:
            log_event("AUTH", f"VAULT_{vault_level}", "FAILED_INVALID_PW")
            return False, "Invalid password"
        if vault_level == 3:
            # physical key presence must be checked; use defensive wrapper
            if not verify_physical_key(3):
                log_event("AUTH", "VAULT_3", "FAILED_KEY")
                return False, "Physical key not detected"
        log_event("AUTH", f"VAULT_{vault_level}", "SUCCESS")
        return True, "OK"
    except Exception as e:
        log_event("ERROR", "AUTH_EXCEPTION", str(e))
        return False, "Authentication error"

# Export public API
__all__ = [
    'APP_DIR','AUDIT_LOG','CITIES',
    'get_vault_config','save_vault_config',
    'store_physical_key','get_physical_key','update_key_verified',
    'get_vault_dir','lock_file','unlock_file','list_vault_files','delete_locked_item','transfer_items_between_vaults',
    'get_removable_drives','create_usb_key_on_drive','verify_usb_key','verify_usb_key_direct',
    'scan_bluetooth_connected','create_bluetooth_key','verify_bluetooth_key','verify_physical_key',
    'generate_level1_password','generate_level2_password','authenticate_vault','human_size','log_event'
]