import sys
sys.path.insert(0, '.')

from wechat_decrypt import config
_cfg = config.load_config()

decrypted_dir = _cfg["decrypted_dir"]
CONTACT_CACHE = _cfg.get("decrypted_dir", "decrypted")
import os
CONTACT_CACHE = os.path.join(decrypted_dir, "contact", "contact.db")

print("CONTACT_CACHE:", CONTACT_CACHE)
print("Exists:", os.path.exists(CONTACT_CACHE))

# Load names
import sqlite3
names = {}
try:
    conn = sqlite3.connect(CONTACT_CACHE)
    for r in conn.execute("SELECT username, nick_name, remark FROM contact").fetchall():
        names[r[0]] = r[2] if r[2] else r[1] if r[1] else r[0]
    conn.close()
except Exception as e:
    print("Error:", e)

print("\nTotal contacts:", len(names))
for username, name in names.items():
    if 'chatroom' in username:
        print(f"  {username} -> {name}")
