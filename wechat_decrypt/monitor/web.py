"""
微信实时消息监听器 - SSE 服务端 (mtime检测)

http://localhost:5678
- 30ms轮询WAL/DB文件的mtime变化（WAL是预分配固定大小，不能用size检测）
- 检测到变化后：全量解密DB + 全量WAL patch
- SSE 服务器推送，支持 /stream 端点
"""
import hashlib, struct, os, sys, json, time, sqlite3, threading, queue
import hmac as hmac_mod
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from Crypto.Cipher import AES
import urllib.parse
import glob as glob_mod
import zstandard as zstd
from ..decrypt.image import extract_md5_from_packed_info, decrypt_dat_file, is_v2_format
from ..key_utils import get_key_info, strip_key_metadata

_zstd_dctx = zstd.ZstdDecompressor()

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
RESERVE_SZ = 80
SQLITE_HDR = b'SQLite format 3\x00'
WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24

from ..config import load_config
_cfg = load_config()
DB_DIR = _cfg["db_dir"]
KEYS_FILE = _cfg["keys_file"]
CONTACT_CACHE = os.path.join(_cfg["decrypted_dir"], "contact", "contact.db")
DECRYPTED_SESSION = os.path.join(_cfg["decrypted_dir"], "session", "session.db")
DECODED_IMAGE_DIR = _cfg.get("decoded_image_dir", os.path.join(os.path.dirname(os.path.abspath(__file__)), "decoded_images"))
MONITOR_CACHE_DIR = os.path.join(_cfg["decrypted_dir"], "_monitor_cache")
WECHAT_BASE_DIR = _cfg.get("wechat_base_dir", "")
IMAGE_AES_KEY = None  # 将在 main() 中重新加载
IMAGE_XOR_KEY = 0x88  # 默认值，将在 main() 中更新

POLL_MS = 30  # 高频轮询WAL/DB的mtime，30ms一次
PORT = 5678

sse_clients = []
sse_lock = threading.Lock()
messages_log = []
messages_lock = threading.Lock()
MAX_LOG = 500
_img_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix='img')
_hidden_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='hidden')

# ---- Emoji 缓存 (md5 → {cdn_url, aes_key, encrypt_url}) ----
_emoji_lookup = {}       # md5 → dict
_emoji_lookup_lock = threading.Lock()

_emoji_keys_dict = None  # 保存 keys 引用供刷新用
_emoji_last_refresh = 0

def _build_emoji_lookup(keys_dict):
    """从 emoticon.db 构建 emoji md5 → URL 映射（直接解密，不走 cache）"""
    global _emoji_lookup, _emoji_keys_dict, _emoji_last_refresh
    _emoji_keys_dict = keys_dict
    key_info = get_key_info(keys_dict, os.path.join("emoticon", "emoticon.db"))
    if not key_info:
        print("[emoji] 无 emoticon.db key，跳过", flush=True)
        return

    src = os.path.join(DB_DIR, "emoticon", "emoticon.db")
    if not os.path.exists(src):
        return

    import tempfile
    dst = os.path.join(tempfile.gettempdir(), "wechat_emoticon_dec.db")
    enc_key = bytes.fromhex(key_info["enc_key"])

    try:
        full_decrypt(src, dst, enc_key)
        wal = src + "-wal"
        if os.path.exists(wal):
            decrypt_wal_full(wal, dst, enc_key)
    except Exception as e:
        print(f"[emoji] emoticon.db 解密失败: {e}", flush=True)
        return

    try:
        conn = sqlite3.connect(f"file:{dst}?mode=ro", uri=True)
        new_lookup = {}

        # 1. NonStore 表情（有独立 cdn_url）
        rows = conn.execute(
            "SELECT md5, aes_key, cdn_url, encrypt_url, product_id FROM kNonStoreEmoticonTable"
        ).fetchall()
        # 收集每个 package 的 cdn_url 模板
        pkg_cdn_template = {}  # package_id → cdn_url (任意一个)
        for md5, aes_key, cdn_url, encrypt_url, product_id in rows:
            if md5:
                new_lookup[md5] = {
                    'cdn_url': cdn_url or '',
                    'aes_key': aes_key or '',
                    'encrypt_url': encrypt_url or '',
                }
            if product_id and cdn_url:
                pkg_cdn_template[product_id] = cdn_url

        non_store_count = len(new_lookup)

        # 2. Store 表情（尝试构造 cdn_url）
        store_rows = conn.execute(
            "SELECT package_id_, md5_ FROM kStoreEmoticonFilesTable"
        ).fetchall()
        store_added = 0
        for pkg_id, md5 in store_rows:
            if md5 and md5 not in new_lookup:
                # 尝试用同 package 的模板构造 URL
                template = pkg_cdn_template.get(pkg_id, '')
                if template and '&' in template:
                    # 替换 m= 参数为新 md5
                    import re
                    constructed = re.sub(r'm=[0-9a-f]+', f'm={md5}', template)
                    new_lookup[md5] = {
                        'cdn_url': constructed,
                        'aes_key': '',
                        'encrypt_url': '',
                    }
                    store_added += 1

        conn.close()
        with _emoji_lookup_lock:
            _emoji_lookup = new_lookup
        _emoji_last_refresh = time.time()
        print(f"[emoji] 已加载 {non_store_count} NonStore + {store_added} Store = {len(new_lookup)} 个表情映射", flush=True)
    except Exception as e:
        print(f"[emoji] 构建映射失败: {e}", flush=True)
    finally:
        try:
            os.unlink(dst)
        except OSError:
            pass

def _download_emoji(md5):
    """从 CDN 下载表情并缓存到 decoded_images/，返回文件名或 None"""
    with _emoji_lookup_lock:
        info = _emoji_lookup.get(md5)
    if not info:
        # Lookup miss: 刷新 emoticon.db（最多每60秒一次）
        if _emoji_keys_dict and time.time() - _emoji_last_refresh > 60:
            print(f"  [emoji] lookup miss, 刷新 emoticon.db...", flush=True)
            _build_emoji_lookup(_emoji_keys_dict)
            with _emoji_lookup_lock:
                info = _emoji_lookup.get(md5)
        if not info:
            return None

    # 先检查是否已缓存
    for ext in ('.gif', '.png', '.jpg', '.webp'):
        cached = os.path.join(DECODED_IMAGE_DIR, f"emoji_{md5}{ext}")
        if os.path.exists(cached):
            return f"emoji_{md5}{ext}"

    cdn_url = info.get('cdn_url', '')
    aes_key = info.get('aes_key', '')
    encrypt_url = info.get('encrypt_url', '')

    data = None
    # 方法1: 从 cdn_url 直接下载（未加密）
    if cdn_url:
        try:
            import urllib.request
            req = urllib.request.Request(cdn_url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=15)
            data = resp.read()
        except Exception as e:
            print(f"  [emoji] cdn下载失败 {md5[:12]}: {e}", flush=True)

    # 方法2: 从 encrypt_url 下载 + AES-CBC 解密
    if not data and encrypt_url and aes_key:
        try:
            import urllib.request
            req = urllib.request.Request(encrypt_url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=15)
            enc_data = resp.read()
            key_bytes = bytes.fromhex(aes_key)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv=key_bytes)
            data = cipher.decrypt(enc_data)
            # 去除 PKCS7 padding
            if data:
                pad = data[-1]
                if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
                    data = data[:-pad]
        except Exception as e:
            print(f"  [emoji] encrypt下载解密失败 {md5[:12]}: {e}", flush=True)

    if not data or len(data) < 4:
        return None

    # 检测格式
    if data[:3] == b'\xff\xd8\xff':
        ext = '.jpg'
    elif data[:4] == b'\x89PNG':
        ext = '.png'
    elif data[:3] == b'GIF':
        ext = '.gif'
    elif data[:4] == b'RIFF':
        ext = '.webp'
    elif data[:4] in (b'wxgf', b'wxam'):
        # WXGF/WXAM 需要转换
        ext = '.gif'
        tmp_path = os.path.join(DECODED_IMAGE_DIR, f"emoji_{md5}.wxgf")
        with open(tmp_path, 'wb') as f:
            f.write(data)
        jpg_path = _convert_hevc_to_jpeg(tmp_path, os.path.join(DECODED_IMAGE_DIR, f"emoji_{md5}.jpg"))
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        if jpg_path:
            return f"emoji_{md5}.jpg"
        return None
    else:
        ext = '.bin'

    out_name = f"emoji_{md5}{ext}"
    out_path = os.path.join(DECODED_IMAGE_DIR, out_name)
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"  [emoji] 下载缓存: {out_name} ({len(data)//1024}KB)", flush=True)
    return out_name


class MonitorDBCache:
    """轻量 DB 缓存，mtime 检测变化时重新解密（线程安全）"""

    def __init__(self, keys, tmp_dir):
        self.keys = keys
        self.tmp_dir = tmp_dir
        os.makedirs(tmp_dir, exist_ok=True)
        self._state = {}  # rel_key → (db_mtime, wal_mtime)
        self._locks = {}  # per-key 锁，防止并发解密同一 DB
        self._meta_lock = threading.Lock()

    def _get_lock(self, rel_key):
        with self._meta_lock:
            if rel_key not in self._locks:
                self._locks[rel_key] = threading.Lock()
            return self._locks[rel_key]

    def invalidate(self, rel_key):
        """强制清除缓存状态，下次 get() 会重新全量解密"""
        lock = self._get_lock(rel_key)
        with lock:
            self._state.pop(rel_key, None)

    def peek(self, rel_key):
        """返回当前已解密文件路径,**不触发**重新解密 (即使源 mtime 变了)。

        给主循环 hot path (check_updates → _lookup_latest_message) 用,
        避免每次新消息都同步等待整个 message_N.db 重新全量解密 (10s+),
        把主循环延迟从亚秒级飙到 8-125s。

        返回的路径可能 stale (滞后 1 个 mtime 周期)。调用方应能容忍 stale
        (比如查不到 latest_local_id 时跳过加 _shown_keys, 让 hidden 路径
        异步兜底)。

        get() 仍保留同步行为给真正需要最新的调用方 (hidden 路径异步线程)。
        """
        if not get_key_info(self.keys, rel_key):
            return None
        out_name = rel_key.replace('\\', '_').replace('/', '_')
        out_path = os.path.join(self.tmp_dir, out_name)
        return out_path if os.path.exists(out_path) else None

    def get(self, rel_key):
        """返回解密后的临时文件路径，mtime 变化时自动重新解密"""
        key_info = get_key_info(self.keys, rel_key)
        if not key_info:
            return None

        lock = self._get_lock(rel_key)
        with lock:
            enc_key = bytes.fromhex(key_info["enc_key"])
            rel_path = rel_key.replace('\\', '/').replace('/', os.sep)
            db_path = os.path.join(DB_DIR, rel_path)
            wal_path = db_path + "-wal"

            if not os.path.exists(db_path):
                return None

            try:
                db_mtime = os.path.getmtime(db_path)
                wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
            except OSError:
                return None

            out_name = rel_key.replace('\\', '_').replace('/', '_')
            out_path = os.path.join(self.tmp_dir, out_name)

            prev = self._state.get(rel_key)

            if prev is None or db_mtime != prev[0]:
                t0 = time.perf_counter()
                for _retry in range(3):
                    try:
                        full_decrypt(db_path, out_path, enc_key)
                        break
                    except PermissionError:
                        if _retry < 2:
                            time.sleep(1)
                        else:
                            raise
                if os.path.exists(wal_path):
                    decrypt_wal_full(wal_path, out_path, enc_key)
                ms = (time.perf_counter() - t0) * 1000
                print(f"  [cache] {rel_key} 全量解密 {ms:.0f}ms", flush=True)
                self._state[rel_key] = (db_mtime, wal_mtime)
            elif wal_mtime != prev[1]:
                t0 = time.perf_counter()
                decrypt_wal_full(wal_path, out_path, enc_key)
                ms = (time.perf_counter() - t0) * 1000
                print(f"  [cache] {rel_key} WAL patch {ms:.0f}ms", flush=True)
                self._state[rel_key] = (db_mtime, wal_mtime)

            return out_path


def build_username_db_map():
    """从已解密的 Name2Id 表构建 username → [db_keys] 映射

    同一个 username 可能存在于多个 message_N.db 中,
    按 DB 文件修改时间倒序排列（最新的排前面）。
    """
    # 先获取每个 DB 的 mtime 用于排序
    db_mtimes = {}
    for i in range(5):
        rel_key = os.path.join("message", f"message_{i}.db")
        db_path = os.path.join(DB_DIR, "message", f"message_{i}.db")
        try:
            db_mtimes[rel_key] = os.path.getmtime(db_path)
        except OSError:
            db_mtimes[rel_key] = 0

    mapping = {}  # username → [db_keys], 最新的在前
    decrypted_msg_dir = os.path.join(_cfg["decrypted_dir"], "message")
    for i in range(5):
        db_path = os.path.join(decrypted_msg_dir, f"message_{i}.db")
        if not os.path.exists(db_path):
            continue
        rel_key = os.path.join("message", f"message_{i}.db")
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            for row in conn.execute("SELECT user_name FROM Name2Id").fetchall():
                if row[0] not in mapping:
                    mapping[row[0]] = []
                mapping[row[0]].append(rel_key)
            conn.close()
        except Exception as e:
            print(f"  [WARN] Name2Id message_{i}.db: {e}", flush=True)

    # 对每个 username 的 db_keys 按 mtime 倒序（最新的优先）
    for username in mapping:
        mapping[username].sort(key=lambda k: db_mtimes.get(k, 0), reverse=True)

    return mapping


def decrypt_page(enc_key, page_data, pgno):
    """解密单个加密页面"""
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + 16]
    if pgno == 1:
        encrypted = page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ)
    else:
        encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def full_decrypt(db_path, out_path, enc_key):
    """首次全量解密"""
    t0 = time.perf_counter()
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break
            fout.write(decrypt_page(enc_key, page, pgno))

    ms = (time.perf_counter() - t0) * 1000
    return total_pages, ms


def decrypt_wal_full(wal_path, out_path, enc_key):
    """解密WAL当前有效frame，patch到已解密的DB副本

    WAL是预分配固定大小(4MB)，包含当前有效frame和上一轮遗留的旧frame。
    通过WAL header中的salt值区分：只有frame header的salt匹配WAL header的才是有效frame。

    返回: (patched_pages, elapsed_ms)
    """
    t0 = time.perf_counter()

    if not os.path.exists(wal_path):
        return 0, 0

    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HEADER_SZ:
        return 0, 0

    frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ  # 24 + 4096 = 4120
    patched = 0

    with open(wal_path, 'rb') as wf, open(out_path, 'r+b') as df:
        # 读WAL header，获取当前salt值
        wal_hdr = wf.read(WAL_HEADER_SZ)
        wal_salt1 = struct.unpack('>I', wal_hdr[16:20])[0]
        wal_salt2 = struct.unpack('>I', wal_hdr[20:24])[0]

        while wf.tell() + frame_size <= wal_size:
            fh = wf.read(WAL_FRAME_HEADER_SZ)
            if len(fh) < WAL_FRAME_HEADER_SZ:
                break
            pgno = struct.unpack('>I', fh[0:4])[0]
            frame_salt1 = struct.unpack('>I', fh[8:12])[0]
            frame_salt2 = struct.unpack('>I', fh[12:16])[0]

            ep = wf.read(PAGE_SZ)
            if len(ep) < PAGE_SZ:
                break

            # 校验: pgno有效 且 salt匹配当前WAL周期
            if pgno == 0 or pgno > 1000000:
                continue
            if frame_salt1 != wal_salt1 or frame_salt2 != wal_salt2:
                continue  # 旧周期遗留的frame，跳过

            dec = decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)
            patched += 1

    ms = (time.perf_counter() - t0) * 1000
    return patched, ms


_global_contact_names = None
_global_contact_full = None
_global_contact_db_mtime = 0
_global_contact_lock = threading.Lock()


def _get_contact_db_path_with_cache(db_cache):
    """获取 contact.db 路径, 通过 mtime 检测变化时刷新缓存。

    优先用 db_cache（实时解密），fallback 到静态 CONTACT_CACHE。
    """
    global _global_contact_db_mtime, _global_contact_names, _global_contact_full

    if db_cache:
        try:
            contact_path = db_cache.get(os.path.join("contact", "contact.db"))
            if contact_path and os.path.exists(contact_path):
                curr_mtime = os.path.getmtime(contact_path)
                if curr_mtime != _global_contact_db_mtime:
                    _global_contact_db_mtime = curr_mtime
                    _global_contact_names = None
                    _global_contact_full = None
                return contact_path
        except Exception:
            pass

    pre = CONTACT_CACHE
    if os.path.exists(pre):
        try:
            curr_mtime = os.path.getmtime(pre)
            if curr_mtime != _global_contact_db_mtime:
                _global_contact_db_mtime = curr_mtime
                _global_contact_names = None
                _global_contact_full = None
            return pre
        except Exception:
            pass

    return None


def load_contact_names(db_path=None):
    """加载联系人名字字典 (线程安全，带缓存)。

    Args:
        db_path: 指定的 contact.db 路径。None 则自动检测最新来源。
                 实时场景建议配合 _get_contact_db_path_with_cache 使用。
    """
    global _global_contact_names, _global_contact_full

    if _global_contact_names is not None:
        return _global_contact_names.copy()

    names = {}
    full = []
    db_to_load = db_path or CONTACT_CACHE
    if not os.path.exists(db_to_load):
        with _global_contact_lock:
            if _global_contact_names is None:
                _global_contact_names = {}
                _global_contact_full = []
        return {}

    try:
        conn = sqlite3.connect(db_to_load)
        for r in conn.execute("SELECT username, nick_name, remark FROM contact").fetchall():
            username, nick_name, remark = r[0], r[1], r[2]
            display = remark if remark else nick_name if nick_name else username
            names[username] = display
            full.append({
                "username": username,
                "nick_name": nick_name or "",
                "remark": remark or "",
                "display_name": display,
            })
        conn.close()
    except Exception:
        pass

    with _global_contact_lock:
        if _global_contact_names is None:
            _global_contact_names = names
            _global_contact_full = full

    return names.copy()


def load_contact_full(db_path=None):
    """加载完整联系人信息列表，包含 username、nick_name、remark 等字段。

    Args:
        db_path: 指定的 contact.db 路径。None 则自动检测最新来源。
    """
    global _global_contact_full

    if _global_contact_full is not None:
        return list(_global_contact_full)

    load_contact_names(db_path)
    return list(_global_contact_full) if _global_contact_full else []


def _build_contact_lookup(db_cache=None):
    """构建 username -> {nick_name, remark, display_name} 的快速查找字典。

    优先使用 db_cache 实时解密，fallback 到静态缓存。
    """
    db_path = _get_contact_db_path_with_cache(db_cache)
    if db_path is None:
        return {}

    if _global_contact_full is None or _global_contact_names is None:
        load_contact_names(db_path)

    lookup = {}
    for contact in (_global_contact_full or []):
        uname = contact.get("username", "")
        if uname:
            lookup[uname] = {
                "nick_name": contact.get("nick_name", ""),
                "remark": contact.get("remark", ""),
                "display_name": contact.get("display_name", uname),
            }
    return lookup


def invalidate_contact_cache():
    """强制清除联系人缓存，下次调用 load_contact_names 时重新加载"""
    global _global_contact_names, _global_contact_full, _global_contact_db_mtime
    with _global_contact_lock:
        _global_contact_names = None
        _global_contact_full = None
        _global_contact_db_mtime = 0


def _extract_pb_field_30(data):
    """从 extra_buffer (protobuf) 中提取 Field #30 的字符串值（联系人标签ID）"""
    if not data:
        return None
    pos = 0
    n = len(data)
    while pos < n:
        tag = 0
        shift = 0
        while pos < n:
            b = data[pos]; pos += 1
            tag |= (b & 0x7f) << shift
            if not (b & 0x80):
                break
            shift += 7
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:
            while pos < n and data[pos] & 0x80:
                pos += 1
            pos += 1
        elif wire_type == 2:
            length = 0; shift = 0
            while pos < n:
                b = data[pos]; pos += 1
                length |= (b & 0x7f) << shift
                if not (b & 0x80):
                    break
                shift += 7
            if field_num == 30:
                try:
                    return data[pos:pos + length].decode('utf-8')
                except Exception:
                    return None
            pos += length
        elif wire_type == 1:
            pos += 8
        elif wire_type == 5:
            pos += 4
        else:
            break
    return None


def load_contact_tags():
    """加载联系人标签及其成员"""
    try:
        conn = sqlite3.connect(CONTACT_CACHE)
        try:
            label_rows = conn.execute(
                "SELECT label_id_, label_name_, sort_order_ FROM contact_label ORDER BY sort_order_"
            ).fetchall()
        except Exception:
            conn.close()
            return []
        if not label_rows:
            conn.close()
            return []

        labels = {}
        for lid, lname, sort_order in label_rows:
            labels[lid] = {'id': lid, 'name': lname, 'sort_order': sort_order, 'members': []}

        names = load_contact_names()
        rows = conn.execute(
            "SELECT username, extra_buffer FROM contact WHERE extra_buffer IS NOT NULL"
        ).fetchall()
        conn.close()

        for username, buf in rows:
            label_str = _extract_pb_field_30(buf)
            if not label_str:
                continue
            display = names.get(username, username)
            for lid_s in label_str.split(','):
                try:
                    lid = int(lid_s.strip())
                except (ValueError, AttributeError):
                    continue
                if lid in labels:
                    labels[lid]['members'].append({'username': username, 'display_name': display})

        result = sorted(labels.values(), key=lambda t: t['sort_order'])
        for t in result:
            t['member_count'] = len(t['members'])
        return result
    except Exception:
        return []


def format_msg_type(t):
    return {
        1: '文本', 3: '图片', 34: '语音', 42: '名片',
        43: '视频', 47: '表情', 48: '位置', 49: '链接/文件',
        50: '通话', 10000: '系统', 10002: '撤回',
    }.get(t, f'type={t}')


def msg_type_icon(t):
    return {
        1: '💬', 3: '🖼️', 34: '🎤', 42: '👤',
        43: '🎬', 47: '😀', 48: '📍', 49: '🔗',
        50: '📞', 10000: '⚙️', 10002: '↩️',
    }.get(t, '📨')


def broadcast_sse(msg_data):
    event_type = msg_data.get('event', '')
    data_line = f"data: {json.dumps(msg_data, ensure_ascii=False)}\n"
    if event_type:
        payload = f"event: {event_type}\n{data_line}\n"
    else:
        payload = f"{data_line}\n"
    with sse_lock:
        dead = []
        for q in sse_clients:
            try:
                q.put_nowait(payload)
            except:
                dead.append(q)
        for q in dead:
            sse_clients.remove(q)


def _convert_hevc_to_jpeg(hevc_path, jpeg_path):
    """将 wxgf/HEVC 文件转为 JPEG

    wxgf 是微信自有格式: wxgf header + ICC profile + HEVC NAL units
    通过扫描 HEVC VPS start code (00 00 00 01 40 01) 定位 Annex B 流，
    再用 PyAV (ffmpeg) 解码首帧为 JPEG。
    """
    try:
        import av

        with open(hevc_path, 'rb') as f:
            data = f.read()

        # 扫描 HEVC Annex B VPS start code: 00 00 00 01 40 01
        vps_sig = b'\x00\x00\x00\x01\x40\x01'
        hevc_start = data.find(vps_sig)
        if hevc_start < 0:
            # fallback: 找 SPS (00 00 00 01 42 01)
            hevc_start = data.find(b'\x00\x00\x00\x01\x42\x01')
        if hevc_start < 0:
            print(f"  [img] wxgf 中未找到 HEVC VPS/SPS", flush=True)
            return None

        # 提取 HEVC Annex B 流并用 PyAV 解码
        h265_path = hevc_path + '.h265'
        with open(h265_path, 'wb') as f:
            f.write(data[hevc_start:])

        try:
            container = av.open(h265_path, format='hevc')
            for frame in container.decode(video=0):
                img = frame.to_image()
                img.save(jpeg_path, "JPEG", quality=90)
                container.close()
                return jpeg_path
            container.close()
        finally:
            if os.path.exists(h265_path):
                os.unlink(h265_path)

    except ImportError:
        print(f"  [img] 需要 PyAV: pip install av", flush=True)
    except Exception as e:
        print(f"  [img] HEVC→JPEG 失败: {e}", flush=True)
    return None


# ============ 监听器 ============

class SessionMonitor:
    # 改名/备注变更场景的刷新最小间隔（秒）。低于此间隔的 mtime 变化不触发
    # 全量 reload，避免微信高频写 contact.db 时 CPU 抖动。30s 是经验值。
    CONTACT_REFRESH_COOLDOWN = 30

    def __init__(self, enc_key, session_db, contact_names, db_cache=None, username_db_map=None):
        self.enc_key = enc_key
        self.session_db = session_db
        self.wal_path = session_db + "-wal"
        self.contact_names = contact_names
        self.db_cache = db_cache
        self.username_db_map = username_db_map or {}
        self.prev_state = {}
        self.decrypt_ms = 0
        self.patched_pages = 0
        # 已显示消息去重: {(username, timestamp, base_msg_type), ...}
        self._shown_keys = set()
        # contact.db mtime + 上次刷新时间，用于检测改名/备注变更
        self._contact_db_mtime = 0
        self._last_contact_refresh = 0

    def _maybe_refresh_contacts(self):
        """检测 contact.db mtime 变化时全量 reload 联系人缓存。

        覆盖三种变更场景:
        - 新增联系人（之前 commit e86e00d 只覆盖了这种）
        - 修改备注名（issue #67）
        - 修改群名

        受 CONTACT_REFRESH_COOLDOWN 节流，避免 contact.db 高频变更时反复 reload。
        """
        if not self.db_cache:
            return
        try:
            contact_path = self.db_cache.get(os.path.join("contact", "contact.db"))
        except Exception as e:
            print(f"  [contact] 实时解密 contact.db 失败: {e}", flush=True)
            return
        if not contact_path:
            return
        try:
            curr_mtime = os.path.getmtime(contact_path)
        except OSError:
            return
        now = time.time()
        if curr_mtime <= self._contact_db_mtime:
            return  # mtime 没变，跳过
        if now - self._last_contact_refresh < self.CONTACT_REFRESH_COOLDOWN:
            return  # cooldown 中，等下次
        refreshed = load_contact_names(contact_path)
        if refreshed:
            self.contact_names.update(refreshed)
        self._contact_db_mtime = curr_mtime
        self._last_contact_refresh = now

    def resolve_image(self, username, timestamp):
        """解密图片: username+timestamp → 解密后的图片文件名，失败返回 None"""
        if not self.db_cache or not self.username_db_map:
            return None

        # 1. 找到 username 对应的所有 message_N.db（按 mtime 倒序）
        db_keys = self.username_db_map.get(username)
        if not db_keys:
            return None

        # 2. 遍历候选 DB，找到包含该 timestamp 消息的那个
        table_name = f"Msg_{hashlib.md5(username.encode()).hexdigest()}"
        local_id = None
        for db_key in db_keys:
            for _try in range(2):
                msg_db_path = self.db_cache.get(db_key)
                if not msg_db_path:
                    break
                try:
                    conn = sqlite3.connect(f"file:{msg_db_path}?mode=ro", uri=True)
                    # 微信4.0 图片的 local_type 可能是复合编码: (sub<<32)|3
                    row = conn.execute(f"""
                        SELECT local_id FROM [{table_name}]
                        WHERE (local_type = 3 OR (local_type > 4294967296 AND local_type % 4294967296 = 3))
                        AND create_time = ?
                    """, (timestamp,)).fetchone()
                    if not row:
                        row = conn.execute(f"""
                            SELECT local_id FROM [{table_name}]
                            WHERE (local_type = 3 OR (local_type > 4294967296 AND local_type % 4294967296 = 3))
                            AND ABS(create_time - ?) <= 3
                            ORDER BY ABS(create_time - ?) LIMIT 1
                        """, (timestamp, timestamp)).fetchone()
                    conn.close()
                    if row:
                        local_id = row[0]
                    break
                except Exception as e:
                    if 'malformed' in str(e) and _try == 0:
                        print(f"  [img] {db_key} malformed, 强制刷新...", flush=True)
                        self.db_cache.invalidate(db_key)
                        continue
                    if 'no such table' not in str(e):
                        print(f"  [img] 查询 {db_key}/{table_name} 失败: {e}", flush=True)
                    break
            if local_id:
                break

        if not local_id:
            print(f"  [img] 未找到 local_id: {username} t={timestamp}", flush=True)
            return None

        # 4. 查 message_resource.db 获取 MD5
        #    local_id 不全局唯一，需要同时匹配 create_time
        file_md5 = None
        for _try in range(2):
            res_path = self.db_cache.get(os.path.join("message", "message_resource.db"))
            if not res_path:
                return None
            try:
                conn = sqlite3.connect(f"file:{res_path}?mode=ro", uri=True)
                row = conn.execute(
                    "SELECT packed_info FROM MessageResourceInfo "
                    "WHERE message_local_id = ? AND message_create_time = ? "
                    "AND (message_local_type = 3 OR message_local_type % 4294967296 = 3)",
                    (local_id, timestamp)
                ).fetchone()
                if not row:
                    row = conn.execute(
                        "SELECT packed_info FROM MessageResourceInfo "
                        "WHERE message_create_time = ? "
                        "AND (message_local_type = 3 OR message_local_type % 4294967296 = 3)",
                        (timestamp,)
                    ).fetchone()
                conn.close()
                if row and row[0]:
                    file_md5 = extract_md5_from_packed_info(row[0])
                break
            except Exception as e:
                if 'malformed' in str(e) and _try == 0:
                    print(f"  [img] resource DB malformed, 强制刷新...", flush=True)
                    self.db_cache.invalidate(os.path.join("message", "message_resource.db"))
                    continue
                print(f"  [img] 查询 message_resource 失败: {e}", flush=True)
                return None

        if not file_md5:
            print(f"  [img] 未找到 MD5: local_id={local_id} t={timestamp}", flush=True)
            return None

        # 5. 查找 .dat 文件
        attach_dir = os.path.join(WECHAT_BASE_DIR, "msg", "attach")
        username_hash = hashlib.md5(username.encode()).hexdigest()
        search_base = os.path.join(attach_dir, username_hash)

        if not os.path.isdir(search_base):
            print(f"  [img] attach 目录不存在: {search_base}", flush=True)
            return None

        pattern = os.path.join(search_base, "*", "Img", f"{file_md5}*.dat")
        dat_files = sorted(glob_mod.glob(pattern))
        if not dat_files:
            print(f"  [img] 未找到 .dat: MD5={file_md5}", flush=True)
            return None

        # 分类 .dat 文件
        # 优先级: 原图.dat(最大) > _h.dat > _W.dat > _t.dat(缩略图)
        ranked = []
        for f in dat_files:
            fname = os.path.basename(f).lower()
            sz = os.path.getsize(f)
            if '_t_' in fname:
                rank = 5  # _t_W.dat 缩略图变体
            elif '_t.' in fname:
                rank = 4  # _t.dat 缩略图
            elif '_w.' in fname:
                rank = 2  # _W.dat (V2 可转 JPEG)
            elif '_h.' in fname:
                rank = 1  # 高清
            elif fname == f"{file_md5}.dat".lower():
                rank = 0  # 原图 (最优先)
            else:
                rank = 0
            ranked.append((rank, sz, f))
        ranked.sort(key=lambda x: (x[0], -x[1]))

        # 6. 解密图片
        os.makedirs(DECODED_IMAGE_DIR, exist_ok=True)
        out_base = os.path.join(DECODED_IMAGE_DIR, file_md5)
        rank_names = {0: 'orig', 1: 'h', 2: 'W', 4: 't', 5: 't_W'}
        browser_formats = ('jpg', 'png', 'gif', 'webp')

        # 已有可用缓存则跳过
        for ext in browser_formats:
            candidate = f"{out_base}.{ext}"
            if os.path.exists(candidate):
                cached_sz = os.path.getsize(candidate)
                best_rank = ranked[0][0] if ranked else 99
                if cached_sz > 20480 or best_rank >= 4:
                    return os.path.basename(candidate)
                os.unlink(candidate)
                print(f"  [img] 缩略图升级: {cached_sz/1024:.0f}KB → 重解密", flush=True)
                break

        for rank, sz, selected in ranked:
            sel_type = rank_names.get(rank, '?')
            print(f"  [img] 尝试 {sel_type}({sz/1024:.0f}KB): {os.path.basename(selected)}", flush=True)

            if is_v2_format(selected) and not IMAGE_AES_KEY:
                print(f"  [img] V2 格式缺少 AES key, 跳过", flush=True)
                continue

            result_path, fmt = decrypt_dat_file(selected, f"{out_base}.tmp", IMAGE_AES_KEY, IMAGE_XOR_KEY)
            if not result_path:
                print(f"  [img] 解密失败, 跳过", flush=True)
                continue

            # HEVC/wxgf → 用 pillow-heif 转 JPEG
            if fmt in ('hevc', 'bin'):
                jpg_path = _convert_hevc_to_jpeg(result_path, f"{out_base}.jpg")
                os.unlink(result_path)
                if jpg_path:
                    size_kb = os.path.getsize(jpg_path) / 1024
                    print(f"  [img] HEVC→JPEG 成功: {os.path.basename(jpg_path)} ({size_kb:.0f}KB)", flush=True)
                    return os.path.basename(jpg_path)
                print(f"  [img] HEVC→JPEG 转换失败, 尝试下一个", flush=True)
                continue

            final = f"{out_base}.{fmt}"
            if os.path.exists(final):
                os.unlink(final)
            os.rename(result_path, final)
            size_kb = os.path.getsize(final) / 1024
            print(f"  [img] 解密成功: {os.path.basename(final)} ({size_kb:.0f}KB)", flush=True)
            return os.path.basename(final)

        print(f"  [img] 所有 .dat 均无法解密", flush=True)
        return '__v2_unsupported__'

    def _async_resolve_image(self, username, timestamp, msg_data):
        """后台线程: 解密图片并通过 SSE 推送更新"""
        delays = [0.3, 1.0, 2.0]
        for attempt in range(3):
            try:
                img_name = self.resolve_image(username, timestamp)
                if img_name == '__v2_unsupported__':
                    msg_data['content'] = '[图片 - 新加密格式暂不支持预览]'
                    broadcast_sse({
                        'event': 'image_update',
                        'timestamp': timestamp,
                        'username': username,
                        'v2_unsupported': True,
                    })
                    return
                elif img_name:
                    image_url = f'/img/{img_name}'
                    msg_data['image_url'] = image_url
                    broadcast_sse({
                        'event': 'image_update',
                        'timestamp': timestamp,
                        'username': username,
                        'image_url': image_url,
                    })
                    print(f"  [img] 异步解密成功: {img_name}", flush=True)
                    return
                elif attempt < 2:
                    time.sleep(delays[attempt])
            except Exception as e:
                print(f"  [img] 异步解密失败(attempt={attempt}): {e}", flush=True)
                if attempt < 2:
                    time.sleep(delays[attempt])

    def _fresh_decrypt_query(self, db_key, table_name, prev_ts, curr_ts):
        """独立解密 message DB 到临时文件并查询，避免共享缓存竞态"""
        key_info = get_key_info(self.db_cache.keys, db_key)
        if not key_info:
            return []
        enc_key = bytes.fromhex(key_info["enc_key"])
        rel_path = db_key.replace('\\', '/').replace('/', os.sep)
        db_path = os.path.join(DB_DIR, rel_path)
        wal_path = db_path + "-wal"
        if not os.path.exists(db_path):
            return []

        import tempfile
        fd, tmp_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        try:
            t0 = time.perf_counter()
            full_decrypt(db_path, tmp_path, enc_key)
            if os.path.exists(wal_path):
                decrypt_wal_full(wal_path, tmp_path, enc_key)
            ms = (time.perf_counter() - t0) * 1000
            print(f"  [hidden] {db_key} 独立解密 {ms:.0f}ms", flush=True)

            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            rows = conn.execute(f"""
                SELECT create_time, local_type, message_content, WCDB_CT_message_content
                FROM [{table_name}]
                WHERE create_time >= ? AND create_time <= ?
                ORDER BY create_time ASC
            """, (prev_ts, curr_ts)).fetchall()
            conn.close()
            return rows
        except Exception as e:
            print(f"  [hidden] {db_key} 独立解密失败: {e}", flush=True)
            return []
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _lookup_latest_message(self, username, timestamp):
        """从 message_N.db 查指定 username 在 timestamp 的最新一条消息，返回
        (local_id, message_content)。

        SessionTable 推送时调用：
        - local_id 加入 _shown_keys，供 `_check_hidden_messages` 精确去重 (issue #79)
        - message_content 用于替换 SessionTable.summary 的 ~80 字短截断 (issue #42)

        两者本就同行，合并到一次 SELECT，相比原 MAX(local_id) 不增加 IO。

        时机风险：SessionTable 写入比 message DB 早几毫秒，可能查不到。查不到时返回
        (None, None)，调用方跳过加 key，由 `_check_hidden_messages` 兜底。
        """
        if not self.db_cache or not self.username_db_map:
            return None, None
        db_keys = self.username_db_map.get(username, [])
        if not db_keys:
            return None, None
        table_name = f"Msg_{hashlib.md5(username.encode()).hexdigest()}"
        for db_key in db_keys:
            # 用 peek 不触发同步解密 (主线程 hot path)。如果缓存还 stale
            # 没 latest_local_id, 让 hidden 异步路径稍后兜底加 _shown_keys。
            # 见 MonitorDBCache.peek 注释关于为什么这里不能用 .get。
            dec_path = self.db_cache.peek(db_key)
            if not dec_path:
                continue
            try:
                with closing(sqlite3.connect(f"file:{dec_path}?mode=ro&immutable=1", uri=True)) as conn:
                    row = conn.execute(
                        f"SELECT local_id, message_content, WCDB_CT_message_content "
                        f"FROM [{table_name}] WHERE create_time = ? "
                        f"ORDER BY local_id DESC LIMIT 1",
                        (timestamp,),
                    ).fetchone()
                    if row and row[0]:
                        local_id, mc, ct = row
                        if isinstance(mc, bytes) and ct == 4:
                            try:
                                mc = _zstd_dctx.decompress(mc).decode('utf-8', errors='replace')
                            except Exception:
                                mc = mc.decode('utf-8', errors='replace')
                        elif isinstance(mc, bytes):
                            mc = mc.decode('utf-8', errors='replace')
                        # 群消息 message_content 形如 'wxid_xxx:\n<正文>'，与
                        # SessionTable.summary 调用方一致地剥离前缀
                        if mc and ':\n' in mc:
                            mc = mc.split(':\n', 1)[1]
                        return local_id, mc
            except Exception:
                continue
        return None, None

    def _check_hidden_messages(self, username, prev_ts, curr_ts, curr_msg_type, display, is_group, sender, local_id=None):
        """检查时间窗口内是否有被 session 摘要覆盖的消息（文字、图片、表情等）

        先用共享缓存查询（快），失败或可疑时用独立解密（慢但可靠）。
        local_id: 从 SessionTable 最新消息对应的 local_id（可能因缓存过期为 None）
        """
        if not self.username_db_map:
            return
        db_keys = self.username_db_map.get(username)
        if not db_keys:
            return

        # 防止 _lookup_latest_message 因缓存过期返回 None 导致消息被重复发送
        # 如果主循环已查到 local_id，先加入 _shown_keys
        if local_id is not None:
            self._shown_keys.add((username, local_id))

        table_name = f"Msg_{hashlib.md5(username.encode()).hexdigest()}"
        print(f"  [hidden] 检查 {display[:15]} prev_ts={prev_ts} curr_ts={curr_ts} type={curr_msg_type}", flush=True)

        # 等待 message DB 写入完成
        time.sleep(1.0)

        # 快速路径: 用共享缓存查询（带重试）
        all_rows = []
        cache_failed = False
        for _try in range(3):
            all_rows.clear()
            if self.db_cache:
                for db_key in db_keys:
                    dec_path = self.db_cache.get(db_key)
                    if not dec_path:
                        continue
                    try:
                        conn = sqlite3.connect(f"file:{dec_path}?mode=ro", uri=True)
                        rows = conn.execute(f"""
                            SELECT local_id, create_time, local_type, message_content, WCDB_CT_message_content
                            FROM [{table_name}]
                            WHERE create_time >= ? AND create_time <= ?
                            ORDER BY create_time ASC, local_id ASC
                        """, (prev_ts, curr_ts)).fetchall()
                        conn.close()
                        all_rows.extend(rows)
                    except Exception as e:
                        print(f"  [hidden] 缓存查询失败 {db_key}: {e}", flush=True)
                        cache_failed = True
                        break
            # 检查是否找到了 curr_ts 的消息（说明缓存是最新的）
            # 注: r[1] 是 create_time（新 schema：local_id, create_time, local_type, ...）
            has_curr = any(r[1] == curr_ts for r in all_rows)
            if has_curr or cache_failed:
                break
            # 缓存可能还没更新到最新数据，短暂等待后重试
            if _try < 2:
                time.sleep(1.5)
                print(f"  [hidden] 缓存未包含最新消息，重试({_try+1})...", flush=True)

        # 仅在缓存查询出错时才用昂贵的独立解密
        if cache_failed:
            print(f"  [hidden] 缓存异常，启动独立解密...", flush=True)
            all_rows = []
            for db_key in db_keys:
                rows = self._fresh_decrypt_query(db_key, table_name, prev_ts, curr_ts)
                all_rows.extend(rows)
                if rows:
                    break
        else:
            print(f"  [hidden] 缓存查到 {len(all_rows)} 条", flush=True)

        # 过滤出隐藏消息
        # 去重 key 用 local_id（之前用 (username, ts, base) 太粗，同秒同类型多条会被
        # 误判为重复，导致 issue #79 的 "10 丢 4"）
        hidden_msgs = []
        exclude_lid = local_id  # 当前正在处理的 local_id（主循环已广播）
        for local_id, ts, lt, mc, ct in all_rows:
            base = lt % 4294967296 if lt > 4294967296 else lt
            # 跳过已显示的消息（按 local_id 精确去重）
            if (username, local_id) in self._shown_keys:
                continue
            # 跳过当前正在处理的 local_id（主循环通过 SessionTable 更新触发，
            # 已经在 check_updates 中通过 broadcast_sse 发送过了，避免重复）
            if exclude_lid is not None and local_id == exclude_lid:
                continue
            # 解压 zstd
            if isinstance(mc, bytes) and ct == 4:
                try:
                    mc = _zstd_dctx.decompress(mc).decode('utf-8', errors='replace')
                except Exception:
                    mc = mc.decode('utf-8', errors='replace') if isinstance(mc, bytes) else ''
            elif isinstance(mc, bytes):
                mc = mc.decode('utf-8', errors='replace')
            hidden_msgs.append((local_id, ts, base, mc or ''))

        print(f"  [hidden] 找到 {len(hidden_msgs)} 条隐藏消息", flush=True)

        if not hidden_msgs:
            return

        global messages_log
        for local_id, ts, base, mc in hidden_msgs:
            self._shown_keys.add((username, local_id))
            msg_data = {
                'time': datetime.fromtimestamp(ts).strftime('%H:%M:%S'),
                'timestamp': ts,
                'chat': display,
                'username': username,
                'is_group': is_group,
                'sender': sender,
            }
            if base == 3:
                # 隐藏的图片消息
                time.sleep(0.5)
                img_name = self.resolve_image(username, ts)
                if img_name and img_name != '__v2_unsupported__':
                    msg_data.update({
                        'type': '图片', 'type_icon': '\U0001f5bc\ufe0f',
                        'content': '', 'image_url': f'/img/{img_name}',
                    })
                    print(f"  [hidden] 补充图片: {img_name} t={ts}", flush=True)
                else:
                    continue
            elif base == 1:
                # 隐藏的文字消息
                msg_data.update({
                    'type': '文本', 'type_icon': '\U0001f4ac',
                    'content': mc,
                })
                print(f"  [hidden] 补充文字: {mc[:30]} t={ts}", flush=True)
            elif base == 47:
                rich = self.resolve_rich_content(username, ts, 47)
                msg_data.update({
                    'type': '表情', 'type_icon': '\U0001f600',
                    'content': '[表情]',
                })
                if rich:
                    msg_data['rich'] = rich
                print(f"  [hidden] 补充表情 t={ts}", flush=True)
            elif base == 49:
                rich = self.resolve_rich_content(username, ts, 49)
                msg_data.update({
                    'type': format_msg_type(base), 'type_icon': msg_type_icon(base),
                    'content': mc[:100] if mc else '',
                })
                if rich:
                    msg_data['rich'] = rich
                print(f"  [hidden] 补充富媒体 t={ts}", flush=True)
            else:
                # 其他类型
                msg_data.update({
                    'type': format_msg_type(base), 'type_icon': msg_type_icon(base),
                    'content': mc[:100] if mc else f'[{format_msg_type(base)}]',
                })
                print(f"  [hidden] 补充type={base} t={ts}", flush=True)

            with messages_lock:
                messages_log.append(msg_data)
                if len(messages_log) > MAX_LOG:
                    messages_log = messages_log[-MAX_LOG:]
            broadcast_sse(msg_data)

    def _query_msg_content(self, username, timestamp, base_type):
        """通用: 从 message_*.db 查找指定类型消息的 XML 内容

        base_type: 基础类型 (47, 49, 43, 34 等)
        微信4.0 的 local_type 是复合编码: (sub_type << 32) | base_type
        """
        db_keys = self.username_db_map.get(username, [])
        if not db_keys:
            return None

        tbl = f"Msg_{hashlib.md5(username.encode()).hexdigest()}"
        for dk in db_keys:
            for _try in range(2):
                dec_path = self.db_cache.get(dk)
                if not dec_path:
                    break
                try:
                    conn = sqlite3.connect(f"file:{dec_path}?mode=ro", uri=True)
                    row = conn.execute(f'''
                        SELECT message_content, WCDB_CT_message_content, local_type
                        FROM "{tbl}"
                        WHERE (local_type = ? OR (local_type > 4294967296 AND local_type % 4294967296 = ?))
                        AND create_time BETWEEN ? AND ?
                        ORDER BY create_time DESC LIMIT 1
                    ''', (base_type, base_type, timestamp - 5, timestamp + 5)).fetchone()
                    conn.close()

                    if not row:
                        break  # 表存在但没找到匹配行，换下一个 DB
                    mc, ct_flag, full_type = row
                    if isinstance(mc, bytes) and ct_flag == 4:
                        mc = _zstd_dctx.decompress(mc).decode('utf-8', errors='replace')
                    elif isinstance(mc, bytes):
                        mc = mc.decode('utf-8', errors='replace')
                    if not mc:
                        break

                    xml_start = mc.find('<msg>')
                    if xml_start < 0:
                        xml_start = mc.find('<msg\n')
                    if xml_start < 0:
                        xml_start = mc.find('<?xml')
                    if xml_start > 0:
                        mc = mc[xml_start:]

                    return mc, full_type

                except Exception as e:
                    if 'malformed' in str(e) and _try == 0:
                        print(f"  [rich] {dk} malformed, 强制刷新...", flush=True)
                        self.db_cache.invalidate(dk)
                        continue
                    if 'no such table' not in str(e):
                        print(f"  [rich] 查询 {dk} 失败: {e}", flush=True)
                    break
        return None

    def _parse_rich_content(self, username, timestamp, msg_type):
        """解析富媒体消息, 返回 dict 或 None"""
        import xml.etree.ElementTree as ET

        if msg_type == 47:
            result = self._query_msg_content(username, timestamp, 47)
            if not result:
                print(f"  [emoji] 查询失败 user={username[:10]} ts={timestamp}", flush=True)
                return None
            mc, _ = result
            if '<emoji' not in mc:
                return None
            try:
                root = ET.fromstring(mc)
                emoji = root.find('.//emoji')
                if emoji is None:
                    return None
                md5 = emoji.get('md5', '')
                etype = emoji.get('type', '')
                url = emoji.get('thumburl') or emoji.get('externurl') or emoji.get('cdnurl') or ''
                url = url.replace('&amp;', '&')
                if url and url.startswith('http'):
                    print(f"  [emoji] XML有URL md5={md5[:12] if md5 else 'N/A'} type={etype}", flush=True)
                    return {'type': 'emoji', 'emoji_url': url}
                if md5:
                    with _emoji_lookup_lock:
                        in_lookup = md5 in _emoji_lookup
                        lookup_size = len(_emoji_lookup)
                    print(f"  [emoji] XML无URL md5={md5[:12]} type={etype} lookup={lookup_size} found={in_lookup}", flush=True)
                    img_name = _download_emoji(md5)
                    if img_name:
                        return {'type': 'emoji', 'emoji_url': f'/img/{img_name}'}
                    print(f"  [emoji] 下载失败 md5={md5[:12]}, 返回fallback图标", flush=True)
                    return {'type': 'emoji', 'emoji_url': None}
                else:
                    print(f"  [emoji] 无md5 type={etype}, 返回fallback图标", flush=True)
                    return {'type': 'emoji', 'emoji_url': None}
            except ET.ParseError:
                pass
            return None

        elif msg_type == 49:
            # --- 链接/文件/引用/公众号/小程序 ---
            result = self._query_msg_content(username, timestamp, 49)
            if not result:
                return None
            mc, full_type = result
            sub_type = full_type >> 32 if full_type > 4294967296 else 0
            if '<appmsg' not in mc:
                return None
            try:
                root = ET.fromstring(mc)
                appmsg = root.find('.//appmsg')
                if appmsg is None:
                    return None
                title = (appmsg.findtext('title') or '').strip()
                des = (appmsg.findtext('des') or '').strip()
                url = (appmsg.findtext('url') or '').strip().replace('&amp;', '&')
                app_type = int(appmsg.findtext('type') or sub_type or 0)

                if app_type == 57:
                    # 引用回复: title 是回复内容
                    ref = appmsg.find('.//refermsg')
                    ref_name = ref.findtext('displayname') if ref is not None else ''
                    ref_content = ref.findtext('content') if ref is not None else ''
                    if ref_content:
                        ref_content = ref_content.strip()[:100]
                    return {
                        'type': 'quote',
                        'title': title,
                        'ref_name': ref_name or '',
                        'ref_content': ref_content or '',
                    }
                elif app_type == 6:
                    # 文件
                    attach = appmsg.find('.//appattach')
                    size = int(attach.findtext('totallen') or 0) if attach is not None else 0
                    ext = (attach.findtext('fileext') or '') if attach is not None else ''
                    return {
                        'type': 'file',
                        'title': title,
                        'file_ext': ext,
                        'file_size': size,
                    }
                elif app_type == 5:
                    # 链接/文章 — 清理 tracking 参数
                    clean_url = url
                    if 'mp.weixin.qq.com' in url:
                        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                        pu = urlparse(url)
                        params = parse_qs(pu.query, keep_blank_values=False)
                        # 只保留文章必要参数
                        keep = {k: v for k, v in params.items()
                                if k in ('__biz', 'mid', 'idx', 'sn', 'chksm')}
                        clean_url = urlunparse(pu._replace(
                            query=urlencode(keep, doseq=True), fragment=''))
                    source = (appmsg.findtext('sourcedisplayname') or '').strip()
                    return {
                        'type': 'link',
                        'title': title,
                        'des': des[:200] if des else '',
                        'url': clean_url,
                        'source': source,
                    }
                elif app_type == 33 or app_type == 36:
                    # 小程序
                    source = (appmsg.findtext('sourcedisplayname') or '').strip()
                    return {
                        'type': 'miniapp',
                        'title': title,
                        'source': source,
                        'url': url,
                    }
                elif app_type == 51:
                    # 视频号
                    return {
                        'type': 'channels',
                        'title': title or '视频号内容',
                    }
                elif app_type == 19:
                    # 聊天记录转发 — 解析 recorditem 获取消息列表
                    items = []
                    ri = appmsg.findtext('recorditem') or ''
                    if ri:
                        try:
                            ri_root = ET.fromstring(ri)
                            for di in ri_root.findall('.//dataitem'):
                                name = (di.findtext('sourcename') or '').strip()
                                desc = (di.findtext('datadesc') or '').strip()
                                if name and desc:
                                    items.append({'name': name, 'text': desc[:100]})
                                if len(items) >= 20:
                                    break
                        except ET.ParseError:
                            pass
                    return {
                        'type': 'chatlog',
                        'title': title,
                        'des': des[:200] if des else '',
                        'items': items,
                    }
                elif app_type == 2000:
                    # 微信转账 — 复用 mcp_server 已有的解析器，单一来源避免字段漂移
                    # （snake/camel 大小写、未来新 paysubtype 兜底）。
                    from ..services import mcp
                    info = mcp._extract_transfer_info(appmsg) or {}
                    pay_memo = info.get('pay_memo', '')
                    paysubtype = info.get('paysubtype', '')
                    # 已知 paysubtype 显示中文 label；未知用空串而非"未知(paysubtype=N)"，
                    # 避免 UI 出现内部诊断字串。日志侧若需要可看 chat history。
                    direction = (info.get('paysubtype_label', '')
                                 if paysubtype in mcp_server._TRANSFER_PAYSUBTYPE_LABEL
                                 else '')
                    return {
                        'type': 'transfer',
                        'title': title or '微信转账',
                        'direction': direction,
                        'paysubtype': paysubtype,
                        'fee_desc': info.get('fee_desc', ''),
                        'pay_memo': pay_memo[:200] if pay_memo else '',
                    }
                else:
                    # 其他子类型: 用 title 显示
                    if title:
                        return {
                            'type': 'link',
                            'title': title,
                            'des': des[:200] if des else '',
                            'url': url,
                        }
            except ET.ParseError:
                pass
            return None

        elif msg_type == 43:
            # --- 视频 ---
            result = self._query_msg_content(username, timestamp, 43)
            if not result:
                return None
            mc, _ = result
            try:
                root = ET.fromstring(mc)
                video = root.find('.//videomsg')
                if video is None:
                    return None
                length = int(video.get('playlength') or 0)
                return {
                    'type': 'video',
                    'duration': length,
                }
            except ET.ParseError:
                pass
            return None

        elif msg_type == 34:
            # --- 语音 ---
            result = self._query_msg_content(username, timestamp, 34)
            if not result:
                return None
            mc, _ = result
            try:
                root = ET.fromstring(mc)
                voice = root.find('.//voicemsg')
                if voice is None:
                    return None
                length_ms = int(voice.get('voicelength') or 0)
                return {
                    'type': 'voice',
                    'duration': round(length_ms / 1000, 1),
                }
            except ET.ParseError:
                pass
            return None

        return None

    def _async_resolve_rich(self, username, timestamp, msg_type, msg_data):
        """后台线程: 解析富媒体内容并推送 SSE（带重试）"""
        delays = [0.5, 1.5, 3.0]
        for attempt in range(3):
            try:
                time.sleep(delays[attempt])
                info = self._parse_rich_content(username, timestamp, msg_type)
                if info:
                    msg_data['rich'] = info
                    broadcast_sse({
                        'event': 'rich_update',
                        'timestamp': timestamp,
                        'username': username,
                        'rich': info,
                    })
                    print(f"  [rich] {info['type']} 解析成功", flush=True)
                    return
            except Exception as e:
                print(f"  [rich] 解析失败: {e}", flush=True)
        print(f"  [rich] type={msg_type} 3次重试均失败: {username}", flush=True)

    def query_state(self):
        """查询已解密副本的session状态"""
        conn = sqlite3.connect(f"file:{DECRYPTED_SESSION}?mode=ro", uri=True)
        state = {}
        for r in conn.execute("""
            SELECT username, unread_count, summary, last_timestamp,
                   last_msg_type, last_msg_sender, last_sender_display_name
            FROM SessionTable WHERE last_timestamp > 0
        """).fetchall():
            state[r[0]] = {
                'unread': r[1], 'summary': r[2] or '', 'timestamp': r[3],
                'msg_type': r[4], 'sender': r[5] or '', 'sender_name': r[6] or '',
            }
        conn.close()
        return state

    def do_full_refresh(self):
        """全量解密DB + 全量WAL patch"""
        # 先解密主DB
        pages, ms = full_decrypt(self.session_db, DECRYPTED_SESSION, self.enc_key)
        total_ms = ms
        wal_patched = 0

        # 再patch所有WAL frames
        if os.path.exists(self.wal_path):
            wal_patched, ms2 = decrypt_wal_full(self.wal_path, DECRYPTED_SESSION, self.enc_key)
            total_ms += ms2

        self.decrypt_ms = total_ms
        self.patched_pages = pages + wal_patched
        return self.patched_pages

    def check_updates(self):
        global messages_log
        try:
            t0 = time.perf_counter()
            self.do_full_refresh()
            t1 = time.perf_counter()
            curr_state = self.query_state()
            t2 = time.perf_counter()
            print(f"  [perf] decrypt={self.patched_pages}页/{(t1-t0)*1000:.1f}ms, query={(t2-t1)*1000:.1f}ms", flush=True)
        except Exception as e:
            print(f"  [ERROR] check_updates: {e}", flush=True)
            return

        # 收集所有新消息，按时间排序后再推送
        new_msgs = []
        for username, curr in curr_state.items():
            prev = self.prev_state.get(username)
            # 检测: 时间戳变化 OR 同一秒内消息类型变化（文字+图片组合）
            is_new = prev and (curr['timestamp'] > prev['timestamp'] or
                               (curr['timestamp'] == prev['timestamp'] and curr['msg_type'] != prev.get('msg_type')))
            if is_new:
                # contact.db mtime 变化时刷新缓存：覆盖新增联系人、改名、改备注、群名
                # 修改等场景（issue #46, #67）。受 cooldown 节流。
                self._maybe_refresh_contacts()
                display = self.contact_names.get(username, username)
                is_group = '@chatroom' in username
                sender = ''
                if is_group:
                    sender = self.contact_names.get(curr['sender'], curr['sender_name'] or curr['sender'])

                summary = curr['summary']
                if isinstance(summary, bytes):
                    try:
                        summary = _zstd_dctx.decompress(summary).decode('utf-8', errors='replace')
                    except Exception:
                        summary = '(压缩内容)'
                if summary and ':\n' in summary:
                    summary = summary.split(':\n', 1)[1]

                msg_data = {
                    'time': datetime.fromtimestamp(curr['timestamp']).strftime('%H:%M:%S'),
                    'timestamp': curr['timestamp'],
                    'chat': display,
                    'username': username,
                    'is_group': is_group,
                    'sender': sender,
                    'type': format_msg_type(curr['msg_type']),
                    'type_icon': msg_type_icon(curr['msg_type']),
                    'content': summary,
                    'unread': curr['unread'],
                    'decrypt_ms': round(self.decrypt_ms, 1),
                    'pages': self.patched_pages,
                }

                new_msgs.append(msg_data)
                latest_local_id, full_content = self._lookup_latest_message(username, curr['timestamp'])
                if latest_local_id is not None:
                    self._shown_keys.add((username, latest_local_id))
                    if full_content and len(full_content) > len(msg_data['content']):
                        msg_data['content'] = full_content

                # 图片消息: 后台异步解密（不阻塞轮询）
                if curr['msg_type'] == 3:
                    _img_executor.submit(
                        self._async_resolve_image,
                        username, curr['timestamp'], msg_data
                    )

                # 富媒体消息: 后台解析内容
                if curr['msg_type'] in (47, 49, 43, 34):
                    _img_executor.submit(
                        self._async_resolve_rich,
                        username, curr['timestamp'], curr['msg_type'], msg_data
                    )

                # 检查时间窗口内是否有被 session 摘要覆盖的消息
                # (比如用户发了 图片+文字，session只记录最后一条)
                # 同时传入 latest_local_id，防止 _lookup_latest_message 因缓存过期
                # 返回 None 时消息被 _check_hidden_messages 重复发送
                # 重要：只在 prev['timestamp'] == curr['timestamp'] 时才调用
                # 因为只有同一秒内的消息才可能是"隐藏消息"场景（如图片+文字组合）。
                # 如果时间戳不同，说明是独立的消息，不应该去查询更早的消息。
                if prev and prev['timestamp'] == curr['timestamp']:
                    prev_ts = prev['timestamp'] - 5  # 同一秒内，取5秒窗口
                    _hidden_executor.submit(
                        self._check_hidden_messages,
                        username, prev_ts, curr['timestamp'], curr['msg_type'],
                        display, is_group, sender, latest_local_id
                    )

        # 按时间排序
        new_msgs.sort(key=lambda m: m['timestamp'])

        for msg in new_msgs:
            with messages_lock:
                messages_log.append(msg)
                if len(messages_log) > MAX_LOG:
                    messages_log = messages_log[-MAX_LOG:]

            broadcast_sse(msg)

            try:
                now = time.time()
                msg_age = now - msg['timestamp']
                tag = f"{self.patched_pages}pg/{self.decrypt_ms:.0f}ms"
                sender = msg['sender']
                now_str = datetime.fromtimestamp(now).strftime('%H:%M:%S')
                if sender:
                    print(f"[{msg['time']} 延迟={msg_age:.1f}s] [{msg['chat']}] {sender}: {msg['content']}  ({tag})", flush=True)
                else:
                    print(f"[{msg['time']} 延迟={msg_age:.1f}s] [{msg['chat']}] {msg['content']}  ({tag})", flush=True)
            except Exception:
                pass  # Windows CMD编码问题，不影响SSE推送

        self.prev_state = curr_state

        # 清理 _shown_keys（按数量上限）：local_id 不是时间戳不能按时间 prune。
        # 超过 10000 时保留 local_id 最大的 5000 条（最新消息优先）。
        # 实际触发频率：~几小时一次，set lookup 仍是 O(1)。
        if len(self._shown_keys) > 10000:
            by_local_id = sorted(self._shown_keys, key=lambda k: k[1], reverse=True)
            self._shown_keys = set(by_local_id[:5000])

def monitor_thread(enc_key, session_db, contact_names, db_cache=None, username_db_map=None):
    mon = SessionMonitor(enc_key, session_db, contact_names, db_cache, username_db_map)
    wal_path = mon.wal_path

    # 初始全量解密
    pages, ms = full_decrypt(session_db, DECRYPTED_SESSION, enc_key)
    wal_patched = 0
    wal_ms = 0
    if os.path.exists(wal_path):
        wal_patched, wal_ms = decrypt_wal_full(wal_path, DECRYPTED_SESSION, enc_key)
        print(f"[init] DB {pages}页/{ms:.0f}ms + WAL {wal_patched}页/{wal_ms:.0f}ms", flush=True)
    else:
        print(f"[init] DB {pages}页/{ms:.0f}ms", flush=True)

    mon.prev_state = mon.query_state()
    print(f"[monitor] 跟踪 {len(mon.prev_state)} 个会话", flush=True)
    print(f"[monitor] mtime轮询模式 (每{POLL_MS}ms)", flush=True)

    # mtime-based 轮询: WAL是预分配固定大小，不能用size检测
    poll_interval = POLL_MS / 1000
    prev_wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
    prev_db_mtime = os.path.getmtime(session_db)

    while True:
        time.sleep(poll_interval)
        try:
            # 用mtime检测WAL和DB变化
            try:
                wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
                db_mtime = os.path.getmtime(session_db)
            except OSError:
                continue

            if wal_mtime == prev_wal_mtime and db_mtime == prev_db_mtime:
                continue  # 无变化

            t_detect = time.perf_counter()
            wal_changed = wal_mtime != prev_wal_mtime
            db_changed = db_mtime != prev_db_mtime

            mon.check_updates()

            t_done = time.perf_counter()
            try:
                detect_str = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                print(f"  [{detect_str}] WAL={'变' if wal_changed else '-'} DB={'变' if db_changed else '-'} 总耗时={(t_done-t_detect)*1000:.1f}ms", flush=True)
            except Exception:
                pass

            prev_wal_mtime = wal_mtime
            prev_db_mtime = db_mtime

        except Exception as e:
            print(f"[poll] 错误: {e}", flush=True)
            time.sleep(1)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def handle(self):
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            pass  # 浏览器关闭连接，正常

    def do_GET(self):
        if self.path == '/api/conversations':
            import threading
            _convs_lock = threading.Lock()
            with _convs_lock:
                conversations = []
                try:
                    conn = sqlite3.connect(f"file:{DECRYPTED_SESSION}?mode=ro", uri=True)
                    rows = conn.execute("""
                        SELECT username, unread_count, summary, last_timestamp,
                               last_msg_type, last_msg_sender, last_sender_display_name
                        FROM SessionTable WHERE last_timestamp > 0
                        ORDER BY last_timestamp DESC
                    """).fetchall()
                    conn.close()

                    for r in rows:
                        username = r[0]
                        unread = r[1]
                        summary = r[2] or ''
                        timestamp = r[3]
                        msg_type = r[4]
                        sender = r[5] or ''
                        sender_name = r[6] or ''

                        if isinstance(summary, bytes):
                            try:
                                summary = _zstd_dctx.decompress(summary).decode('utf-8', errors='replace')
                            except Exception:
                                summary = '(压缩内容)'

                        if summary and ':\n' in summary:
                            summary = summary.split(':\n', 1)[1]

                        display = username
                        is_group = '@chatroom' in username

                        conversations.append({
                            'username': username,
                            'chat': display,
                            'is_group': is_group,
                            'unread': unread,
                            'last_message': summary,
                            'timestamp': timestamp,
                            'msg_type': msg_type,
                            'sender': sender,
                            'sender_name': sender_name,
                        })
                except Exception as e:
                    print(f"[api] 获取会话列表失败: {e}", flush=True)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(conversations, ensure_ascii=False).encode('utf-8'))

        elif self.path.startswith('/api/history'):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            filter_chat = params.get('chat', [''])[0].strip().lower()
            since_ts = 0
            try:
                since_ts = int(params.get('since', ['0'])[0])
            except (ValueError, TypeError):
                pass
            limit_val = 500
            try:
                limit_val = min(int(params.get('limit', ['500'])[0]), 2000)
            except (ValueError, TypeError):
                pass

            with messages_lock:
                data = sorted(messages_log, key=lambda m: m.get('timestamp', 0))

            if since_ts:
                data = [m for m in data if m.get('timestamp', 0) > since_ts]
            if filter_chat:
                data = [m for m in data if filter_chat in m.get('chat', '').lower()
                        or filter_chat in m.get('username', '').lower()]
            data = data[-limit_val:]

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

        elif self.path.startswith('/img/'):
            filename = urllib.parse.unquote(self.path[5:])
            # 安全: 防目录穿越
            if '/' in filename or '\\' in filename or '..' in filename:
                self.send_error(403)
                return
            filepath = os.path.join(DECODED_IMAGE_DIR, filename)
            if not os.path.isfile(filepath):
                self.send_error(404)
                return
            ext = os.path.splitext(filename)[1].lower()
            ct = {
                '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
                '.png': 'image/png', '.gif': 'image/gif',
                '.webp': 'image/webp', '.bmp': 'image/bmp',
                '.tif': 'image/tiff',
            }.get(ext, 'application/octet-stream')
            with open(filepath, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header('Content-Type', ct)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'public, max-age=86400')
            self.end_headers()
            self.wfile.write(data)

        elif self.path.startswith('/api/tags'):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            name_filter = params.get('name', [''])[0].strip().lower()

            tags = load_contact_tags()
            if name_filter:
                tags = [t for t in tags if name_filter in t['name'].lower()]

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(tags, ensure_ascii=False).encode('utf-8'))

        elif self.path == '/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()

            q = queue.Queue()
            with sse_lock:
                sse_clients.append(q)
            try:
                while True:
                    try:
                        payload = q.get(timeout=15)
                        self.wfile.write(payload.encode('utf-8'))
                        self.wfile.flush()
                    except queue.Empty:
                        self.wfile.write(b': hb\n\n')
                        self.wfile.flush()
            except:
                pass
            finally:
                with sse_lock:
                    if q in sse_clients:
                        sse_clients.remove(q)
        elif self.path in ('/', '/sse-web.html', '/index.html', '/web'):
            static_dir = os.path.dirname(os.path.abspath(__file__))
            html_file = os.path.join(static_dir, 'sse-web.html')
            if os.path.isfile(html_file):
                with open(html_file, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_error(404)
        else:
            self.send_error(404)


class ThreadedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start_monitor_if_ready():
    """如果 keys 已存在且能解出 session.db, 启动监听线程; 否则跳过。

    返回 True = 监听已启动, False = 未启动。
    """
    if not os.path.exists(KEYS_FILE):
        print(f"[!] 未找到 keys 文件: {KEYS_FILE}", flush=True)
        print("    请先运行 main.py decrypt 提取密钥并解密数据库", flush=True)
        print("    解密完成后重启本进程, 监听会自动启动\n", flush=True)
        return False

    try:
        with open(KEYS_FILE, encoding="utf-8") as f:
            keys = strip_key_metadata(json.load(f))
    except Exception as e:
        print(f"[!] 读取 keys 文件失败: {e}", flush=True)
        return False

    session_key_info = get_key_info(keys, os.path.join("session", "session.db"))
    if not session_key_info:
        print("[!] keys 文件里没有 session.db 密钥", flush=True)
        print("    可能 keys 是部分提取的, 请重新运行 main.py decrypt\n",
              flush=True)
        return False

    enc_key = bytes.fromhex(session_key_info["enc_key"])
    session_db = os.path.join(DB_DIR, "session", "session.db")
    if not os.path.exists(session_db):
        print(f"[!] session.db 不存在: {session_db}", flush=True)
        print("    检查 config.json 的 db_dir 是否对应当前微信账号\n", flush=True)
        return False

    print("加载联系人...", flush=True)
    contact_names = load_contact_names()
    print(f"已加载 {len(contact_names)} 个联系人", flush=True)

    print("构建 username→DB 映射...", flush=True)
    username_db_map = build_username_db_map()
    print(f"已映射 {len(username_db_map)} 个用户名", flush=True)

    # 启动时清理可能损坏的缓存
    if os.path.isdir(MONITOR_CACHE_DIR):
        for f in os.listdir(MONITOR_CACHE_DIR):
            fp = os.path.join(MONITOR_CACHE_DIR, f)
            if f.endswith('.db'):
                try:
                    c = sqlite3.connect(fp)
                    c.execute("SELECT 1 FROM sqlite_master LIMIT 1")
                    c.close()
                except Exception:
                    try:
                        os.unlink(fp)
                        print(f"[cleanup] 删除损坏缓存: {f}", flush=True)
                    except PermissionError:
                        print(f"[cleanup] 缓存被占用跳过: {f}", flush=True)

    db_cache = MonitorDBCache(keys, MONITOR_CACHE_DIR)
    global _global_db_cache
    _global_db_cache = db_cache

    # 后台预热所有 message DB
    def _warmup():
        try:
            t0 = time.perf_counter()
            warmup_keys = [os.path.join("message", "message_resource.db")]
            for i in range(5):
                k = os.path.join("message", f"message_{i}.db")
                if get_key_info(keys, k):
                    warmup_keys.append(k)
            for k in warmup_keys:
                t1 = time.perf_counter()
                try:
                    db_cache.get(k)
                    print(f"[warmup] {k} {(time.perf_counter()-t1)*1000:.0f}ms", flush=True)
                except Exception as e:
                    print(f"[warmup] {k} 失败: {e}", flush=True)
        except Exception as e:
            print(f"[warmup] 异常: {e}", flush=True)
        _build_emoji_lookup(keys)
        print(f"[warmup] 全部完成 {(time.perf_counter()-t0)*1000:.0f}ms", flush=True)
    threading.Thread(target=_warmup, daemon=True).start()

    t = threading.Thread(target=monitor_thread,
                         args=(enc_key, session_db, contact_names, db_cache, username_db_map),
                         daemon=True)
    t.start()
    return True


def main():
    global IMAGE_AES_KEY, IMAGE_XOR_KEY

    cfg = load_config()
    IMAGE_AES_KEY = cfg.get("image_aes_key")
    IMAGE_XOR_KEY = cfg.get("image_xor_key", 0x88)

    print("=" * 60, flush=True)
    print("  WeChat Decrypt — 实时消息监听", flush=True)
    print("=" * 60, flush=True)

    _start_monitor_if_ready()

    server = ThreadedServer(('0.0.0.0', PORT), Handler)
    print(f"=> SSE 服务已启动: http://localhost:{PORT}/stream", flush=True)
    print("Ctrl+C 停止\n", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == '__main__':
    main()
