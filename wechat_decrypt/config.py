"""
配置加载器 - 从 config.json 读取路径配置
首次运行时自动检测微信数据目录，检测失败则提示手动配置
"""
import glob
import json
import os
import sys

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def _app_base_dir():
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(pkg_dir)


def _config_file_path():
    root_dir = _app_base_dir()
    p = os.path.join(root_dir, "config.json")
    if os.path.exists(p):
        return p
    fallback = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if os.path.exists(fallback):
        return fallback
    return p


_DEFAULT_TEMPLATE_DIR = r"D:\xwechat_files\your_wxid\db_storage"
_DEFAULT_PROCESS = "Weixin.exe"

_DEFAULT = {
    "db_dir": _DEFAULT_TEMPLATE_DIR,
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "decoded_image_dir": "decoded_images",
    "wechat_process": _DEFAULT_PROCESS,
    "wxwork_db_dir": "",
    "wxwork_keys_file": "wxwork_keys.json",
    "wxwork_decrypted_dir": "wxwork_decrypted",
    "wxwork_export_dir": "wxwork_export",
    "wxwork_process": "WXWork.exe",
    "transcription_backend": "local",
    "local_whisper_model": "base",
    "openai_api_key": "",
}


def _choose_candidate(candidates):
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        if (
            os.environ.get("WECHAT_DECRYPT_NONINTERACTIVE") == "1"
            or not sys.stdin.isatty()
        ):
            return candidates[0]
        print("[!] 检测到多个微信数据目录（请选择当前正在运行的微信账号）:")
        for i, c in enumerate(candidates, 1):
            print(f"    {i}. {c}")
        print("    0. 跳过，稍后手动配置")
        try:
            while True:
                choice = input("请选择 [0-{}]: ".format(len(candidates))).strip()
                if choice == "0":
                    return None
                if choice.isdigit() and 1 <= int(choice) <= len(candidates):
                    return candidates[int(choice) - 1]
                print("    无效输入，请重新选择")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
    return None


def _auto_detect_db_dir():
    appdata = os.environ.get("APPDATA", "")
    config_dir = os.path.join(appdata, "Tencent", "xwechat", "config")
    if not os.path.isdir(config_dir):
        return None

    data_roots = []
    for ini_file in glob.glob(os.path.join(config_dir, "*.ini")):
        try:
            content = None
            for enc in ("utf-8", "gbk"):
                try:
                    with open(ini_file, "r", encoding=enc) as f:
                        content = f.read(1024).strip()
                    break
                except UnicodeDecodeError:
                    continue
            if not content or any(c in content for c in "\n\r\x00"):
                continue
            if os.path.isdir(content):
                data_roots.append(content)
        except OSError:
            continue

    seen = set()
    candidates = []
    for root in data_roots:
        pattern = os.path.join(root, "xwechat_files", "*", "db_storage")
        for match in glob.glob(pattern):
            normalized = os.path.normcase(os.path.normpath(match))
            if os.path.isdir(match) and normalized not in seen:
                seen.add(normalized)
                candidates.append(match)

    return _choose_candidate(candidates)


def load_config():
    cfg = {}
    config_file = _config_file_path()
    if os.path.exists(config_file):
        try:
            with open(config_file, encoding="utf-8") as f:
                cfg = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] {config_file} 格式损坏，将使用默认配置")
            cfg = {}

    db_dir = cfg.get("db_dir", "")
    if not db_dir or db_dir == _DEFAULT_TEMPLATE_DIR or "your_wxid" in db_dir:
        detected = _auto_detect_db_dir()
        if detected:
            print(f"[+] 自动检测到微信数据目录: {detected}")
            cfg = {**_DEFAULT, **cfg, "db_dir": detected}
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4, ensure_ascii=False)
            print(f"[+] 已保存到: {config_file}")
        else:
            if not os.path.exists(config_file):
                with open(config_file, "w", encoding="utf-8") as f:
                    json.dump(_DEFAULT, f, indent=4, ensure_ascii=False)
            print(f"[!] 未能自动检测微信数据目录")
            print(f"    请手动编辑 {config_file} 中的 db_dir 字段")
            print(f"    路径可在 微信设置 → 文件管理 中找到")
            sys.exit(1)
    else:
        cfg = {**_DEFAULT, **cfg}

    base = _app_base_dir()
    for key in (
        "keys_file", "decrypted_dir", "decoded_image_dir",
        "wxwork_keys_file", "wxwork_decrypted_dir", "wxwork_export_dir",
    ):
        if key in cfg and cfg[key] and not os.path.isabs(cfg[key]):
            cfg[key] = os.path.join(base, cfg[key])

    base = _app_base_dir()
    if cfg.get("db_dir"):
        cfg["db_dir"] = os.path.expanduser(os.path.expandvars(cfg["db_dir"]))
    for key in ("keys_file", "decrypted_dir", "decoded_image_dir"):
        if cfg.get(key):
            cfg[key] = os.path.expanduser(os.path.expandvars(cfg[key]))
            if not os.path.isabs(cfg[key]):
                cfg[key] = os.path.join(base, cfg[key])

    db_dir = cfg.get("db_dir", "")
    if db_dir and os.path.basename(db_dir) == "db_storage":
        cfg["wechat_base_dir"] = os.path.dirname(db_dir)
    else:
        cfg["wechat_base_dir"] = db_dir

    wxid = os.path.basename(os.path.normpath(cfg["wechat_base_dir"]))
    cfg["output_base_dir"] = os.path.join(base, "wechat_files", wxid)

    if "decoded_image_dir" not in cfg:
        cfg["decoded_image_dir"] = os.path.join(base, "decoded_images")

    if not cfg.get("wechat_files_dir"):
        wechat_files_base = os.path.join(os.path.expanduser("~"), "Documents", "WeChat Files")
        if os.path.isdir(wechat_files_base):
            wxid_prefix = wxid.rsplit("_", 1)[0] if "_" in wxid else wxid
            for d in os.listdir(wechat_files_base):
                if d == wxid or d == wxid_prefix or wxid.startswith(d):
                    candidate = os.path.join(wechat_files_base, d)
                    if os.path.isdir(os.path.join(candidate, "FileStorage")):
                        cfg["wechat_files_dir"] = candidate
                        break

    wf_dir = cfg.get("wechat_files_dir", "")
    cfg["msgattach_dir"] = os.path.join(wf_dir, "FileStorage", "MsgAttach") if wf_dir else ""
    cfg["sns_cache_dir"] = os.path.join(wf_dir, "FileStorage", "Sns", "Cache") if wf_dir else ""

    wb = cfg["wechat_base_dir"]
    cfg["xwechat_attach_dir"] = os.path.join(wb, "msg", "attach") if wb else ""
    cfg["xwechat_cache_dir"] = os.path.join(wb, "cache") if wb else ""

    return cfg