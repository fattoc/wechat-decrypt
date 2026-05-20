"""wechat_decrypt 包入口 — 支持 python -m wechat_decrypt"""
import sys
import os

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

import main
main.main()