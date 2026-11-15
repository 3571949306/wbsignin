#!/usr/bin/env python3
"""从本机浏览器 / 豆包客户端提取 doubao.com 登录 Cookie（Windows 专用）。

背景：豆包签到凭据是 doubao.com 会话 Cookie。登录后它被 Chromium 加密保存在
浏览器/客户端的 SQLite 里（os_crypt + DPAPI + AES-256-GCM）。本脚本把它解密
拼回 "name=value; ..." 形式的 Cookie 头，供 wbsignin 使用。

依赖：全标准库 + Windows 原生 DPAPI/CNG（无需安装第三方包）。

用法：
  python pull_doubao_cookie.py                          # 扫描全部配置档并打印预览（复制首个到剪贴板）
  python pull_doubao_cookie.py --print                  # 打印完整 Cookie（慎用，会留在终端）
  python pull_doubao_cookie.py --local                  # 直接导入到本机 wbsignin 凭据库
  python pull_doubao_cookie.py --push --host your-vps   # 扫描全部可用豆包账号并推送到服务器（自动按 uid 去重）
  python pull_doubao_cookie.py --push 豆包小号 --host your-vps  # 推送匹配到的账号为指定名称（可配合 --profile）

顺序：豆包客户端（Default / Profile *）→ Chrome → Edge → Brave。
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from _remote_push import import_local_with_tempfile, push_via_ssh
from _win_crypto import chromium_local_state_key as _encryption_key
from _win_crypto import decrypt_v10


def _copy_shared(src: Path, dst: Path) -> None:
    """复制 Chromium SQLite 文件：常规失败时用 FILE_SHARE_ALL 打开读取。"""
    try:
        shutil.copy2(src, dst)
        return
    except PermissionError:
        pass
    k32 = ctypes.windll.kernel32
    handle = k32.CreateFileW(str(src), 0x80000000, 0x00000007, None, 3, 0, None)
    if handle in (-1, 0, wintypes.HANDLE(-1).value):
        raise PermissionError("文件被进程独占锁定，无法读取: %s" % src)
    try:
        chunks: List[bytes] = []
        buf = ctypes.create_string_buffer(65536)
        n = wintypes.DWORD(0)
        while k32.ReadFile(handle, buf, 65536, ctypes.byref(n), None) and n.value > 0:
            chunks.append(buf.raw[: n.value])
        dst.write_bytes(b"".join(chunks))
    finally:
        k32.CloseHandle(handle)


# ---------- 浏览器/客户端定位 ----------
def _browser_candidates():
    local = Path(os.environ["LOCALAPPDATA"])
    return [
        # 豆包客户端最可靠（专属 Chromium，v10 加密，且 Chrome 常被进程独占锁文件）
        ("豆包客户端", local / "Doubao" / "User Data"),
        ("Chrome", local / "Google" / "Chrome" / "User Data"),
        ("Edge", local / "Microsoft" / "Edge" / "User Data"),
        ("Brave", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
    ]


def _read_cookies(cookies_path: Path):
    """把 Cookies(+wal/shm) 拷到临时目录再读，规避浏览器运行时的锁。"""
    with tempfile.TemporaryDirectory() as d:
        for suffix in ("", "-wal", "-shm"):
            src = Path(str(cookies_path) + suffix)
            if src.exists():
                _copy_shared(src, Path(d) / ("Cookies" + suffix))
        conn = sqlite3.connect(Path(d) / "Cookies")
        try:
            rows = conn.execute(
                "SELECT host_key, name, encrypted_value FROM cookies "
                "WHERE host_key LIKE '%doubao.com'"
            ).fetchall()
        finally:
            conn.close()
        return rows


def _profile_display_map(user_data_dir: Path) -> Dict[str, str]:
    try:
        ls = json.loads((user_data_dir / "Local State").read_text(encoding="utf-8"))
        cache = (ls.get("profile") or {}).get("info_cache") or {}
        return {
            str(k): str(v.get("name") or k)
            for k, v in cache.items()
            if isinstance(v, dict)
        }
    except Exception:
        return {}


def _iter_profile_cookies(user_data_dir: Path) -> List[Tuple[str, str, Path]]:
    if not user_data_dir.is_dir():
        return []
    names = _profile_display_map(user_data_dir)
    dirs: List[Path] = []
    default_dir = user_data_dir / "Default"
    if default_dir.is_dir():
        dirs.append(default_dir)
    others = [
        d
        for d in sorted(user_data_dir.iterdir(), key=lambda p: p.name)
        if d.is_dir() and d.name != "Default"
    ]
    dirs.extend(others)

    out: List[Tuple[str, str, Path]] = []
    for sub in dirs:
        for rel in (Path("Network") / "Cookies", Path("Cookies")):
            cpath = sub / rel
            if cpath.is_file():
                out.append((sub.name, names.get(sub.name) or sub.name, cpath))
                break
    return out


def _decrypt_value(encrypted_value, key: bytes, host_key: str):
    plain = decrypt_v10(bytes(encrypted_value), key)
    if plain is None:
        return None  # app-bound 加密，DPAPI 解不开
    if bytes(encrypted_value).startswith(b"v10"):
        prefix = hashlib.sha256(host_key.encode("utf-8")).digest()
        if plain.startswith(prefix):
            plain = plain[32:]
    return plain.decode("utf-8", "replace")


def extract_all() -> List[Dict[str, Any]]:
    """扫描所有浏览器与全部配置档，返回按 uid_tt 去重后的可用豆包账号列表。"""
    found: List[Dict[str, Any]] = []
    seen_uids = set()
    for browser, udd in _browser_candidates():
        if not (udd / "Local State").is_file():
            continue
        try:
            key = _encryption_key(udd)
        except Exception as exc:
            print(f"[跳过] {browser}: 读取主密钥失败: {exc}", file=sys.stderr)
            continue
        for prof_dir, prof_name, cookies_path in _iter_profile_cookies(udd):
            tag = f"{browser} / {prof_name} ({prof_dir})"
            try:
                rows = _read_cookies(cookies_path)
            except Exception as exc:
                print(f"[跳过] {tag}: {exc}（若需提取此配置档可先退出对应窗口）", file=sys.stderr)
                continue
            if not rows:
                continue
            pairs, app_bound = [], 0
            cookie_map: Dict[str, str] = {}
            for host_key, cname, enc in rows:
                val = _decrypt_value(enc, key, host_key)
                if val is None:
                    app_bound += 1
                    continue
                pairs.append(f"{cname}={val}")
                cookie_map[cname] = val
            if not pairs:
                print(
                    f"[跳过] {tag}: {len(rows)} 个 doubao cookie 均为 app-bound(v20)，DPAPI 无法解密",
                    file=sys.stderr,
                )
                continue
            uid = cookie_map.get("uid_tt") or cookie_map.get("uid_tt_ss") or ""
            sid = cookie_map.get("sessionid") or cookie_map.get("sessionid_ss") or ""
            if not (uid or sid):
                continue
            dedup_key = uid or sid
            if dedup_key in seen_uids:
                continue
            seen_uids.add(dedup_key)
            found.append(
                {
                    "browser": browser,
                    "profile_dir": prof_dir,
                    "profile_name": prof_name,
                    "uid_tt": uid,
                    "cookie": "; ".join(pairs),
                    "count": len(pairs),
                    "app_bound": app_bound,
                }
            )
    return found


def extract():
    items = extract_all()
    if not items:
        return None, "", 0, 0
    first = items[0]
    return (
        f"{first['browser']}({first['profile_name']})",
        first["cookie"],
        first["count"],
        first["app_bound"],
    )


def _masked_preview(cookie: str) -> str:
    parts = [p for p in cookie.split("; ") if p]
    names = []
    for p in parts:
        if "=" in p:
            names.append(p.split("=", 1)[0])
    return "、".join(names) if names else "(空)"


def _copy_clipboard(text: str) -> bool:
    try:
        subprocess.run(["clip"], input=text.encode("utf-8"), check=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return True
    except Exception:
        try:
            subprocess.run(["clip.exe"], input=text.encode("utf-8"), check=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return True
        except Exception:
            return False


def _push(
    cookie: str,
    name: str = "",
    default_name: str = "豆包",
    host: str = "",
    remote_dir: str = "",
    remote_home: str = "",
) -> int:
    """经单次 SSH 会话把 Cookie 写入远端临时文件并执行 login-doubao。"""
    remote_tmp = "/tmp/db_cookie_%d.txt" % os.getpid()
    name_arg = (shlex.quote(name) + " ") if name else ""
    return push_via_ssh(
        host=host,
        payload=cookie.encode("utf-8"),
        remote_tmp=remote_tmp,
        build_cli_args=lambda q_tmp: (
            f"login-doubao {name_arg}"
            f"--default-name {shlex.quote(default_name)} --cookie-file {q_tmp}"
        ),
        remote_dir=remote_dir,
        remote_home=remote_home,
    )


def _import_local(cookie: str, name: str = "", default_name: str = "豆包") -> int:
    def _args(tmp_path: str) -> List[str]:
        out = ["login-doubao"]
        if name:
            out.append(name)
        out.extend(["--default-name", default_name, "--cookie-file", tmp_path])
        return out

    return import_local_with_tempfile(cookie.encode("utf-8"), ".txt", _args)


def main() -> int:
    ap = argparse.ArgumentParser(description="提取本机 doubao.com 登录 Cookie（支持多配置档）")
    ap.add_argument("--print", action="store_true", help="打印完整 Cookie")
    ap.add_argument("--profile", default="", help="只选择指定配置档目录或显示名")
    ap.add_argument("--local", nargs="?", const="", default=None, metavar="名称",
                    help="提取后直接导入到本机 wbsignin 凭据库")
    ap.add_argument("--push", nargs="?", const="", default=None, metavar="名称",
                    help="提取后经 SSH 推送到服务器（不填名称则自动推送全部配置档）")
    ap.add_argument("--host", default="",
                    help="SSH 目标主机名（也可通过环境变量 WBSIGNIN_SSH_HOST 指定）")
    ap.add_argument("--remote-dir", default="",
                    help="远端 wbsignin 代码目录（默认自动探测 ~/.local/share/wbsignin、~/wbsignin、/opt/wbsignin）")
    ap.add_argument("--remote-home", default="",
                    help="远端凭据状态目录（默认 $WBSIGNIN_HOME 或 ~/.wbsignin）")
    args = ap.parse_args()

    items = extract_all()
    if args.profile:
        q = args.profile.strip().lower()
        items = [
            it for it in items
            if q in it["profile_dir"].lower() or q in it["profile_name"].lower()
        ]
    if not items:
        print("未找到可用的 doubao Cookie：请先在 Chrome 或豆包客户端登录 doubao.com")
        return 1

    for idx, it in enumerate(items, 1):
        uid_mask = (it["uid_tt"][:6] + "..." + it["uid_tt"][-4:]) if len(it["uid_tt"]) > 10 else (it["uid_tt"] or "-")
        print(
            f"[{idx}] {it['browser']} / {it['profile_name']} ({it['profile_dir']})  "
            f"uid={uid_mask}  [{it['count']} 个 cookie]"
            + (f"（另有 {it['app_bound']} 个 app-bound）" if it["app_bound"] else "")
        )
    print(f"[Cookie 名] {_masked_preview(items[0]['cookie'])}")

    if args.local is not None:
        forced_name = args.local.strip()
        targets = items[:1] if (forced_name and len(items) > 1 and not args.profile) else items
        rc = 0
        for it in targets:
            def_name = f"豆包-{it['profile_name']}"
            r = _import_local(it["cookie"], name=forced_name, default_name=def_name)
            label_show = forced_name or def_name
            print("[本机导入 %s] %s" % (label_show, "成功" if r == 0 else f"失败（退出码 {r}）"))
            if r != 0:
                rc = r
        return rc

    if args.push is not None:
        forced_name = args.push.strip()
        targets = items[:1] if (forced_name and len(items) > 1 and not args.profile) else items
        rc = 0
        for it in targets:
            def_name = f"豆包-{it['profile_name']}"
            r = _push(
                it["cookie"],
                name=forced_name,
                default_name=def_name,
                host=args.host,
                remote_dir=args.remote_dir,
                remote_home=args.remote_home,
            )
            label_show = forced_name or def_name
            print("[推送 %s] %s" % (label_show, "成功" if r == 0 else f"失败（退出码 {r}）"))
            if r != 0:
                rc = r
        return rc

    if args.print:
        for it in items:
            print(f"\n# {it['browser']} / {it['profile_name']}\n{it['cookie']}")
        return 0
    if _copy_clipboard(items[0]["cookie"]):
        print("[剪贴板] 已复制第 1 个账号，直接粘贴到控制台「添加豆包」的 Cookie 框即可")
    else:
        print("[提示] 剪贴板复制失败，用 --print 手动复制")
    return 0


if __name__ == "__main__":
    sys.exit(main())
