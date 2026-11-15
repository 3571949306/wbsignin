"""单写者锁。

为什么需要它
------------
刷新令牌（RT）是滚动轮换的：每次用旧 RT 换取新 RT，旧 RT 立即失效。
如果两个进程（例如 cron 与本机手动执行、或同一台机器跑了两个实例）
同时拿同一个 RT 去刷新，就会出现：

    A 用 RT1 换到 RT2 并落盘
    B 用 RT1 换到 RT3 并落盘   ← 覆盖掉 RT2
    下一次 A 用 RT2 → 服务端已作废 → 该账号静默失效

这个过程通常**没有任何明显报错**，直到某天发现连续签到断了。
所以所有「读取 RT → 刷新 → 写回」的临界区必须串行化。

实现
----
POSIX 用 fcntl.flock，Windows 用 msvcrt.locking，均对独立锁文件加排他锁。
锁文件与凭据库分离，避免对 vault.json 的 flock 与原子 rename 相互干扰
（rename 会替换 inode，锁住的将是旧 inode，等于没锁）。

另外写一份 lease 元数据（pid / host / 时间）用于诊断"谁在占着"，
它只用于排错，不承担互斥职责。
"""
from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path
from typing import Optional

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore
    import msvcrt


class LockTimeout(Exception):
    """在超时时间内未能获得锁。"""


class FileLock:
    def __init__(self, path: Path, lease_path: Optional[Path] = None):
        self.path = Path(path)
        self.lease_path = Path(lease_path) if lease_path else Path(str(path) + ".lease")
        self._fh = None

    # -- 底层加锁 --
    def _try_lock(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+b")
        try:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:  # pragma: no cover - Windows
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            fh.close()
            return False
        self._fh = fh
        return True

    def acquire(self, timeout: float = 120.0, poll: float = 0.5) -> "FileLock":
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if self._try_lock():
                self._write_lease()
                return self
            if timeout <= 0:
                raise LockTimeout(self._describe_holder())
            if time.monotonic() >= deadline:
                raise LockTimeout(
                    "等待锁超时（%.0fs）%s" % (timeout, self._describe_holder())
                )
            time.sleep(poll)

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            else:  # pragma: no cover - Windows
                try:
                    self._fh.seek(0)
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        finally:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None
            try:
                self.lease_path.unlink()
            except OSError:
                pass

    # -- lease 诊断信息 --
    def _write_lease(self) -> None:
        info = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "since": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ts": time.time(),
        }
        try:
            self.lease_path.write_text(
                json.dumps(info, ensure_ascii=False), encoding="utf-8"
            )
            os.chmod(self.lease_path, 0o600)
        except OSError:
            pass

    def _describe_holder(self) -> str:
        try:
            info = json.loads(self.lease_path.read_text(encoding="utf-8"))
            return "（占用者：pid=%s host=%s 自 %s）" % (
                info.get("pid"),
                info.get("host"),
                info.get("since"),
            )
        except Exception:
            return ""

    # -- 上下文管理 --
    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, *exc) -> None:
        self.release()


def is_locked(path: Path) -> bool:
    """只探测、不加锁：用于 status 命令展示。"""
    lock = FileLock(Path(path))
    try:
        lock.acquire(timeout=0)
    except LockTimeout:
        return True
    finally:
        lock.release()
    return False
