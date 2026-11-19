import ctypes
import glob
import logging
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import msgpack
import psutil
import shutil
import zmq

from x64dbg_automate.events import DebugEventQueueMixin, DEFAULT_LOG_EVENT_QUEUE_MAXLEN
from x64dbg_automate.hla_xauto import XAutoHighLevelCommandAbstractionMixin
from x64dbg_automate.models import DebugSession

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    from x64dbg_automate.win32 import GetTempPathW, SetConsoleCtrlHandler, EnumWindows, GetWindowTextW, GetWindowThreadProcessId


COMPAT_VERSION = "ghost_fungus_2026_11" # TODO: externalize
logger = logging.getLogger(__name__)
all_instances: list['X64DbgClient'] = []


# ---------------------------------------------------------------------------
# Launcher resolution
#
# x96dbg.exe 是 x64dbg 的 launcher：必须带转发参数才会启动真正的调试器
#   .\x96dbg.exe x64\x64dbg.exe
#   .\x96dbg.exe x32\x32dbg.exe
# 裸 Popen(x96dbg.exe) 不会拉起任何连 ZMQ 的实体，只会挂着空跑 —— 而 launcher 的
# PID 也不是 debugger 的 PID，attach_session 等锁文件必然超时。
# 所以这里按目标位数直接把 launcher 解析成 x64dbg.exe / x32dbg.exe 再启动。
# Local patch (local.7).
# ---------------------------------------------------------------------------

_LAUNCHER_NAMES = ("x96dbg.exe", "x96dbg")


def _pe_bitness(exe_path: str) -> int:
    """读 PE Machine 字段判断 32/64 位；读不出来时按 64 处理（与 MCP 侧默认一致）。"""
    import struct
    try:
        with open(exe_path, "rb") as f:
            if f.read(2) != b"MZ":
                return 64
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                return 64
            machine = struct.unpack("<H", f.read(2))[0]
    except Exception:
        return 64
    return 32 if machine == 0x14C else 64


def _process_bitness(pid: int) -> int:
    """目标进程是 32 位（WOW64）还是 64 位；拿不到时按 64 处理。"""
    if not _IS_WINDOWS:
        return 64
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k32 = ctypes.windll.kernel32
    handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return 64
    try:
        wow64 = ctypes.c_int(0)
        if k32.IsWow64Process(handle, ctypes.byref(wow64)) and wow64.value:
            return 32
        return 64
    finally:
        k32.CloseHandle(handle)


def _resolve_launcher(path: Path, bitness: int) -> Path:
    """x96dbg.exe -> 同目录下的 x64\\x64dbg.exe 或 x32\\x32dbg.exe。"""
    arch = "x64" if bitness == 64 else "x32"
    name = "x64dbg.exe" if bitness == 64 else "x32dbg.exe"
    for candidate in (path.parent / arch / name,
                      path.parent / name,
                      path.parent / "release" / arch / name):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"Cannot resolve {path.name} to {arch}\\{name} for a {bitness}-bit target. "
        f"Pass the debugger binary directly (e.g. {path.parent / arch / name}).")


if _IS_WINDOWS:
    def ctrl_c_handler(sig_t: int) -> bool:
        logger.warning(f'Received exit signal {sig_t}, detaching and exiting')
        for i in all_instances:
            i.detach_session()
        import psutil
        psutil.Process().terminate()
        return True
    ctrl_c_handler = SetConsoleCtrlHandler.argtypes[0](ctrl_c_handler)
    SetConsoleCtrlHandler(ctrl_c_handler, True)


class ClientConnectionFailedError(Exception):
    pass

class X64DbgClient(XAutoHighLevelCommandAbstractionMixin, DebugEventQueueMixin):
    def _init_fields(self, x64dbg_path: str | None = None, remote_host: str = "localhost",
                     req_rep_port: int = 0, pub_sub_port: int = 0,
                     log_event_queue_maxlen: int = DEFAULT_LOG_EVENT_QUEUE_MAXLEN):
        self.x64dbg_path = x64dbg_path
        self.proc = None
        self.session_pid = None
        self.context = zmq.Context()
        self.req_socket = None
        self.sub_socket = None
        self.sess_req_rep_port = req_rep_port
        self.sess_pub_sub_port = pub_sub_port
        self.remote_host = remote_host
        self._req_lock = threading.Lock()
        self._last_target: tuple[str, str, str] | None = None
        self._init_event_queues(log_event_queue_maxlen)
        all_instances.append(self)

    def __init__(self, x64dbg_path: str = "x64dbg",
                 log_event_queue_maxlen: int = DEFAULT_LOG_EVENT_QUEUE_MAXLEN):
        """
        Args:
            x64dbg_path: Path to the x64dbg executable (or a name resolvable on PATH).
            log_event_queue_maxlen: Maximum number of `EVENT_LOG_MESSAGE` events
                retained in the dedicated log-event queue. Log events are kept
                separate from other debug events so a verbose log stream (e.g. a
                trace) cannot evict breakpoint/step events. Can also be changed
                later via the `log_event_queue_maxlen` property.
        """
        resolved = x64dbg_path
        if not Path(resolved).is_file():
            resolved = shutil.which(x64dbg_path)
        if resolved is None or not Path(resolved).is_file():
            raise FileNotFoundError(f"x64dbg executable not found at {x64dbg_path} or in PATH")
        self._init_fields(x64dbg_path=resolved, log_event_queue_maxlen=log_event_queue_maxlen)

    @classmethod
    def connect_remote(cls, host: str, req_rep_port: int, pub_sub_port: int,
                       log_event_queue_maxlen: int = DEFAULT_LOG_EVENT_QUEUE_MAXLEN) -> 'X64DbgClient':
        """Connect to a remote x64dbg instance by host and port pair.

        This bypasses local session discovery (lockfiles) and connects directly
        to a remote x64dbg plugin configured to bind on an accessible address.

        Args:
            host: Remote hostname or IP address (e.g. '192.168.1.100')
            req_rep_port: The REQ/REP port the plugin is listening on
            pub_sub_port: The PUB/SUB port the plugin is listening on
            log_event_queue_maxlen: Maximum number of `EVENT_LOG_MESSAGE` events
                retained in the dedicated log-event queue (see `__init__`).

        Returns:
            A connected X64DbgClient instance
        """
        client = cls.__new__(cls)
        client._init_fields(remote_host=host, req_rep_port=req_rep_port, pub_sub_port=pub_sub_port,
                            log_event_queue_maxlen=log_event_queue_maxlen)
        client._init_connection()
        client._assert_connection_compat()
        return client

    def __del__(self):
        all_instances.remove(self)
    
    def _sub_thread(self) -> None:
        while True:
            try:
                if self.sub_socket is None:
                    break
                msg = msgpack.unpackb(self.sub_socket.recv(zmq.DONTWAIT))
                self.debug_event_publish(msg)
            except zmq.error.Again:
                # No messages on socket
                time.sleep(0.2)
                pass
            except KeyboardInterrupt:
                # Quitting, expected exit
                break
            except zmq.error.ZMQError:
                logger.exception("Unhandled ZMQError, retrying")

    
    def _init_connection(self) -> None:
        if self.req_socket is not None:
            self._close_connection()

        self.req_socket = self.context.socket(zmq.REQ)
        self.req_socket.setsockopt(zmq.CONNECT_TIMEOUT, 6000)
        self.req_socket.setsockopt(zmq.SNDTIMEO, 6000)
        self.req_socket.setsockopt(zmq.RCVTIMEO, 10000)
        self.req_socket.connect(f"tcp://{self.remote_host}:{self.sess_req_rep_port}")
        self.req_socket.send(msgpack.packb("PING"))
        if msgpack.unpackb(self.req_socket.recv()) != "PONG":
            raise ClientConnectionFailedError(f"Connection to x64dbg failed on port {self.sess_req_rep_port}")
        
        self.sub_socket = self.context.socket(zmq.SUB)
        self.sub_socket.setsockopt(zmq.CONNECT_TIMEOUT, 6000)
        self.sub_socket.setsockopt(zmq.SNDTIMEO, 6000)
        self.sub_socket.setsockopt(zmq.RCVTIMEO, 10000)
        self.sub_socket.connect(f"tcp://{self.remote_host}:{self.sess_pub_sub_port}")
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "")
        self.sub_thread = threading.Thread(target=self._sub_thread)
        self.sub_thread.start()

    def _close_connection(self) -> None:
        if self.req_socket is None:
            return
        self.req_socket.close()
        self.sub_socket.close()
        self.req_socket = None
        self.sub_socket = None
        self.sub_thread.join()
        self.session_pid = None
        self.proc = None
        self.sess_req_rep_port = 0
        self.sess_pub_sub_port = 0

    def _rebuild_req_socket(self) -> None:
        """Recreate the REQ socket after a timed-out recv.

        REQ/REP is a strict state machine: a socket that timed out waiting for its
        reply refuses the next send (EFSM), so a retry has to start from a new one.
        """
        port = self.sess_req_rep_port
        if not port:
            raise ClientConnectionFailedError("no REQ/REP port to reconnect to")
        try:
            self.req_socket.close(linger=0)
        except Exception:
            pass
        self.req_socket = self.context.socket(zmq.REQ)
        self.req_socket.setsockopt(zmq.CONNECT_TIMEOUT, 6000)
        self.req_socket.setsockopt(zmq.SNDTIMEO, 6000)
        self.req_socket.setsockopt(zmq.RCVTIMEO, 10000)
        self.req_socket.connect(f"tcp://{self.remote_host}:{port}")

    def dismiss_debugger_dialogs_soon(self, seconds: float = 4.0,
                                      interval: float = 0.2) -> int:
        """Keep an eye on the debugger for `seconds`, closing message boxes as they pop.

        x64dbg announces script completion with a modal box, but it appears *after*
        the script command returns, so a single check right after `script_run` is
        too early (measured: the box showed up later and then blocked the next RPC).
        """
        deadline = time.time() + max(0.0, seconds)
        total = 0
        while time.time() < deadline:
            total += self.dismiss_debugger_dialogs()
            time.sleep(interval)
        return total

    def dismiss_debugger_dialogs(self) -> int:
        """Close modal message boxes owned by the debugger process.

        x64dbg announces script completion with a modal MessageBox. While it is up
        the GUI thread stops pumping, the plugin cannot answer any bridge call, and
        the client mistakes the silence for a dead connection (every later call
        then fails with "Not connected"). Closing the box is the only recovery that
        does not need a human to click OK.

        Returns:
            Number of dialog boxes closed.
        """
        pid = self.session_pid
        if not pid:
            return 0
        try:
            from x64dbg_automate.win32 import close_dialog_boxes
            n = close_dialog_boxes(int(pid))
            if n:
                logger.warning("closed %d modal dialog(s) blocking the debugger bridge", n)
            return n
        except Exception:
            logger.debug("dismiss_debugger_dialogs failed", exc_info=True)
            return 0

    def _send_request(self, request_type: str, *args) -> tuple:
        payload = msgpack.packb((request_type, *args))
        with self._req_lock:
            try:
                self.req_socket.send(payload)
                msg = msgpack.unpackb(self.req_socket.recv(), use_list=False)
            except zmq.error.Again:
                # Nothing came back in RCVTIMEO. The dominant cause is a modal box in
                # the debugger (GuiScriptMessage after a script finishes) blocking the
                # GUI thread; without this recovery the connection stays poisoned.
                if not self.dismiss_debugger_dialogs():
                    raise
                self._rebuild_req_socket()
                self.req_socket.send(payload)
                msg = msgpack.unpackb(self.req_socket.recv(), use_list=False)
        if msg is None:
            raise RuntimeError("Empty response from x64dbg")
        if isinstance(msg, tuple) and len(msg) == 2 and isinstance(msg[0], str) and msg[0].startswith("XERROR_"):
            raise RuntimeError(msg)
        return msg

    def _assert_connection_compat(self) -> None:
        v = self._get_xauto_compat_version()
        assert v == COMPAT_VERSION, f"Incompatible x64dbg plugin and client versions {v} != {COMPAT_VERSION}"
        
    def _launch_x64dbg(self, bitness: int = 64) -> int:
        if self.x64dbg_path is None:
            raise RuntimeError("Cannot launch x64dbg in remote mode — no x64dbg_path configured")
        launch = self.x64dbg_path
        configured = Path(launch)
        if configured.name.lower() in _LAUNCHER_NAMES:
            launch = str(_resolve_launcher(configured, bitness))
            logger.info("resolved launcher %s -> %s (%d-bit target)",
                        self.x64dbg_path, launch, bitness)
        self.proc = subprocess.Popen([launch], executable=launch)
        self.session_pid = self.proc.pid
        try:
            self.attach_session(self.session_pid)
        except BaseException:
            # attach 失败时别把空跑的调试器留在后台（launcher 解析不到、插件缺失、
            # 或本机已有同名会话等），否则 tasklist 里全是僵尸。
            # Local patch (local.6).
            try:
                self.proc.kill()
                self.proc.wait(timeout=5)
            except Exception:
                pass
            raise

    def reset_breakpoints(self) -> dict:
        """
        Clears every breakpoint type restored from the module debug database.

        x64dbg keeps a per-module database (``<x64dbg>/db/<module>.dd64``) holding
        breakpoints, labels, comments and patches across sessions, and re-applies
        it on *every* load. terminate_session() does not write the database back,
        so clearing breakpoints in one session has no effect on the next one: a
        stale TLS/entry breakpoint returns and silently eats the first ``go``.

        Returns:
            Per-type success flags for the three breakpoint families
        """
        return {
            "software": self.cmd_sync("bpc"),
            "hardware": self.cmd_sync("bphwc"),
            "memory": self.cmd_sync("bpmc"),
        }

    def start_session(self, target_exe: str = "", cmdline: str = "", current_dir: str = "",
                      clean_breakpoints: bool = False) -> int:
        """
        Start a new x64dbg session and optionally load an executable into it. If target_exe is not provided,
        the debugger starts without any executable. This is useful for performing configuration before the debuggee is loaded.

        Args:
            target_exe: The path to the target executable (optional)
            cmdline: The command line arguments to pass to the executable (optional)
            current_dir: The current working directory to set for the executable (optional)
            clean_breakpoints: Clear the breakpoints restored from the .dd64 database
                once the debuggee stops at the system breakpoint. x64dbg re-applies
                that database on every load, so without this a breakpoint left over
                from a previous session stops the first ``go``.

        Returns:
            The debug session ID
        """
        if len(target_exe.strip()) == 0 and (len(cmdline) > 0 or len(current_dir) > 0):
            raise ValueError("cmdline and current_dir cannot be provided without target_exe")

        # 给 launcher 解析用：有目标就按它的 PE 位数，没有就默认 64（x96dbg 的默认行为）
        bitness = _pe_bitness(target_exe.strip()) if target_exe.strip() else 64
        self._launch_x64dbg(bitness)
        # New debugger process => the previous int3 trampoline page is gone (local.20).
        self._pause_page = 0

        if target_exe.strip() != "":
            if not self.load_executable(target_exe.strip(), cmdline, current_dir):
                self.terminate_session()
                raise RuntimeError("Failed to load executable")
            self.wait_cmd_ready()
            if clean_breakpoints:
                # InitDebug loads the database, so this must run after the debuggee
                # exists - clearing before the launch would be undone by the load.
                self.reset_breakpoints()
            # Remembered so restart_session() can relaunch the same target without
            # the caller having to keep the path around (A11).
            self._last_target = (target_exe.strip(), cmdline, current_dir)
        return self.session_pid

    def restart_session(self, target_exe: str | None = None, cmdline: str | None = None,
                        current_dir: str | None = None, timeout: int = 25,
                        clean_breakpoints: bool = False) -> bool:
        """
        Restarts the debuggee *inside* the current debugger session.

        Unlike terminate_session() + start_session(), the debugger process stays
        alive, so the plugin connection, the breakpoint database and any analysis
        already performed survive the restart. Implemented by queueing ``stop``
        followed by ``init "<path>"`` on the debugger command thread (DbgCmdExec).

        Note: x64dbg has no ``rerun`` command — sending it yields
        ``Unknown command/expression: "rerun"``. ``init`` is the real command and
        it requires the executable path as its first argument.

        Args:
            target_exe: Executable to load; defaults to the last start_session() target
            cmdline: Command line arguments (defaults to the previous value)
            current_dir: Working directory (defaults to the previous value)
            timeout: Seconds to wait for the ``init`` sentinel and for the debuggee
            clean_breakpoints: Clear the breakpoints ``init`` restored from the .dd64
                database (same trap as start_session: the database is re-applied on
                every load, including a restart)

        Returns:
            True if a debuggee is present again after the restart
        """
        if target_exe is None:
            if self._last_target is None:
                raise RuntimeError("No previous target; call start_session() first "
                                   "or pass target_exe explicitly")
            target_exe, prev_cmdline, prev_dir = self._last_target
            cmdline = prev_cmdline if cmdline is None else cmdline
            current_dir = prev_dir if current_dir is None else current_dir

        target_exe = str(target_exe)
        if not Path(target_exe).is_file():
            raise FileNotFoundError(f"Target executable not found: {target_exe}")

        if self.is_debugging():
            self.cmd_sync("stop")
            deadline = time.time() + 10
            while self.is_debugging() and time.time() < deadline:
                time.sleep(0.05)

        args = [f'"{target_exe}"']
        if cmdline:
            args.append(f'"{cmdline}"')
        if current_dir:
            args.append(f'"{current_dir}"')

        _, executed, _ = self.dbg_cmd_exec("init " + ", ".join(args), timeout)
        if not executed:
            return False
        self._last_target = (target_exe, cmdline or "", current_dir or "")
        # The debuggee was recreated: its address space is new, so drop the cached
        # int3 trampoline page (local.20).
        self._pause_page = 0
        ready = self.wait_until_debugging(timeout)
        if ready and clean_breakpoints:
            # `init` re-loads the .dd64 database just like a fresh launch does.
            self.reset_breakpoints()
        return ready

    def start_session_attach(self, pid: int) -> int:
        """
        Start a new x64dbg session and attach to an existing process identified by pid.

        Args:
            pid (int): Process Identifier (PID) of the process to attach to.

        Returns:
            int: The debug session ID (the PID of the x64dbg process).

        Raises:
            RuntimeError: If attaching to the process fails.
        """
        self._launch_x64dbg(_process_bitness(pid))

        if not self.attach(pid):
            self.terminate_session()
            raise RuntimeError("Failed to attach to process")

        self.wait_until_debugging()
        return self.session_pid
    
    @staticmethod
    def wait_for_session(session_pid: int, timeout: int = 10) -> DebugSession:
        """
        Wait for an x64dbg session to start

        Args:
            session_pid: The session ID to wait for (debugger PID)
            timeout: The maximum time to wait in seconds

        Returns:
            The awaited debug session object
        """
        while timeout > 0:
            sessions = X64DbgClient.list_sessions()
            sessions = [s for s in sessions if s.pid == session_pid]
            if session_pid in [s.pid for s in sessions]:
                return sessions[0]
            time.sleep(0.2)
            timeout -= 0.2
        raise TimeoutError("Session did not appear in a reasonable amount of time")
    
    def attach_session(self, session_pid: int) -> None:
        """
        Attach to an existing x64dbg session

        Args:
            session_pid: The session ID to attach to (debugger PID)
        """
        session = X64DbgClient.wait_for_session(session_pid)
        self.sess_req_rep_port = session.sess_req_rep_port
        self.sess_pub_sub_port = session.sess_pub_sub_port
        self._init_connection()
        self._assert_connection_compat()
    
    def detach_session(self) -> None:
        """
        Detach from the current x64dbg session, leaving the debugger process running.
        """
        self._close_connection()

    def terminate_session(self) -> None:
        """
        End the current x64dbg session, terminating the debugger process.
        """
        sid = self.session_pid
        self._pause_page = 0  # nothing of this session's address space survives (local.20)
        self._xauto_terminate_session()
        self._close_connection()
        if not _IS_WINDOWS or self.x64dbg_path is None:
            # Remote mode — cannot poll local lockfiles for confirmation
            return
        for _ in range(100):
            time.sleep(0.2)
            if sid not in [p.pid for p in self.list_sessions()]:
                return
        raise TimeoutError("Session did not terminate in a reasonable amount of time")
    
    @staticmethod
    def _window_title_for_pid(pid: int) -> str:
        if not _IS_WINDOWS:
            return ''
        wnd_title = ctypes.create_unicode_buffer(1024)
        found_title = ''
        def EnumWindowsCb(hwnd, pid):
            nonlocal found_title
            enum_process_id = ctypes.c_ulong()
            GetWindowThreadProcessId(hwnd, ctypes.byref(enum_process_id))
            if enum_process_id.value == pid:
                GetWindowTextW(hwnd, wnd_title, 1024)
                if 'x64dbg' in wnd_title.value.lower() or 'x32dbg' in wnd_title.value.lower():
                    found_title = wnd_title.value if len(wnd_title.value) > len(found_title) else found_title
            return True
        EnumWindowsCb = EnumWindows.argtypes[0](EnumWindowsCb)
        EnumWindows(EnumWindowsCb, pid)
        return found_title

    @staticmethod
    def list_sessions() -> list[DebugSession]:
        """
        Lists all active x64dbg sessions (local only, requires Windows).

        Returns:
            A list of sessions
        """
        if not _IS_WINDOWS:
            raise NotImplementedError("Local session discovery is only available on Windows. Use connect_remote() for remote connections.")

        sessions: list[DebugSession] = []
        temp_path_cstr = ctypes.create_unicode_buffer(1024)
        if GetTempPathW(1024, temp_path_cstr) == 0:
            temp_path = "c:\\windows\\temp\\"
        else:
            temp_path = temp_path_cstr.value

        locks = glob.glob(f'{temp_path}xauto_session.*.lock')
        for lock in locks:
            while True:
                try:
                    with open(lock, 'r') as f:
                        sess_req_rep_port = int(f.readline().strip())
                        sess_pub_sub_port = int(f.readline().strip())
                        host_line = f.readline().strip()
                        host = host_line if host_line else "localhost"
                        # For local discovery, 0.0.0.0 means connect via localhost
                        if host == "0.0.0.0":
                            host = "localhost"

                    pid = int(lock.split('.')[-2])
                    if psutil.pid_exists(pid):
                        process = psutil.Process(pid)
                        try:
                            cmdline = process.cmdline()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            cmdline = []
                        try:
                            cwd = process.cwd()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            cwd = ""
                        sessions.append(DebugSession(
                            pid=pid,
                            lockfile_path=lock,
                            cmdline=cmdline,
                            cwd=cwd,
                            window_title=X64DbgClient._window_title_for_pid(pid),
                            sess_req_rep_port=sess_req_rep_port,
                            sess_pub_sub_port=sess_pub_sub_port,
                            host=host
                        ))
                        break
                    else:
                        if time.time() - os.path.getctime(lock) > 10.0:
                            logger.warning(f"Stale lockfile {lock}, removing")
                            os.unlink(lock)
                            break
                except (FileNotFoundError, psutil.AccessDenied, psutil.NoSuchProcess):
                    # The process exited or is inaccessible
                    break

        return sessions
    
