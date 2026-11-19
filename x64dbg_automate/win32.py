import ctypes


K32 = ctypes.windll.kernel32
U32 = ctypes.windll.user32

CloseHandle = K32.CloseHandle
CloseHandle.argtypes = [ctypes.c_void_p]

OpenProcess = K32.OpenProcess
OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]

CreateRemoteThread = K32.CreateRemoteThread
CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]

WaitForSingleObject = K32.WaitForSingleObject
WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

SetConsoleCtrlHandler = K32.SetConsoleCtrlHandler
SetConsoleCtrlHandler.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int), ctypes.c_bool]

GetTempPathW = K32.GetTempPathW
GetTempPathW.argtypes = [ctypes.c_uint32, ctypes.c_wchar_p]

EnumWindows = U32.EnumWindows
EnumWindows.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p), ctypes.c_void_p]

GetWindowTextW = U32.GetWindowTextW
GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]

GetWindowThreadProcessId = U32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

# --- modal dialog dismissal -------------------------------------------------
# x64dbg reports script completion (and several other events) through a modal
# MessageBox. A modal box stops the GUI thread from pumping, and every bridge
# call the plugin makes (DbgIsDebugging, DbgCmdExec, DbgDisasmAt...) queues
# behind it: the plugin's REP socket goes quiet and the client times out with
# "Resource temporarily unavailable", after which everything fails with
# "Not connected". Closing the box from outside is the only way to recover
# without a human clicking OK.
GetClassNameW = U32.GetClassNameW
GetClassNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]

IsWindowVisible = U32.IsWindowVisible
IsWindowVisible.argtypes = [ctypes.c_void_p]
IsWindowVisible.restype = ctypes.c_bool

PostMessageW = U32.PostMessageW
PostMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_size_t]
PostMessageW.restype = ctypes.c_bool

WM_CLOSE = 0x0010
# x64dbg is a Qt app: its message boxes are "Qt5QWindowIcon", not the Win32
# "#32770" class. Matching only the latter silently closed nothing (measured).
DIALOG_CLASSES = ("#32770", "Qt5QWindowIcon")
# The main window title is "<module> - PID: <n> - 模块: ... - x64dbg"; every other
# visible top-level window of the process is a message box worth closing.
MAIN_WINDOW_HINT = " - PID: "


def close_dialog_boxes(pid: int, classes: tuple = DIALOG_CLASSES, limit: int = 8) -> int:
    """Post WM_CLOSE to every visible message box owned by `pid`; returns how many.

    WM_CLOSE is honoured by Qt's QMessageBox (verified against a live
    "脚本执行完毕" box: the hwnd becomes invalid within a second).
    """
    closed = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def _cb(hwnd, _lparam):
        if len(closed) >= limit:
            return False
        owner = ctypes.c_ulong(0)
        GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != int(pid):
            return True
        cls = ctypes.create_unicode_buffer(128)
        GetClassNameW(hwnd, cls, 128)
        if cls.value not in classes:
            return True
        title = ctypes.create_unicode_buffer(256)
        GetWindowTextW(hwnd, title, 256)
        if MAIN_WINDOW_HINT in title.value:
            return True
        if not IsWindowVisible(hwnd):
            return True
        PostMessageW(hwnd, WM_CLOSE, 0, 0)
        closed.append(hwnd)
        return True

    EnumWindows(_cb, 0)
    return len(closed)

# --- process-wide suspend/resume (outside the debugger) ---------------------
# x64dbg stops a debuggee by injecting a break-in thread; anti-anti-debug plugins
# (ScyllaHide) hook thread creation and swallow it, so pause() never returns.
# NtSuspendProcess freezes every thread at the kernel level and does not go
# through the debugger at all.
NTDLL = ctypes.windll.ntdll

NtSuspendProcess = NTDLL.NtSuspendProcess
NtSuspendProcess.argtypes = [ctypes.c_void_p]
NtSuspendProcess.restype = ctypes.c_long

NtResumeProcess = NTDLL.NtResumeProcess
NtResumeProcess.argtypes = [ctypes.c_void_p]
NtResumeProcess.restype = ctypes.c_long

PROCESS_SUSPEND_RESUME = 0x0800


def suspend_process(pid: int) -> bool:
    """Freeze every thread of `pid`. Returns True on success."""
    handle = OpenProcess(PROCESS_SUSPEND_RESUME, False, int(pid))
    if not handle:
        return False
    try:
        return NtSuspendProcess(handle) == 0
    finally:
        CloseHandle(handle)


def resume_process(pid: int) -> bool:
    """Thaw every thread of `pid` (undo suspend_process). Returns True on success."""
    handle = OpenProcess(PROCESS_SUSPEND_RESUME, False, int(pid))
    if not handle:
        return False
    try:
        return NtResumeProcess(handle) == 0
    finally:
        CloseHandle(handle)