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