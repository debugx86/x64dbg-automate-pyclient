import logging
import os
import time
from x64dbg_automate.commands_xauto import XAutoCommandsMixin
from x64dbg_automate.models import HardwareBreakpointType, MemPage, \
    MemoryBreakpointType, MutableRegister, PageRightsConfiguration, ReferenceViewRef, StandardBreakpointType

# 之前 pause() 的失败分支直接引用了 logger，但本模块没定义它 —— 一旦真的走到
# 那条分支就是 NameError，把"pause 失败"变成"抛异常"。顺手补上。
logger = logging.getLogger(__name__)


class XAutoHighLevelCommandAbstractionMixin(XAutoCommandsMixin):
    """
    Higher-level abstractions built on top of raw XAuto command primitives
    """

    def load_executable(self, target_exe: str, cmdline: str = "", current_dir: str = "", wait_timeout: int = 10) -> bool:
        """
        Loads a new executable into the debugger. This method will block until the debugee is ready to receive a command.

        Args:
            target_exe: Path to the executable to load
            cmdline: Command line arguments to pass to the executable
            current_dir: Current working directory for the executable
            wait_timeout: Max time to wait for the debugee to be ready

        Returns:
            True if successful, False otherwise
        """
        cmdline = cmdline.replace('"', r'\"')
        current_dir = current_dir.replace('"', r'\"')
        if len(current_dir) == 0:
            current_dir = "."
        if current_dir == "." or current_dir == "":
            target_exe = os.path.abspath(target_exe)
        else:
            target_exe = os.path.abspath(os.path.join(current_dir, target_exe))
        if not self.cmd_sync(f'init "{target_exe}", "{cmdline}", "{current_dir}"'):
            return False
        return self.wait_cmd_ready(wait_timeout)

    def attach(self, pid: int, wait_timeout: int = 10) -> bool:
        """
        Attaches the debugger to a running process. This method does *NOT* block until a breakpoint has been reached.

        Args:
            pid (int): Process Identifier (PID) of the running process.
            wait_timeout (int): Maximum time (in seconds) to wait for the debugger to be ready.

        Returns:
            bool: True if the debugger attaches successfully, False otherwise.
        """
        if not self.cmd_sync(f"attach 0x{pid:x}"):
            return False
        return self.wait_until_debugging(wait_timeout)

    def detach(self, wait_timeout: int = 10) -> bool:
        """
        Detaches the debugger from the currently debugged process.
        This method will block until we are no longer debugging.

        Args:
            wait_timeout (int): Maximum time (in seconds) to wait for the debugger to be ready.

        Returns:
            bool: True if the debugger detaches successfully, False otherwise.
        """
        if not self.cmd_sync("detach"):
            return False
        return self.wait_until_not_debugging(wait_timeout)

    def unload_executable(self, wait_timeout: int = 10) -> bool:
        """
        Unloads the currently loaded executable. This method will block until the debugger is no longer debugging.

        Args:
            wait_timeout: Max time to wait for the debugger finish unloading

        Returns:
            True if successful, False otherwise
        """
        if not self.cmd_sync(f'stop'):
            return False
        return self.wait_until_not_debugging(wait_timeout)

    def stepi(self, step_count: int = 1, pass_exceptions: bool = False, swallow_exceptions: bool = False, wait_for_ready: bool = True, wait_timeout: int = 2) -> bool:
        """
        Steps into N instructions.
        
        Args:
            step_count: Number of instructions to step through
            pass_exceptions: Pass exceptions to the debugee during step
            swallow_exceptions: Swallow exceptions during step
            wait_for_ready: Block until debugger is stopped
            wait_timeout: Maximum time in seconds to wait for debugger to stop
        Returns:
            bool: True if stepping operation was successful, False otherwise.
        Raises:
            ValueError: If both pass_exceptions and swallow_exceptions are True.
        """
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        if pass_exceptions:
            prefix = 'e'
        elif swallow_exceptions:
            prefix = 'se'
        else:
            prefix = ''
        res = self.cmd_sync(f"{prefix}sti 0x{step_count:x}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def stepo(self, step_count: int = 1, pass_exceptions: bool = False, swallow_exceptions: bool = False, wait_for_ready: bool = True, wait_timeout: int = 2) -> bool:
        """
        Steps over N instructions.
        
        Args:
            step_count: Number of instructions to step through
            pass_exceptions: Pass exceptions to the debugee during step
            swallow_exceptions: Swallow exceptions during step
            wait_for_ready: Block until debugger is stopped
            wait_timeout: Maximum time in seconds to wait for debugger to stop
        Returns:
            bool: True if stepping operation was successful, False otherwise.
        Raises:
            ValueError: If both pass_exceptions and swallow_exceptions are True.
        """
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        if pass_exceptions:
            prefix = 'e'
        elif swallow_exceptions:
            prefix = 'se'
        else:
            prefix = ''
        res = self.cmd_sync(f"{prefix}sto 0x{step_count:x}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def skip(self, skip_count: int = 1, wait_for_ready: bool = True, wait_timeout: int = 2) -> bool:
        """
        Skips over N instructions.
        
        Args:
            skip_count: Number of instructions to skip
            wait_for_ready: Block until debugger is stopped
            wait_timeout: Maximum time in seconds to wait for debugger to stop
        Returns:
            bool: True if stepping operation was successful, False otherwise.
        """
        res = self.cmd_sync(f"skip {skip_count}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def ret(self, frames: int = 1, wait_timeout: int = 10) -> bool:
        """
        Steps until a ret instruction is encountered.
        
        Args:
            frames: Number of ret instructions to seek
            wait_timeout: Maximum time in seconds to wait for debugger to stop
        Returns:
            bool: True if stepping operation was successful, False otherwise.
        """
        if not self.cmd_sync(f"rtr {frames}"):
            return False
        return self.wait_cmd_ready(wait_timeout)
    
    def go(self, pass_exceptions: bool = False, swallow_exceptions: bool = False) -> bool:
        """
        Resumes the debugee. This method will block until the debugee is in the running state.

        Args:
            pass_exceptions: Pass exceptions to the debugee
            swallow_exceptions: Swallow exceptions

        Returns:
            True if successful, False otherwise
        """
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        if pass_exceptions:
            prefix = 'e'
        elif swallow_exceptions:
            prefix = 'se'
        else:
            prefix = ''
        ip_start = self.get_reg('cip')
        if not self.cmd_sync(f"{prefix}run"):
            return False
        if self.get_reg('cip') == ip_start:
            self.wait_until_running(timeout=1)
        return True

    
    def virt_alloc(self, n: int = 0x1000, addr: int = 0) -> int:
        """
        Allocates memory in the debugee's address space

        Args:
            n: Size of memory to allocate
            addr: Address to allocate memory at

        Returns:
            Address of the allocated memory
        """
        if not self.cmd_sync(f"alloc 0x{n:x}, 0x{addr:x}"):
            raise ValueError("Failed to allocate memory")
        addr, success = self.eval_sync("$result")
        if not success:
            raise ValueError("Failed to evaluate result")
        return addr
    
    def virt_free(self, addr: int) -> bool:
        """
        Frees memory in the debugee's address space

        Args:
            addr: Address to free memory at

        Returns:
            Success
        """
        if not self.cmd_sync(f"free 0x{addr:x}"):
            raise ValueError("Failed to free memory")
        return True
    
    def virt_protect(self, addr: int, page_rights: PageRightsConfiguration, guard: bool = False) -> bool:
        """
        Changes a pages memory protection in the debugee's address space, optionally setting a page guard.

        Args:
            addr: Address to operate on
            page_rights: New memory protection configuration
            guard: page guard toggle

        Returns:
            Success
        """
        rights_str = str(page_rights)
        if guard:
            rights_str = f'G{rights_str}'
        if not self.cmd_sync(f"setpagerights 0x{addr:x}, {rights_str}"):
            raise ValueError("Failed to set memory protection")
        return True
    
    def virt_query(self, addr: int) -> MemPage | None:
        """
        Retrieves information about a memory region.

        Args:
            addr: Address to query

        Returns:
            MemPage on success, None on failure
        """
        map = self.memmap()
        for m in map:
            if m.base_address <= addr < m.base_address + m.region_size:
                return m
        return None
    
    def memset(self, addr: int, byte_val: int, size: int) -> bool:
        """
        Sets memory in the debugee's address space to the specified value

        Args:
            addr: Address to set memory at
            byte_val: Value to set memory to
            size: Number of bytes to set

        Returns:
            Success
        """
        if not self.cmd_sync(f"memset 0x{addr:x}, 0x{byte_val:x}, 0x{size:x}"):
            raise ValueError("Failed to set memory")
        return True
    
    def set_reg(self, reg: MutableRegister | str, val: int) -> bool:
        """
        Set a single register or subregister to a value

        Args:
            reg: Register to set
            val: Value to set

        Returns:
            Success
        """
        reg = MutableRegister(str(reg).lower())
        if not isinstance(val, int):
            raise TypeError("val must be an integer")
        return self.cmd_sync(f'{reg}=0x{val:X}')
    
    def get_reg(self, reg: MutableRegister | str) -> int:
        """
        Get a single register or subregister

        Args:
            reg: Register to get

        Returns:
            Success
        """
        reg = MutableRegister(str(reg).lower())
        res, success = self.eval_sync(f'{reg}')
        if not success:
            raise ValueError(f"Failed to evaluate register {reg}")
        return res
    
    def pause(self, force: bool = True, fast: bool = False) -> bool:
        """
        Pauses the debugee. This method will block until the debugee is in the stopped state.

        x64dbg >= 2026-07-15 backs ``cbDebugPause`` with a break-in thread, but only
        for the *second* pause call that lands >= 2000 ms after the previous one with
        no debug event in between. When the debuggee is blocked in a kernel wait
        (console ``ReadFile``, a syscall) a single ``pause`` therefore never returns.
        This implementation issues the second pause itself instead of leaving that to
        every caller. Local patch (local.3).

        If that still fails, the two fallbacks below run in order (local.19). Both
        exist because x64dbg's break-in thread is ``ntdll!DbgUiRemoteBreakin``, whose
        first two instructions abort the thread *before* any exception is produced:

            cmp byte ptr gs:[0x60+2], 0    ; PEB.BeingDebugged
            jnz  ok
            test byte ptr ds:[0x7FFE02D4], 2
            jz   exit_thread               ; -> RtlExitUserThread(0)
        ok: mov rax, gs:[0x30]             ; TEB
            test byte ptr [rax+0x17EE], 0x20
            jnz  exit_thread
            call DbgBreakPoint             ; only now an int3 shows up

        Anti-anti-debug plugins flip PEB.BeingDebugged to 0, so the thread exits and
        x64dbg never sees ``EXCEPTION_BREAKPOINT`` - it keeps reporting "running".

        Args:
            force: try the fallbacks when the regular break-in fails
            fast: skip the BeingDebugged fallback and go straight to the int3 page.
                The int3 route stops in ~3 ms but lands on the injected thread, so
                register/stack context is gone (that thread is terminated again);
                the BeingDebugged route takes ~5 s and stops at the real execution
                point, which is what you usually want before reading registers.

        Returns:
            True if successful, False otherwise
        """
        if not self.is_debugging():
            return False
        if not self.is_running():
            return True
        # If PEB.BeingDebugged is already 0, the injected break-in thread is
        # guaranteed to exit before raising int3 (that is the first gate), so the
        # two regular pause calls below can only waste ~5 s. Skip straight to the
        # repair paths instead.
        gate_closed = self._being_debugged_gate_closed()
        started = time.time()
        if not gate_closed:
            try:
                self.cmd_sync("pause")
            except Exception:
                pass
            if self.wait_until_stopped(timeout=1.2):
                return True
            # The break-in fallback needs ~2 s since the previous pause command.
            remain = 2.25 - (time.time() - started)
            if remain > 0:
                time.sleep(remain)
            if not self.is_running():
                return True
            try:
                self.cmd_sync("pause")
            except Exception:
                pass
            if self.wait_until_stopped(timeout=3):
                return True
        if not force:
            return False
        if not fast and self._pause_via_being_debugged():
            return True
        if self._pause_via_int3_page():
            return True
        logger.warning(
            "pause() could not stop the debuggee (break-in thread died before raising "
            "int3, and both fallbacks failed). suspend_debuggee() freezes the process "
            "via NtSuspendProcess instead, at the cost of x64dbg still reporting running.")
        return False

    def _being_debugged_gate_closed(self) -> bool:
        """True when PEB.BeingDebugged == 0, i.e. DbgUiRemoteBreakin will bail out."""
        try:
            peb, ok = self.eval_sync("peb()")
            if not ok or not peb:
                return False
            return self.read_memory(peb + 2, 1)[:1] == b"\x00"
        except Exception:
            return False

    def _pause_via_being_debugged(self, timeout: float = 2.5) -> bool:
        """Re-open the first gate: write PEB.BeingDebugged back to 1.

        ``ntdll!DbgUiRemoteBreakin`` checks that byte first and bails out when it is
        0 - exactly what anti-anti-debug plugins write. Restoring it for the duration
        of one break-in lets x64dbg's own mechanism work again; the original value is
        put back afterwards, so the debuggee never observes a debugger while it runs.
        """
        try:
            peb, ok = self.eval_sync("peb()")
        except Exception:
            return False
        if not ok or not peb:
            return False
        try:
            original = self.read_memory(peb + 2, 1)
        except Exception:
            return False
        if original[:1] == b"\x01":
            # Gate already open, so writing it cannot change anything - let the
            # int3 fallback have a go instead of waiting for another 2 s cycle.
            return False
        try:
            self.write_memory(peb + 2, b"\x01")
        except Exception:
            return False
        try:
            for _ in range(2):
                if not self.is_running():
                    return True
                try:
                    self.cmd_sync("pause")
                except Exception:
                    pass
                if self.wait_until_stopped(timeout=timeout):
                    logger.info("pause(): stopped after restoring PEB.BeingDebugged")
                    return True
                time.sleep(2.1)
            return False
        finally:
            try:
                self.write_memory(peb + 2, original)
            except Exception:
                logger.warning("could not restore PEB.BeingDebugged to %r", original)

    def _pause_via_int3_page(self, timeout: float = 3.0) -> bool:
        """Inject a thread that starts on a *registered* breakpoint.

        A raw ``0xCC`` byte is not enough: x64dbg only stops when the int3 maps to a
        breakpoint it knows about, otherwise the first-chance exception is passed
        through and the thread simply exits (measured under ScyllaHide: log shows
        ``EXCEPTION_DEBUG_INFO dwFirstChance: 1`` followed by ``线程退出``, state stays
        running). So the page gets a real software breakpoint first, then the thread
        is created on it - the resulting hit is indistinguishable from a user
        breakpoint, and this path never touches ``DbgUiRemoteBreakin``, so neither of
        its gates matters. Registering is not enough while the debuggee runs, so the
        0xCC is written by us as well (local.20 - measured: without it the very first
        call in a session silently fails because x64dbg patches bp bytes on the next
        pause only).

        The page is allocated once and reused (validated against the memory map, so a
        restarted debuggee does not inherit a dead address); the injected thread is
        terminated only after switching the active thread back to the main one, so
        register reads stay usable.
        """
        page = self._valid_pause_page()
        tid = None
        landed = False
        try:
            if not page:
                page = int(self.virt_alloc(0x1000))
                if not page:
                    return False
                # ret: once the breakpoint is cleared, the thread falls through and
                # exits instead of executing the rest of the page.
                if not self.write_memory(page, b"\xC3"):
                    return False
                self._pause_page = page
            if not self.set_breakpoint(page):
                return False
            # x64dbg only *registers* a software breakpoint while the debuggee runs -
            # the 0xCC is patched into memory on the next pause, which by then is too
            # late: CreateRemoteThread (that is what `createthread` calls) starts the
            # thread immediately, so it executes the `ret` and exits without ever
            # stopping. Measured: a fresh session that never paused before returns
            # False here, while a session that already paused once returns True.
            # Writing the int3 ourselves makes the first shot work; x64dbg still owns
            # the entry in its breakpoint table, so the hit is reported as a normal
            # user breakpoint.
            if not self.write_memory(page, b"\xCC"):
                self._clear_pause_bp(page)
                return False
            landed = True
            tid = self.thread_create(page, 0)
            if not tid:
                self._clear_pause_bp(page)
                return False
            # The thread only runs while the debuggee runs; hitting the breakpoint is
            # what stops us again.
            self.go()
            stopped = bool(self.wait_until_stopped(timeout=timeout))
            self._clear_pause_bp(page)
            if not stopped:
                return False
            # The stop can be a mirage: plugins that hide threads from the debugger
            # (ScyllaHide's NtSetInformationThreadHook) let the hit be reported and
            # then keep going, so confirm it held before telling the caller we paused.
            time.sleep(0.15)
            if self.is_running():
                return False
            # The active thread right now is the injected one. Killing it first leaves
            # the debugger with a dead active thread, and every later register read
            # answers 0 while pause() claims success. Move to the main thread first
            # (`switchthread` without an argument means fdProcessInfo->dwThreadId),
            # then clean the injected thread up.
            try:
                self.cmd_sync("switchthread")
            except Exception:
                pass
            try:
                self.thread_terminate(int(tid))
            except Exception:
                pass
            cip, ok = self.eval_sync("cip")
            if not ok or not cip:
                logger.warning("pause(): int3 fallback stopped the debuggee but the "
                               "active-thread context is unusable (cip=%r)", cip)
            else:
                logger.info("pause(): stopped via injected breakpoint at %#x (cip=%#x)",
                            page, cip)
            return True
        except Exception:
            if landed or page:
                self._clear_pause_bp(page)
            return False

    def _valid_pause_page(self) -> int:
        """Cached int3 trampoline page, or 0 when it no longer belongs to this debuggee."""
        page = int(getattr(self, "_pause_page", 0) or 0)
        if not page:
            return 0
        try:
            for m in self.memmap() or []:
                base = int(getattr(m, "base_address", 0) or 0)
                size = int(getattr(m, "region_size", 0) or 0)
                if base and base <= page < base + max(size, 0x1000):
                    return page
        except Exception:
            pass
        # The page is gone (new session / restarted debuggee): drop the cache so the
        # caller allocates a fresh one instead of pointing a thread at a dead address.
        self._pause_page = 0
        return 0

    def _clear_pause_bp(self, page: int) -> None:
        try:
            if page:
                self.clear_breakpoint(page)
        except Exception:
            pass

    def suspend_debuggee(self) -> bool:
        """
        Freezes every debuggee thread from outside the debugger.

        Fallback for the pause path. x64dbg stops a debuggee by injecting
        ``ntdll!DbgUiRemoteBreakin``, and that routine exits *before* raising int3
        when ``PEB.BeingDebugged`` is 0 (what anti-anti-debug plugins enforce) or
        when ``[TEB+0x17EE] & 0x20`` is set. ``pause()`` now repairs the first case
        itself, but if both of its fallbacks fail this one still works: NtSuspendProcess
        does not involve the debugger at all.

        Note this is *not* a debugger pause: x64dbg keeps reporting "running" and
        register reads stay frozen snapshots. What it gives you is a process that
        stops executing, so memory stops changing (safe to dump/scan), until
        resume_debuggee() is called.

        Returns:
            True if every thread was suspended
        """
        if not self.is_debugging():
            return False
        pid = self.debugee_pid()
        if not pid:
            return False
        from x64dbg_automate.win32 import suspend_process
        return bool(suspend_process(int(pid)))

    def resume_debuggee(self) -> bool:
        """
        Thaws a debuggee frozen by suspend_debuggee() (NtResumeProcess).

        Returns:
            True if the resume call succeeded
        """
        if not self.is_debugging():
            return False
        pid = self.debugee_pid()
        if not pid:
            return False
        from x64dbg_automate.win32 import resume_process
        return bool(resume_process(int(pid)))
    
    def set_breakpoint(self, address_or_symbol: int | str, name: str | None = None, bp_type: StandardBreakpointType = StandardBreakpointType.Short, singleshoot: bool = False) -> bool:
        """
        Sets a software breakpoint at the specified address or symbol.

        Args:
            address_or_symbol: Address or symbol to set the breakpoint at
            name: Optional name for the breakpoint
            bp_type: Type of software breakpoint to set
            singleshoot: Set a single-shot breakpoint

        Returns:
            Success
        """
        bp_type_str = str(bp_type).lower()
        if singleshoot and bp_type_str != "ss":
            bp_type_str = f'ss{bp_type_str}'
        if isinstance(address_or_symbol, int):
            name = name or f"bpx_{address_or_symbol:x}"
            return self.cmd_sync(f'bpx 0x{address_or_symbol:x}, "{name}", {bp_type_str}')
        else:
            name = name or f"bpx_{address_or_symbol.replace(' ', '_')}"
            if '"' in name:
                raise ValueError("Name cannot contain double quotes")
            return self.cmd_sync(f'bpx {address_or_symbol}, "{name}", {bp_type_str}')
    
    def set_hardware_breakpoint(self, address_or_symbol: int | str, bp_type: HardwareBreakpointType = HardwareBreakpointType.x, size: int = 1) -> bool:
        """
        Sets a hardware breakpoint at the specified address or symbol.

        Args:
            address_or_symbol: Address or symbol to set the breakpoint at
            bp_type: Type of software breakpoint to set
            size: breakpoint size, one of [1, 2, 4, 8]

        Returns:
            Success
        """
        if size not in [1, 2, 4, 8]:
            raise ValueError("Invalid size")
        if isinstance(address_or_symbol, int):
            return self.cmd_sync(f'bph 0x{address_or_symbol:x}, {bp_type}, {size}')
        else:
            return self.cmd_sync(f'bph {address_or_symbol}, {bp_type}, {size}')
    
    def set_memory_breakpoint(self, address_or_symbol: int | str, bp_type: MemoryBreakpointType = MemoryBreakpointType.a, singleshoot: bool = False) -> bool:
        """
        Sets a memory breakpoint at the specified address or symbol.

        Args:
            address_or_symbol: Address or symbol to set the breakpoint at
            bp_type: Type of software breakpoint to set
            singleshoot: Set a single-shot breakpoint

        Returns:
            Success
        """
        if isinstance(address_or_symbol, int):
            return self.cmd_sync(f'bpm 0x{address_or_symbol:x}, {int(not singleshoot)}, {bp_type}')
        else:
            return self.cmd_sync(f'bpm {address_or_symbol}, {int(not singleshoot)}, {bp_type}')

    def clear_breakpoint(self, address_name_symbol_or_none: int | str | None = None) -> bool:
        """
        Clears software breakpoint at the specified address, name, or symbol.

        Args:
            address_name_symbol_or_none: Address or symbol to remove the breakpoint at (None removes all breakpoints of this type)

        Returns:
            Success
        """
        if address_name_symbol_or_none is None:
            return self.cmd_sync('bpc')
        if isinstance(address_name_symbol_or_none, int):
            return self.cmd_sync(f'bpc 0x{address_name_symbol_or_none:x}')
        return self.cmd_sync(f'bpc "{address_name_symbol_or_none}"')
    
    def clear_hardware_breakpoint(self, address_symbol_or_none: int | str | None = None) -> bool:
        """
        Clears hardware breakpoint at the specified address or symbol.

        Args:
            address_symbol_or_none: Address or symbol to remove the breakpoint at (None removes all breakpoints of this type)
            
        Returns:
            Success
        """
        if address_symbol_or_none is None:
            return self.cmd_sync('bphc')
        if isinstance(address_symbol_or_none, int):
            return self.cmd_sync(f'bphc 0x{address_symbol_or_none:x}')
        return self.cmd_sync(f'bphc {address_symbol_or_none}')
    
    def clear_memory_breakpoint(self, address_symbol_or_none: int | str | None = None) -> bool:
        """
        Clears memory breakpoint at the specified address or symbol.

        Args:
            address_symbol_or_none: Address or symbol to remove the breakpoint at (None removes all breakpoints of this type)
            
        Returns:
            Success
        """
        if address_symbol_or_none is None:
            return self.cmd_sync('bpmc')
        if isinstance(address_symbol_or_none, int):
            return self.cmd_sync(f'bpmc 0x{address_symbol_or_none:x}')
        return self.cmd_sync(f'bpmc {address_symbol_or_none}')
    
    def toggle_breakpoint(self, address_name_symbol_or_none: int | str | None = None, on: bool = True) -> bool:
        """
        Toggles software breakpoint at the specified address or symbol.

        Args:
            address_name_symbol_or_none: Address, name, or symbol to toggle the breakpoint at
            on: Enable or disable the breakpoint
            
        Returns:
            Success
        """
        toggle_cmd = 'bpe' if on else 'bpd'
        if isinstance(address_name_symbol_or_none, int):
            return self.cmd_sync(f'{toggle_cmd} 0x{address_name_symbol_or_none:x}')
        elif address_name_symbol_or_none is None:
            return self.cmd_sync(f'{toggle_cmd}')
        else:
            return self.cmd_sync(f'{toggle_cmd} {address_name_symbol_or_none}')
    
    def toggle_hardware_breakpoint(self, address_symbol_or_none: int | str | None = None, on: bool = True) -> bool:
        """
        Toggles hardware breakpoint at the specified address or symbol.

        Args:
            address_symbol_or_none: Address or symbol to toggle the breakpoint at
            on: Enable or disable the breakpoint
            
        Returns:
            Success
        """
        toggle_cmd = 'bphe' if on else 'bphd'
        if isinstance(address_symbol_or_none, int):
            return self.cmd_sync(f'{toggle_cmd} 0x{address_symbol_or_none:x}')
        elif address_symbol_or_none is None:
            return self.cmd_sync(f'{toggle_cmd}')
        else:
            return self.cmd_sync(f'{toggle_cmd} {address_symbol_or_none}')
    
    def toggle_memory_breakpoint(self, address_symbol_or_none: int | str | None = None, on: bool = True) -> bool:
        """
        Toggles memory breakpoint at the specified address or symbol.

        Args:
            address_symbol_or_none: Address or symbol to toggle the breakpoint at
            on: Enable or disable the breakpoint
            
        Returns:
            Success
        """
        toggle_cmd = 'bpme' if on else 'bpmd'
        if isinstance(address_symbol_or_none, int):
            return self.cmd_sync(f'{toggle_cmd} 0x{address_symbol_or_none:x}')
        elif address_symbol_or_none is None:
            return self.cmd_sync(f'{toggle_cmd}')
        else:
            return self.cmd_sync(f'{toggle_cmd} {address_symbol_or_none}')

    def set_label_at(self, address: int, text: str) -> bool:
        """
        Sets a label at the specified address

        Args:
            address: Address to set the label at
            text: Label text

        Returns:
            Success
        """
        if '"' in text:
            raise ValueError("Text cannot contain double quotes")
        return self.cmd_sync(f'lblset 0x{address:x}, "{text}"')

    def del_label_at(self, address: int) -> bool:
        """
        Deletes a label at the specified address

        Args:
            address: Address to clear the label at

        Returns:
            Success
        """
        return self.cmd_sync(f'lbldel 0x{address:x}')

    def set_comment_at(self, address: int, text: str) -> bool:
        """
        Sets a comment at the specified address

        Args:
            address: Address to set the comment at
            text: comment text

        Returns:
            Success
        """
        if '"' in text:
            raise ValueError("Text cannot contain double quotes")
        return self.cmd_sync(f'cmtset 0x{address:x}, "{text}"')

    def del_comment_at(self, address: int) -> bool:
        """
        Deletes a comment at the specified address

        Args:
            address: Address to clear the comment at

        Returns:
            Success
        """
        return self.cmd_sync(f'cmtdel 0x{address:x}')

    def hide_debugger_peb(self) -> bool:
        """
        Hides the debugger in the debugee's PEB

        Returns:
            Success
        """
        return self.cmd_sync(f'hide')

    def debugee_pid(self) -> int | None:
        """
        Retrieves the PID of the debugee

        Returns:
            PID of the debugee, or None if the debugger is not debugging
        """
        if self.is_debugging():
            pid, res = self.eval_sync(f'pid')
            if res:
                return pid
        return None

    def thread_create(self, addr: int, arg: int = 0) -> int | None:
        """
        Create a new thread in the debugee.

        Args:
            addr: Address of the thread entry point
            arg: Argument to pass to the thread
        """
        success = self.cmd_sync(f'createthread 0x{addr:x}, 0x{arg:x}')
        if not success:
            return None
        tid, success = self.eval_sync('$result')
        if not success:
            return None
        return tid

    def thread_terminate(self, tid: int):
        """
        Kills a thread in the debugee.

        Args:
            tid: Thread ID to kill
        """
        return self.cmd_sync(f'killthread 0x{tid:x}')

    def thread_pause(self, tid: int):
        """
        Pauses a thread in the debugee.

        Args:
            tid: Thread ID to kill
        """
        return self.cmd_sync(f'suspendthread 0x{tid:x}')

    def thread_resume(self, tid: int):
        """
        Resumes a thread in the debugee.

        Args:
            tid: Thread ID to kill
        """
        return self.cmd_sync(f'resumethread 0x{tid:x}')

    def switch_thread(self, tid: int):
        """
        Switches the currently observed debugger thread.

        Args:
            tid: Thread ID to kill
        """
        return self.cmd_sync(f'switchthread 0x{tid:x}')
    
    def assemble_at(self, addr: int, instr: str) -> int | None:
        """
        Assembles a single instruction at the specified address

        Args:
            addr: Address to assemble at
            instr: Instruction to assemble

        Returns:
            The size of the assembled instruction, or None on failure
        """
        res = self._assemble_at(addr, instr)
        if not res:
            return None
        ins = self.disassemble_at(addr)
        if not ins:
            return None
        return ins.instr_size
    
    # GUI Commands
    
    def log(self, fmt_str: str) -> int | None:
        """
        Logs a string to the x64dbg log window

        Args:
            fmt_str: format String to log

        Returns:
            Success
        """
        sanitized_str = fmt_str.replace('"', '\\"')
        return self.cmd_sync(f'log "{sanitized_str}"')

    def trace_into(
        self,
        break_condition: str,
        max_steps: int = 50000,
        log_text: str | None = None,
        log_condition: str | None = None,
        command_text: str | None = None,
        command_condition: str | None = None,
        log_file: str | None = None,
        pass_exceptions: bool = False,
        swallow_exceptions: bool = False,
        wait_timeout: int = 60,
    ) -> bool:
        """
        Performs a conditional trace-into (single-stepping into calls) until the break condition
        evaluates to true or max_steps is reached.

        Optionally configures trace logging, log conditions, command execution, and log file
        output before starting the trace. These properties persist across traces until cleared.

        Args:
            break_condition: x64dbg expression that stops the trace when it evaluates to non-zero
                (e.g. "cip == 0x401000", "eax == 0", "[esp] > 0x100")
            max_steps: Maximum number of steps before giving up (default 50000)
            log_text: If set, formatted text to log on each trace step (e.g. "{p:cip} {i:cip}")
            log_condition: Expression controlling when log_text is printed (default "1" = always)
            command_text: If set, x64dbg command to execute on each trace step
            command_condition: Expression controlling when command_text runs (defaults to break_condition)
            log_file: If set, path to redirect trace log output to a file
            pass_exceptions: Pass exceptions to the debuggee during trace
            swallow_exceptions: Swallow exceptions during trace
            wait_timeout: Maximum time in seconds to wait for the trace to complete

        Returns:
            True if the trace completed successfully, False otherwise

        Raises:
            ValueError: If both pass_exceptions and swallow_exceptions are True
        """
        return self._trace_conditional(
            "ticnd", break_condition, max_steps, log_text, log_condition,
            command_text, command_condition, log_file, pass_exceptions,
            swallow_exceptions, wait_timeout,
        )

    def trace_over(
        self,
        break_condition: str,
        max_steps: int = 50000,
        log_text: str | None = None,
        log_condition: str | None = None,
        command_text: str | None = None,
        command_condition: str | None = None,
        log_file: str | None = None,
        pass_exceptions: bool = False,
        swallow_exceptions: bool = False,
        wait_timeout: int = 60,
    ) -> bool:
        """
        Performs a conditional trace-over (single-stepping over calls) until the break condition
        evaluates to true or max_steps is reached.

        Optionally configures trace logging, log conditions, command execution, and log file
        output before starting the trace. These properties persist across traces until cleared.

        Args:
            break_condition: x64dbg expression that stops the trace when it evaluates to non-zero
                (e.g. "cip == 0x401000", "eax == 0", "[esp] > 0x100")
            max_steps: Maximum number of steps before giving up (default 50000)
            log_text: If set, formatted text to log on each trace step (e.g. "{p:cip} {i:cip}")
            log_condition: Expression controlling when log_text is printed (default "1" = always)
            command_text: If set, x64dbg command to execute on each trace step
            command_condition: Expression controlling when command_text runs (defaults to break_condition)
            log_file: If set, path to redirect trace log output to a file
            pass_exceptions: Pass exceptions to the debuggee during trace
            swallow_exceptions: Swallow exceptions during trace
            wait_timeout: Maximum time in seconds to wait for the trace to complete

        Returns:
            True if the trace completed successfully, False otherwise

        Raises:
            ValueError: If both pass_exceptions and swallow_exceptions are True
        """
        return self._trace_conditional(
            "tocnd", break_condition, max_steps, log_text, log_condition,
            command_text, command_condition, log_file, pass_exceptions,
            swallow_exceptions, wait_timeout,
        )

    def trace_set_log_file(self, path: str) -> bool:
        """
        Redirects trace log output to a file.

        Args:
            path: File path to write trace log output to

        Returns:
            True if successful, False otherwise
        """
        path = path.replace('"', '\\"')
        return self.cmd_sync(f'TraceSetLogFile "{path}"')

    def _trace_conditional(
        self,
        trace_cmd: str,
        break_condition: str,
        max_steps: int,
        log_text: str | None,
        log_condition: str | None,
        command_text: str | None,
        command_condition: str | None,
        log_file: str | None,
        pass_exceptions: bool,
        swallow_exceptions: bool,
        wait_timeout: int,
    ) -> bool:
        """
        Internal helper to configure and execute a conditional trace command.

        Args:
            trace_cmd: The x64dbg trace command to use ("ticnd" or "tocnd")
            break_condition: Expression that stops the trace when non-zero
            max_steps: Maximum step count
            log_text: Optional log text for each step
            log_condition: Optional condition for log text
            command_text: Optional command to run each step
            command_condition: Optional condition for command execution
            log_file: Optional file path for log redirection
            pass_exceptions: Pass exceptions to the debuggee
            swallow_exceptions: Swallow exceptions
            wait_timeout: Max seconds to wait for trace completion

        Returns:
            True if successful, False otherwise

        Raises:
            ValueError: If both pass_exceptions and swallow_exceptions are True
        """
        if pass_exceptions and swallow_exceptions:
            raise ValueError("Cannot pass and swallow exceptions at the same time")

        # Configure trace properties before starting
        if log_file is not None:
            log_file_escaped = log_file.replace('"', '\\"')
            if not self.cmd_sync(f'TraceSetLogFile "{log_file_escaped}"'):
                return False

        if log_text is not None:
            log_text_escaped = log_text.replace('"', '\\"')
            cmd = f'TraceSetLog "{log_text_escaped}"'
            if log_condition is not None:
                cmd += f", {log_condition}"
            if not self.cmd_sync(cmd):
                return False

        if command_text is not None:
            command_text_escaped = command_text.replace('"', '\\"')
            cmd = f'TraceSetCommand "{command_text_escaped}"'
            if command_condition is not None:
                cmd += f", {command_condition}"
            if not self.cmd_sync(cmd):
                return False

        # Build exception prefix
        if pass_exceptions:
            prefix = 'e'
        elif swallow_exceptions:
            prefix = 'se'
        else:
            prefix = ''

        # Execute the trace
        if not self.cmd_sync(f'{prefix}{trace_cmd} {break_condition}, 0x{max_steps:x}'):
            return False
        return self.wait_cmd_ready(wait_timeout)

    def gui_show_reference_view(self, name: str, refs: list[ReferenceViewRef]) -> bool:
        """
        Shows a reference view populated with refs.

        Args:
            refs: A list of addresses and text to display in the reference view

        Returns:
            Success
        """
        name = name.replace('"', '\\"')
        if not self.cmd_sync(f'refinit "{name}"'):
            return False
        for ref in refs:
            text = ref.text.replace('"', '\\"')
            if not self.cmd_sync(f'refadd 0x{ref.address:x}, "{text}"'):
                return False
