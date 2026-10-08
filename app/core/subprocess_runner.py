"""The only way this application runs an external program.

Every rule here exists because scanners and git operate on untrusted code:

* **List-form arguments, never ``shell=True``.** A file or URL containing
  ``; rm -rf /`` stays a single inert argument. A plain string is rejected
  outright so nobody can "just pass a command line".
* **Resolved absolute executable.** On Windows, process creation can pick up an
  executable from the current directory; a cloned repository containing its own
  ``git.exe`` must never be run. We resolve the tool first and refuse anything
  that lives inside the scratch root (i.e. untrusted content).
* **Working directory confined to scratch.**
* **Minimal environment.** The child gets an allowlisted environment, so the
  API key and any future LLM credentials are never inherited by a process that
  is reading attacker-controlled files.
* **Hard timeout with process-tree kill.** Semgrep spawns a native worker; on
  timeout the whole tree is terminated, not just the parent.
* **Bounded output.** stdout/stderr go to anonymous temp files and are read back
  up to a size cap, so a hostile input cannot exhaust memory through output.
* **No elevation.** Refuses to run as root/Administrator unless explicitly
  configured.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.paths import is_within

log = get_logger(__name__)

# Variables a child process may inherit. Everything else is dropped.
_ENV_ALLOWLIST = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC",
    "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
    "PROGRAMDATA", "LANG", "LC_ALL",
)


class ToolNotFoundError(FileNotFoundError):
    """The requested executable is not installed (or not where it was configured)."""


class UnsafeInvocationError(ValueError):
    """The call violates one of the subprocess safety rules."""


@dataclass(frozen=True)
class ToolResult:
    args: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool
    output_truncated: bool


def is_elevated() -> bool:
    """True when running as root (POSIX) or an elevated Administrator (Windows)."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0  # type: ignore[attr-defined,unused-ignore]


def resolve_executable(name_or_path: str | os.PathLike[str]) -> Path:
    """Resolve a tool to an absolute path that is not inside untrusted content."""
    candidate = Path(name_or_path)
    if candidate.is_absolute() or candidate.parent != Path("."):
        resolved = candidate if candidate.is_file() else None
    else:
        # Search PATH explicitly -- never the current directory.
        found = shutil.which(str(candidate), path=os.environ.get("PATH", ""))
        resolved = Path(found) if found else None
    if resolved is None:
        raise ToolNotFoundError(f"executable not found: {name_or_path}")
    resolved = resolved.resolve()
    if is_within(resolved, get_settings().scratch_root):
        raise UnsafeInvocationError(f"refusing to execute a binary from scratch space: {resolved}")
    return resolved


def _child_env(extra_env: Mapping[str, str] | None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.upper() in _ENV_ALLOWLIST}
    # Semgrep on Windows needs UTF-8 mode to print non-ASCII rule messages.
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    if extra_env:
        env.update(extra_env)
    return env


def _windows_system_dir() -> Path:
    """System32 as reported by the OS -- never derived from an environment variable."""
    buffer = ctypes.create_unicode_buffer(260)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))  # type: ignore[attr-defined]
    if not 0 < length < len(buffer):
        raise OSError("could not determine the Windows system directory")
    return Path(buffer.value)


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        # taskkill /T terminates the child's descendants as well.
        # Found by scanning this code base with its own scanners:
        #  1. Bandit B607 -- a bare "taskkill" is resolved via the search path;
        #  2. the first fix built the path from %SYSTEMROOT%, and Semgrep flagged
        #     that as environment-tainted process arguments. A fix introducing a
        #     new finding is exactly what verification gate 2 exists to catch.
        # The system directory now comes from the Windows API.
        taskkill = _windows_system_dir() / "taskkill.exe"
        subprocess.run(  # noqa: S603 -- OS-reported absolute system binary, integer PID argument
            [str(taskkill), "/F", "/T", "/PID", str(int(proc.pid))],
            capture_output=True, timeout=30, check=False,
        )
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # type: ignore[attr-defined,unused-ignore]
        except ProcessLookupError:
            pass
    try:
        proc.kill()
    except OSError:
        pass


def _read_capped(handle, limit: int) -> tuple[str, bool]:  # noqa: ANN001
    handle.seek(0)
    data = handle.read(limit + 1)
    truncated = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), truncated


def run_tool(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    extra_env: Mapping[str, str] | None = None,
    max_output_bytes: int | None = None,
    confine_cwd: bool = True,
) -> ToolResult:
    """Run an external tool safely and return its (bounded) output.

    Never raises on a non-zero exit code -- scanners use exit codes to mean
    "findings present". Raises only when the call itself is unsafe or impossible.
    """
    settings = get_settings()
    if isinstance(args, (str, bytes)) or not args:
        raise UnsafeInvocationError("args must be a non-empty list of strings, never a command string")
    if not all(isinstance(a, str) for a in args):
        raise UnsafeInvocationError("every argument must be a str")
    if any("\x00" in a for a in args):
        raise UnsafeInvocationError("NUL byte in argument")
    if not settings.allow_elevated and is_elevated():
        raise UnsafeInvocationError("refusing to run external tools with root/Administrator privileges")

    cwd = Path(cwd)
    if not cwd.is_dir():
        raise UnsafeInvocationError(f"working directory does not exist: {cwd}")
    if confine_cwd and not is_within(cwd, settings.scratch_root):
        raise UnsafeInvocationError("working directory must be inside the scratch root")

    executable = resolve_executable(args[0])
    argv = [str(executable), *args[1:]]
    limit = max_output_bytes or settings.max_tool_output_bytes

    popen_kwargs: dict[str, object] = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    else:
        popen_kwargs["start_new_session"] = True

    started = time.monotonic()
    timed_out = False
    with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
        proc = subprocess.Popen(  # noqa: S603 -- list args, resolved executable, no shell
            argv,
            cwd=str(cwd),
            env=_child_env(extra_env),
            stdin=subprocess.DEVNULL,
            stdout=out_f,
            stderr=err_f,
            shell=False,
            **popen_kwargs,  # type: ignore[arg-type]
        )
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(proc)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                log.error("process did not exit after kill", extra={"tool": executable.name})
        duration = time.monotonic() - started
        stdout, trunc_out = _read_capped(out_f, limit)
        stderr, trunc_err = _read_capped(err_f, limit)

    log.info(
        "tool finished",
        extra={"tool": executable.name, "returncode": proc.returncode,
               "duration_s": round(duration, 2), "timed_out": timed_out},
    )
    return ToolResult(
        args=tuple(argv),
        returncode=None if timed_out else proc.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_s=duration,
        timed_out=timed_out,
        output_truncated=trunc_out or trunc_err,
    )


def read_capped_file(path: Path, limit: int | None = None) -> str:
    """Read a tool's report file with the same size cap as its stdout."""
    limit = limit or get_settings().max_tool_output_bytes
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"tool report exceeds size cap ({size} > {limit} bytes)")
    return path.read_text(encoding="utf-8", errors="replace")


__all__ = [
    "ToolNotFoundError", "ToolResult", "UnsafeInvocationError",
    "is_elevated", "read_capped_file", "resolve_executable", "run_tool",
]
