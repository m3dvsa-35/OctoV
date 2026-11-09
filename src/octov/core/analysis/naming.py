"""Suggested function names from the Windows APIs a function uses.

``sub_401000`` tells an analyst nothing; ``net_http_401000`` tells them where to
look first. Names are only *suggested*: the analyst's own names always win.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence

from octov.core.static.pe_parser import normalize_api

API_FAMILIES: dict[str, tuple[str, ...]] = {
    "net_http": (
        "InternetOpen",
        "InternetOpenUrl",
        "InternetConnect",
        "HttpOpenRequest",
        "HttpSendRequest",
        "InternetReadFile",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
        "WinHttpReceiveResponse",
        "WinHttpReadData",
        "URLDownloadToFile",
    ),
    "net_socket": (
        "WSAStartup",
        "socket",
        "connect",
        "send",
        "recv",
        "bind",
        "listen",
        "accept",
        "gethostbyname",
        "getaddrinfo",
        "WSASocket",
        "WSAConnect",
        "closesocket",
    ),
    "file_io": (
        "CreateFile",
        "ReadFile",
        "WriteFile",
        "DeleteFile",
        "MoveFile",
        "CopyFile",
        "FindFirstFile",
        "FindNextFile",
        "SetFilePointer",
        "GetFileSize",
    ),
    "registry": (
        "RegOpenKey",
        "RegOpenKeyEx",
        "RegCreateKey",
        "RegCreateKeyEx",
        "RegSetValue",
        "RegSetValueEx",
        "RegQueryValueEx",
        "RegDeleteKey",
        "RegDeleteValue",
        "RegEnumKeyEx",
    ),
    "process": (
        "CreateProcess",
        "OpenProcess",
        "TerminateProcess",
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
        "ShellExecute",
        "ShellExecuteEx",
        "WinExec",
    ),
    "thread_inject": (
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "SetThreadContext",
        "NtMapViewOfSection",
    ),
    "crypto": (
        "CryptAcquireContext",
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptGenKey",
        "CryptImportKey",
        "CryptCreateHash",
        "CryptHashData",
        "BCryptEncrypt",
        "BCryptDecrypt",
        "BCryptGenerateSymmetricKey",
        "BCryptOpenAlgorithmProvider",
    ),
    "service": (
        "OpenSCManager",
        "CreateService",
        "StartService",
        "OpenService",
        "ControlService",
        "DeleteService",
        "ChangeServiceConfig",
    ),
    "mutex": ("CreateMutex", "CreateMutexEx", "OpenMutex", "ReleaseMutex"),
    "anti_debug": (
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugString",
        "NtSetInformationThread",
    ),
}

_FAMILY_OF = {api: family for family, apis in API_FAMILIES.items() for api in apis}
MIN_CALLS = 2
MIN_SHARE = 0.6


def suggest_name(start: int, imports_called: Sequence[str]) -> str | None:
    """``<family>_<start>`` when one API family clearly dominates the function's imports."""
    if not imports_called:
        return None
    families = Counter(
        _FAMILY_OF.get(normalize_api(name.rsplit("!", 1)[-1])) for name in imports_called
    )
    families.pop(None, None)
    if not families:
        return None
    family, count = families.most_common(1)[0]
    if count >= MIN_CALLS and count / len(imports_called) >= MIN_SHARE:
        return f"{family}_{start:x}"
    return None


_SLUG = re.compile(r"[^a-z0-9]+")
MAX_SLUG = 32


def suggest_name_from_capa(start: int, rules: Sequence[tuple[str, str]]) -> str | None:
    """``<rule slug>_<start>`` when exactly one medium capa rule matched in the function."""
    medium = [name for name, severity in rules if severity == "medium"]
    if len(medium) != 1:
        return None
    slug = _SLUG.sub("_", medium[0].lower()).strip("_")[:MAX_SLUG].rstrip("_")
    return f"{slug}_{start:x}" if slug else None
