from __future__ import annotations


class Logger:
    def __init__(self, verbose: bool) -> None:
        self.verbose = verbose

    def info(self, message: str) -> None:
        print(f"[*] {message}")

    def success(self, message: str) -> None:
        print(f"[+] {message}")

    def warn(self, message: str) -> None:
        print(f"[!] {message}")

    def debug(self, message: str) -> None:
        if self.verbose:
            print(f"[DBG] {message}")
