from colorama import Fore, Style, init
from typing import Optional
import sys

init(autoreset=True)

EMOJI_MAP = {
    "📊": "[统计]",
    "📋": "[日志]",
    "📈": "[趋势]",
    "🔍": "[搜索]",
    "🔗": "[链接]",
    "📤": "[导出]",
    "⏰": "[时间]",
    "📁": "[文件]",
    "❌": "[错误]",
    "⚠️": "[警告]",
    "✅": "[成功]",
    "📍": "[匹配]",
    "🏷️": "[标签]",
    "🐢": "[慢]",
    "⚡": "[峰值]",
    "🏗️": "[服务]",
    "📝": "[记录]",
    "✓": "OK",
    "✗": "ERR",
    "●": "*",
}


def _replace_emoji(text: str) -> str:
    if sys.platform == "win32":
        result = text
        for emoji, replacement in EMOJI_MAP.items():
            result = result.replace(emoji, replacement)
        return result
    return text


class Colorizer:
    LEVEL_COLORS = {
        "DEBUG": Fore.CYAN,
        "INFO": Fore.GREEN,
        "WARN": Fore.YELLOW,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "FATAL": Fore.RED + Style.BRIGHT,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }

    @staticmethod
    def level(level: str) -> str:
        color = Colorizer.LEVEL_COLORS.get(level.upper(), "")
        reset = Style.RESET_ALL if color else ""
        return f"{color}{level}{reset}"

    @staticmethod
    def timestamp(ts: str) -> str:
        return f"{Fore.LIGHTBLACK_EX}{ts}{Style.RESET_ALL}"

    @staticmethod
    def service(service: str) -> str:
        return f"{Fore.LIGHTMAGENTA_EX}{service}{Style.RESET_ALL}"

    @staticmethod
    def trace_id(trace_id: str) -> str:
        return f"{Fore.LIGHTCYAN_EX}{trace_id}{Style.RESET_ALL}"

    @staticmethod
    def error_code(code: str) -> str:
        return f"{Fore.RED}{code}{Style.RESET_ALL}"

    @staticmethod
    def highlight(text: str, keyword: str) -> str:
        if not keyword:
            return text
        idx = text.lower().find(keyword.lower())
        if idx == -1:
            return text
        highlighted = text[idx:idx + len(keyword)]
        return (
            text[:idx]
            + f"{Fore.YELLOW}{Style.BRIGHT}{highlighted}{Style.RESET_ALL}"
            + text[idx + len(keyword):]
        )

    @staticmethod
    def highlight_all(text: str, keywords: list) -> str:
        result = text
        for kw in keywords:
            result = Colorizer.highlight(result, kw)
        return result

    @staticmethod
    def banner(text: str) -> str:
        text = _replace_emoji(text)
        return f"{Style.BRIGHT}{Fore.LIGHTBLUE_EX}{text}{Style.RESET_ALL}"

    @staticmethod
    def summary_key(key: str) -> str:
        key = _replace_emoji(key)
        return f"{Style.BRIGHT}{Fore.LIGHTWHITE_EX}{key}{Style.RESET_ALL}"

    @staticmethod
    def summary_value(value: str, highlight: bool = False) -> str:
        value = _replace_emoji(value)
        if highlight:
            return f"{Style.BRIGHT}{Fore.YELLOW}{value}{Style.RESET_ALL}"
        return f"{Fore.LIGHTGREEN_EX}{value}{Style.RESET_ALL}"

    @staticmethod
    def warning(text: str) -> str:
        prefix = "!" if sys.platform == "win32" else "⚠"
        return f"{Fore.YELLOW}{Style.BRIGHT}{prefix}{Style.RESET_ALL} {_replace_emoji(text)}"

    @staticmethod
    def error(text: str) -> str:
        prefix = "X" if sys.platform == "win32" else "✗"
        return f"{Fore.RED}{Style.BRIGHT}{prefix}{Style.RESET_ALL} {_replace_emoji(text)}"

    @staticmethod
    def success(text: str) -> str:
        prefix = "√" if sys.platform == "win32" else "✓"
        return f"{Fore.GREEN}{Style.BRIGHT}{prefix}{Style.RESET_ALL} {_replace_emoji(text)}"

    @staticmethod
    def bar(filled: int, total: int, width: int = 20) -> str:
        if total == 0:
            return "[" + " " * width + "]"
        ratio = min(filled / total, 1.0)
        filled_chars = int(width * ratio)
        bar_color = Fore.GREEN
        if ratio > 0.7:
            bar_color = Fore.YELLOW
        if ratio > 0.9:
            bar_color = Fore.RED
        return (
            "["
            + f"{bar_color}{Style.BRIGHT}"
            + "█" * filled_chars
            + Style.RESET_ALL
            + " " * (width - filled_chars)
            + "]"
        )
