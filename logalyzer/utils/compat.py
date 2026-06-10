import sys
import os


def safe_echo(text: str) -> str:
    if sys.platform == "win32":
        emoji_map = {
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
            "✓": "[OK]",
            "✗": "[ERR]",
            "●": "*",
        }
        result = text
        for emoji, replacement in emoji_map.items():
            result = result.replace(emoji, replacement)
        return result
    return text


def setup_console():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            os.environ["PYTHONIOENCODING"] = "utf-8"
