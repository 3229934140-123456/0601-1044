import click
import os
import json
import base64
import hashlib
import zlib
from datetime import datetime
from pathlib import Path
from ..parser import LogParser
from ..utils import (
    Colorizer,
    format_timestamp,
    parse_time_range,
    mask_sensitive_data,
)
from .scan import _filter_entries, _print_time_range, _print_file_stats
from ..output import echo


INVESTIGATION_DIR = Path.home() / ".logalyzer" / "investigations"
LINK_STORE_DIR = Path.home() / ".logalyzer" / "links"


@click.command()
@click.argument("files", nargs=-1, required=False)
@click.option("--output", "-o", help="输出文件路径")
@click.option("--format", "-f", "fmt", type=click.Choice(["text", "json", "html", "markdown"]), default="text", help="导出格式")
@click.option("--start", "-s", help="开始时间")
@click.option("--end", "-e", help="结束时间")
@click.option("--last", "-l", help="最近时间段，如 '30m'")
@click.option("--level", "-L", multiple=True, help="日志级别过滤")
@click.option("--service", "-S", help="按服务名过滤")
@click.option("--keyword", "-k", multiple=True, help="关键词过滤")
@click.option("--trace-id", "-t", help="指定 trace_id 导出")
@click.option("--hide-sensitive", "-H", is_flag=True, help="隐藏敏感字段")
@click.option("--save-investigation", is_flag=True, help="保存到排查记录")
@click.option("--notes", "-n", help="排查备注说明")
@click.option("--generate-link", is_flag=True, help="生成问题片段链接")
@click.option("--decode-link", help="解码问题片段链接，还原关键日志摘要")
@click.option("--list-investigations", is_flag=True, help="列出所有排查记录")
@click.option("--show-investigation", help="查看指定 ID 的排查记录")
@click.option("--delete-investigation", help="删除指定 ID 的排查记录")
def export_cmd(
    files,
    output,
    fmt,
    start,
    end,
    last,
    level,
    service,
    keyword,
    trace_id,
    hide_sensitive,
    save_investigation,
    notes,
    generate_link,
    decode_link,
    list_investigations,
    show_investigation,
    delete_investigation,
):
    """导出分析结果、保存排查记录、生成问题片段链接"""
    if list_investigations:
        _list_investigations()
        return

    if show_investigation:
        _show_investigation(show_investigation)
        return

    if delete_investigation:
        _delete_investigation(delete_investigation)
        return

    if decode_link:
        _decode_problem_link(decode_link)
        return

    if not files:
        echo(Colorizer.error("请提供日志文件路径，或使用 --list-investigations / --show-investigation / --delete-investigation / --decode-link"))
        return

    parser = LogParser()

    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner("导出 日志导出工具"))
    echo(Colorizer.banner("=" * 60))

    start_time, end_time = parse_time_range(start, end, last)
    _print_time_range(start_time, end_time)

    all_entries, file_stats = parser.parse_files(list(files))
    _print_file_stats(file_stats)

    if not all_entries:
        echo(Colorizer.warning("未找到任何日志记录"))
        return

    entries = _filter_entries(all_entries, start_time, end_time, level, service)

    if keyword:
        entries = [e for e in entries if e.matches_keywords(list(keyword))]

    if trace_id:
        entries = [e for e in entries if e.trace_id == trace_id]

    if not entries:
        echo(Colorizer.warning("没有符合条件的日志记录"))
        return

    if hide_sensitive:
        for e in entries:
            e.raw_line = mask_sensitive_data(e.raw_line)
            e.message = mask_sensitive_data(e.message)

    if output:
        exported_file = _export_entries(entries, output, fmt, start_time, end_time, notes)
        echo(Colorizer.success(f"已导出到: {exported_file}"))

    if save_investigation:
        inv_id = _save_investigation(entries, files, start_time, end_time, level, service, keyword, trace_id, notes, fmt)
        echo(Colorizer.success(f"已保存排查记录，ID: {inv_id}"))
        echo(f"  查看: logalyzer export --show-investigation {inv_id}")
        echo(f"  删除: logalyzer export --delete-investigation {inv_id}")
        echo(f"  列表: logalyzer export --list-investigations")

    if generate_link:
        link = _generate_problem_link(entries, trace_id or (keyword[0] if keyword else ""))
        echo()
        echo(Colorizer.banner("问题片段链接:"))
        echo(f"   {link}")
        echo()
        echo(Colorizer.warning("链接为完整可解码格式，另一台机器使用以下命令还原:"))
        echo(f"   logalyzer export --decode-link \"{link}\"")

    if not output and not save_investigation and not generate_link:
        echo(Colorizer.warning("请指定 --output, --save-investigation 或 --generate-link"))


def _export_entries(entries, output_path, fmt, start_time, end_time, notes):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    content = ""
    if fmt == "text":
        content = _format_text(entries, start_time, end_time, notes)
    elif fmt == "json":
        content = _format_json(entries, start_time, end_time, notes)
    elif fmt == "markdown":
        content = _format_markdown(entries, start_time, end_time, notes)
    elif fmt == "html":
        content = _format_html(entries, start_time, end_time, notes)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path


def _format_text(entries, start_time, end_time, notes):
    lines = []
    lines.append("=" * 60)
    lines.append("日志分析报告")
    lines.append("=" * 60)
    lines.append(f"生成时间: {format_timestamp(datetime.now())}")
    if start_time and end_time:
        lines.append(f"时间范围: {format_timestamp(start_time)} -> {format_timestamp(end_time)}")
    lines.append(f"总记录数: {len(entries)}")
    error_count = sum(1 for e in entries if e.is_error)
    lines.append(f"错误数: {error_count}")
    if notes:
        lines.append(f"备注: {notes}")
    lines.append("")
    lines.append("-" * 60)
    lines.append("日志详情")
    lines.append("-" * 60)
    lines.append("")

    for entry in entries:
        ts = format_timestamp(entry.timestamp, "%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"[{ts}] [{entry.level}] [{entry.service}] [{entry.trace_id}] {entry.message}"
        if entry.error_code:
            line += f" (错误码: {entry.error_code})"
        if entry.duration_ms:
            line += f" [{entry.duration_ms:.0f}ms]"
        lines.append(line)

    return "\n".join(lines) + "\n"


def _format_json(entries, start_time, end_time, notes):
    data = {
        "generated_at": format_timestamp(datetime.now()),
        "time_range": {
            "start": format_timestamp(start_time) if start_time else None,
            "end": format_timestamp(end_time) if end_time else None,
        },
        "total_entries": len(entries),
        "error_count": sum(1 for e in entries if e.is_error),
        "notes": notes,
        "entries": [
            {
                "timestamp": format_timestamp(e.timestamp, "%Y-%m-%d %H:%M:%S.%f"),
                "level": e.level,
                "service": e.service,
                "trace_id": e.trace_id,
                "message": e.message,
                "error_code": e.error_code,
                "duration_ms": e.duration_ms,
                "source_file": e.source_file,
                "metadata": e.metadata,
            }
            for e in entries
        ],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


def _format_markdown(entries, start_time, end_time, notes):
    lines = []
    lines.append("# 日志分析报告")
    lines.append("")
    lines.append(f"- **生成时间**: {format_timestamp(datetime.now())}")
    if start_time and end_time:
        lines.append(f"- **时间范围**: {format_timestamp(start_time)} -> {format_timestamp(end_time)}")
    lines.append(f"- **总记录数**: {len(entries)}")
    error_count = sum(1 for e in entries if e.is_error)
    lines.append(f"- **错误数**: {error_count}")
    if notes:
        lines.append(f"- **备注**: {notes}")
    lines.append("")
    lines.append("## 日志详情")
    lines.append("")
    lines.append("| 时间 | 级别 | 服务 | Trace ID | 消息 |")
    lines.append("|------|------|------|----------|------|")

    for entry in entries:
        ts = format_timestamp(entry.timestamp, "%Y-%m-%d %H:%M:%S")
        msg = entry.message.replace("|", "\\|")
        if entry.error_code:
            msg += f" (错误码: {entry.error_code})"
        if entry.duration_ms:
            msg += f" [{entry.duration_ms:.0f}ms]"
        lines.append(f"| {ts} | {entry.level} | {entry.service} | {entry.trace_id} | {msg} |")

    return "\n".join(lines) + "\n"


def _format_html(entries, start_time, end_time, notes):
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>日志分析报告</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4CAF50; color: white; }}
        .ERROR {{ color: #dc3545; font-weight: bold; }}
        .WARN {{ color: #ffc107; }}
        .INFO {{ color: #28a745; }}
        .DEBUG {{ color: #17a2b8; }}
        tr:hover {{ background: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>日志分析报告</h1>
    <div class="summary">
        <p><strong>生成时间:</strong> {format_timestamp(datetime.now())}</p>
"""
    if start_time and end_time:
        html += f"        <p><strong>时间范围:</strong> {format_timestamp(start_time)} -> {format_timestamp(end_time)}</p>\n"
    error_count = sum(1 for e in entries if e.is_error)
    html += f"""
        <p><strong>总记录数:</strong> {len(entries)}</p>
        <p><strong>错误数:</strong> {error_count}</p>
"""
    if notes:
        html += f"        <p><strong>备注:</strong> {notes}</p>\n"
    html += """
    </div>
    <table>
        <tr>
            <th>时间</th>
            <th>级别</th>
            <th>服务</th>
            <th>Trace ID</th>
            <th>消息</th>
        </tr>
"""
    for entry in entries:
        ts = format_timestamp(entry.timestamp, "%Y-%m-%d %H:%M:%S")
        msg = entry.message.replace("<", "&lt;").replace(">", "&gt;")
        if entry.error_code:
            msg += f" (错误码: {entry.error_code})"
        if entry.duration_ms:
            msg += f" [{entry.duration_ms:.0f}ms]"
        html += f"""
        <tr>
            <td>{ts}</td>
            <td class="{entry.level}">{entry.level}</td>
            <td>{entry.service}</td>
            <td><code>{entry.trace_id}</code></td>
            <td>{msg}</td>
        </tr>
"""
    html += """
    </table>
</body>
</html>
"""
    return html


def _save_investigation(entries, files, start_time, end_time, level, service, keyword, trace_id, notes, fmt):
    INVESTIGATION_DIR.mkdir(parents=True, exist_ok=True)

    inv_id = hashlib.md5(
        (str(datetime.now()) + str(len(entries))).encode()
    ).hexdigest()[:12]

    data = {
        "id": inv_id,
        "created_at": format_timestamp(datetime.now()),
        "files": list(files),
        "query": {
            "start": format_timestamp(start_time) if start_time else None,
            "end": format_timestamp(end_time) if end_time else None,
            "level": list(level) if level else None,
            "service": service,
            "keyword": list(keyword) if keyword else None,
            "trace_id": trace_id,
        },
        "notes": notes,
        "entry_count": len(entries),
        "entries": [
            {
                "timestamp": format_timestamp(e.timestamp, "%Y-%m-%d %H:%M:%S.%f"),
                "level": e.level,
                "service": e.service,
                "trace_id": e.trace_id,
                "message": e.message,
                "error_code": e.error_code,
                "duration_ms": e.duration_ms,
            }
            for e in entries
        ],
    }

    filepath = INVESTIGATION_DIR / f"{inv_id}.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return inv_id


def _list_investigations():
    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner("排查记录列表"))
    echo(Colorizer.banner("=" * 60))
    echo()

    if not INVESTIGATION_DIR.exists():
        echo(Colorizer.warning("暂无排查记录"))
        echo()
        echo("  保存排查记录: logalyzer export app.log --save-investigation")
        return

    files = sorted(INVESTIGATION_DIR.glob("*.json"), reverse=True)
    if not files:
        echo(Colorizer.warning("暂无排查记录"))
        echo()
        echo("  保存排查记录: logalyzer export app.log --save-investigation")
        return

    echo(f"   {'ID':<14} {'创建时间':<20} {'记录数':<8} 备注")
    echo("   " + "-" * 70)

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            notes = data.get("notes", "") or ""
            if len(notes) > 40:
                notes = notes[:37] + "..."
            echo(
                f"   {Colorizer.trace_id(data['id']):<14} "
                f"{data['created_at']:<20} "
                f"{Colorizer.summary_value(str(data['entry_count'])):<8} "
                f"{notes}"
            )
        except Exception as e:
            echo(f"   {filepath.stem}: 读取失败 ({e})")

    echo()
    echo("  查看: logalyzer export --show-investigation <ID>")
    echo("  删除: logalyzer export --delete-investigation <ID>")


def _show_investigation(inv_id):
    filepath = INVESTIGATION_DIR / f"{inv_id}.json"
    if not filepath.exists():
        echo(Colorizer.error(f"未找到排查记录: {inv_id}"))
        echo("  列出所有记录: logalyzer export --list-investigations")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner(f"排查记录: {inv_id}"))
    echo(Colorizer.banner("=" * 60))
    echo()
    echo(f"   {Colorizer.summary_key('创建时间:')} {data['created_at']}")
    if data.get("files"):
        echo(f"   {Colorizer.summary_key('查询文件:')} {', '.join(data['files'])}")
    if data.get("notes"):
        echo(f"   {Colorizer.summary_key('备注:')} {data['notes']}")
    echo(f"   {Colorizer.summary_key('记录数:')} {Colorizer.summary_value(str(data['entry_count']), highlight=True)}")
    echo()

    query = data.get("query", {})
    if query:
        echo(f"   {Colorizer.summary_key('查询条件:')}")
        for key, value in query.items():
            if value:
                val_str = ", ".join(value) if isinstance(value, list) else str(value)
                echo(f"     {key}: {val_str}")
        echo()

    echo(Colorizer.banner("-" * 60))
    echo(Colorizer.banner("日志详情"))
    echo(Colorizer.banner("-" * 60))
    echo()

    for entry in data["entries"]:
        level_str = Colorizer.level(entry["level"])
        ts_str = Colorizer.timestamp(entry["timestamp"][:-3])
        svc_str = Colorizer.service(entry["service"])
        tid_str = Colorizer.trace_id(entry["trace_id"])
        line = f"   [{ts_str}] [{level_str}] [{svc_str}] [{tid_str}] {entry['message']}"
        if entry.get("error_code"):
            line += f" (错误码: {Colorizer.error_code(entry['error_code'])})"
        if entry.get("duration_ms"):
            line += f" [{entry['duration_ms']:.0f}ms]"
        echo(line)

    echo()
    echo("相关命令:")
    echo(f"  导出报告: logalyzer export --show-investigation {inv_id}")
    echo(f"  删除记录: logalyzer export --delete-investigation {inv_id}")
    echo(f"  所有记录: logalyzer export --list-investigations")


def _delete_investigation(inv_id):
    filepath = INVESTIGATION_DIR / f"{inv_id}.json"
    if not filepath.exists():
        echo(Colorizer.error(f"未找到排查记录: {inv_id}"))
        echo("  列出所有记录: logalyzer export --list-investigations")
        return

    filepath.unlink()
    echo(Colorizer.success(f"已删除排查记录: {inv_id}"))


def _generate_problem_link(entries, keyword=""):
    LINK_STORE_DIR.mkdir(parents=True, exist_ok=True)

    problem_data = {
        "v": 1,
        "ts": format_timestamp(datetime.now()),
        "kw": keyword,
        "cnt": len(entries),
        "logs": [
            {
                "t": format_timestamp(e.timestamp, "%Y-%m-%d %H:%M:%S.%f")[:-3],
                "l": e.level,
                "s": e.service,
                "tid": e.trace_id,
                "m": e.message,
                "ec": e.error_code,
                "dur": e.duration_ms,
            }
            for e in entries
        ],
    }

    json_str = json.dumps(problem_data, ensure_ascii=False, separators=(",", ":"))
    compressed = zlib.compress(json_str.encode("utf-8"), 9)
    encoded = base64.urlsafe_b64encode(compressed).decode("utf-8")

    if len(encoded) <= 2000:
        link = f"logalyzer:link:{encoded}"
        return link

    short_code = hashlib.md5(compressed).hexdigest()[:10]
    link_file = LINK_STORE_DIR / f"{short_code}.json"
    with open(link_file, "w", encoding="utf-8") as f:
        json.dump(problem_data, f, ensure_ascii=False, indent=2)

    link = f"logalyzer:short:{short_code}"
    return link


def _decode_problem_link(link):
    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner("解码问题片段链接"))
    echo(Colorizer.banner("=" * 60))
    echo()

    if link.startswith("logalyzer:link:"):
        encoded = link[len("logalyzer:link:"):]
        try:
            compressed = base64.urlsafe_b64decode(encoded.encode("utf-8"))
            json_str = zlib.decompress(compressed).decode("utf-8")
            problem_data = json.loads(json_str)
        except Exception as e:
            echo(Colorizer.error(f"链接解码失败: {e}"))
            return
    elif link.startswith("logalyzer:short:"):
        short_code = link[len("logalyzer:short:"):]
        link_file = LINK_STORE_DIR / f"{short_code}.json"
        if not link_file.exists():
            echo(Colorizer.error(f"本地短码记录不存在: {short_code}"))
            echo(Colorizer.warning("该短码仅在生成链接的机器上有效，请使用完整链接格式"))
            return
        with open(link_file, "r", encoding="utf-8") as f:
            problem_data = json.load(f)
    else:
        try:
            encoded = link.strip()
            compressed = base64.urlsafe_b64decode(encoded.encode("utf-8"))
            json_str = zlib.decompress(compressed).decode("utf-8")
            problem_data = json.loads(json_str)
        except Exception:
            echo(Colorizer.error("无法识别的链接格式"))
            echo("  支持格式: logalyzer:link:xxx 或 logalyzer:short:xxx")
            return

    echo(f"   {Colorizer.summary_key('生成时间:')} {problem_data.get('ts', 'N/A')}")
    if problem_data.get("kw"):
        echo(f"   {Colorizer.summary_key('关键词:')} {Colorizer.summary_value(problem_data['kw'], highlight=True)}")
    echo(f"   {Colorizer.summary_key('日志条数:')} {Colorizer.summary_value(str(problem_data.get('cnt', 0)))}")
    echo()

    logs = problem_data.get("logs", [])
    if not logs:
        echo(Colorizer.warning("链接中无日志记录"))
        return

    error_logs = [l for l in logs if l.get("l") in ("ERROR", "FATAL", "CRITICAL")]
    slow_logs = [l for l in logs if l.get("dur") and l["dur"] > 3000]
    trace_ids = set(l.get("tid") for l in logs if l.get("tid"))

    if error_logs:
        echo(Colorizer.banner("-" * 40))
        echo(f"   {Colorizer.summary_key('错误日志')} ({len(error_logs)} 条)")
        echo(Colorizer.banner("-" * 40))
        for log in error_logs:
            level_str = Colorizer.level(log["l"])
            ts_str = Colorizer.timestamp(log["t"])
            svc_str = Colorizer.service(log.get("s", ""))
            line = f"   [{ts_str}] [{level_str}] [{svc_str}] {log.get('m', '')}"
            if log.get("ec"):
                line += f" (错误码: {Colorizer.error_code(log['ec'])})"
            if log.get("dur"):
                line += f" [{log['dur']:.0f}ms]"
            echo(line)
        echo()

    if slow_logs:
        echo(Colorizer.banner("-" * 40))
        echo(f"   {Colorizer.summary_key('慢请求')} ({len(slow_logs)} 条)")
        echo(Colorizer.banner("-" * 40))
        for log in slow_logs:
            ts_str = Colorizer.timestamp(log["t"])
            svc_str = Colorizer.service(log.get("s", ""))
            dur_str = Colorizer.summary_value(f"{log['dur']:.0f}ms", highlight=True)
            echo(f"   [{ts_str}] [{svc_str}] 耗时: {dur_str} - {log.get('m', '')[:60]}")
        echo()

    if trace_ids:
        echo(f"   {Colorizer.summary_key('相关 Trace ID:')}")
        for tid in sorted(trace_ids):
            has_error = any(l.get("l") in ("ERROR", "FATAL", "CRITICAL") and l.get("tid") == tid for l in logs)
            marker = " [错误]" if has_error else ""
            echo(f"     {Colorizer.trace_id(tid)}{marker}")
        echo()

    echo(Colorizer.banner("-" * 40))
    echo(f"   {Colorizer.summary_key('完整日志摘要')}")
    echo(Colorizer.banner("-" * 40))
    echo()

    for log in logs:
        level_str = Colorizer.level(log.get("l", "INFO"))
        ts_str = Colorizer.timestamp(log.get("t", ""))
        svc_str = Colorizer.service(log.get("s", ""))
        tid_str = Colorizer.trace_id(log.get("tid", "")) if log.get("tid") else ""
        tid_part = f" [{tid_str}]" if tid_str else ""
        line = f"   [{ts_str}] [{level_str}] [{svc_str}]{tid_part} {log.get('m', '')}"
        if log.get("ec"):
            line += f" (错误码: {Colorizer.error_code(log['ec'])})"
        if log.get("dur"):
            line += f" [{log['dur']:.0f}ms]"
        echo(line)
