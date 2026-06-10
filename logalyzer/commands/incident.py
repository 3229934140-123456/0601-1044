import click
import json
import random
from datetime import datetime
from pathlib import Path
from ..parser import LogParser
from ..models import LogEntry, TraceContext
from ..utils import Colorizer, format_timestamp, parse_time_range, mask_sensitive_data
from .scan import _filter_entries, _print_time_range, _print_file_stats
from ..output import echo


INCIDENT_DIR = Path.home() / ".logalyzer" / "incidents"


@click.group()
def incident_cmd():
    """事件会话模式：创建、追踪、关闭、导出事件"""
    pass


@incident_cmd.command()
@click.option("--title", "-t", required=True, help="事件标题")
@click.option("--severity", "-s", type=click.Choice(["低", "中", "高", "紧急"]), default="中", help="严重程度")
def create(title, severity):
    """创建一个新的事件会话"""
    INCIDENT_DIR.mkdir(parents=True, exist_ok=True)

    incident_id = _generate_incident_id()

    data = {
        "id": incident_id,
        "title": title,
        "severity": severity,
        "status": "open",
        "created_at": format_timestamp(datetime.now()),
        "updated_at": format_timestamp(datetime.now()),
        "closed_at": None,
        "entries": [],
    }

    filepath = INCIDENT_DIR / f"{incident_id}.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner("🚨 事件已创建"))
    echo(Colorizer.banner("=" * 60))
    echo()
    echo(f"   {Colorizer.summary_key('事件ID:')} {Colorizer.trace_id(incident_id)}")
    echo(f"   {Colorizer.summary_key('标题:')} {Colorizer.summary_value(title)}")
    echo(f"   {Colorizer.summary_key('严重程度:')} {_color_severity(severity)}")
    echo(f"   {Colorizer.summary_key('状态:')} {Colorizer.success('open')}")
    echo(f"   {Colorizer.summary_key('创建时间:')} {Colorizer.timestamp(format_timestamp(datetime.now()))}")
    echo()
    echo(Colorizer.success(f"✓ 事件已保存到: {filepath}"))


@incident_cmd.command("add")
@click.option("--incident-id", "-i", required=True, help="事件 ID")
@click.option("--source", "-s", type=click.Choice(["scan", "filter", "trace", "stats"]), required=True, help="来源类型")
@click.option("--keyword", "-k", multiple=True, help="关键词")
@click.option("--level", "-L", multiple=True, help="级别过滤")
@click.option("--trace-id", "-t", help="指定 trace_id")
@click.argument("files", nargs=-1, required=True)
def add_entries(incident_id, source, keyword, level, trace_id, files):
    """将查询结果追加到指定事件下"""
    incident = _load_incident(incident_id)
    if not incident:
        echo(Colorizer.error(f"未找到事件: {incident_id}"))
        return

    if incident["status"] == "closed":
        echo(Colorizer.warning(f"事件 {incident_id} 已关闭，无法追加记录"))
        return

    parser = LogParser()
    all_entries, file_stats = parser.parse_files(list(files))

    if not all_entries:
        echo(Colorizer.warning("未找到任何日志记录"))
        return

    entries = _filter_entries(all_entries, None, None, level if level else None, None)

    if keyword:
        entries = [e for e in entries if e.matches_keywords(list(keyword))]

    if trace_id:
        entries = [e for e in entries if e.trace_id == trace_id]

    if not entries:
        echo(Colorizer.warning("没有符合条件的日志记录"))
        return

    existing_raw = {e["raw_line"] for e in incident["entries"]}
    added = 0
    for entry in entries:
        if entry.raw_line not in existing_raw:
            incident["entries"].append(_entry_to_dict(entry, source))
            existing_raw.add(entry.raw_line)
            added += 1

    incident["updated_at"] = format_timestamp(datetime.now())
    _save_incident(incident)

    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner(f"📥 追加到事件 {Colorizer.trace_id(incident_id)}"))
    echo(Colorizer.banner("=" * 60))
    echo()
    echo(f"   {Colorizer.summary_key('来源:')} {Colorizer.summary_value(source)}")
    if keyword:
        echo(f"   {Colorizer.summary_key('关键词:')} {', '.join(Colorizer.summary_value(k) for k in keyword)}")
    if level:
        echo(f"   {Colorizer.summary_key('级别:')} {', '.join(Colorizer.level(l) for l in level)}")
    if trace_id:
        echo(f"   {Colorizer.summary_key('Trace ID:')} {Colorizer.trace_id(trace_id)}")
    echo(f"   {Colorizer.summary_key('匹配记录:')} {Colorizer.summary_value(str(len(entries)))}")
    echo(f"   {Colorizer.summary_key('新增记录:')} {Colorizer.summary_value(str(added), highlight=added > 0)}")
    echo(f"   {Colorizer.summary_key('去重跳过:')} {Colorizer.summary_value(str(len(entries) - added))}")
    echo(f"   {Colorizer.summary_key('事件总记录:')} {Colorizer.summary_value(str(len(incident['entries'])), highlight=True)}")
    echo()
    echo(Colorizer.success(f"✓ 已追加 {added} 条记录到事件 {incident_id}"))


@incident_cmd.command("show")
@click.option("--incident-id", "-i", required=True, help="事件 ID")
def show(incident_id):
    """显示指定事件的完整信息"""
    incident = _load_incident(incident_id)
    if not incident:
        echo(Colorizer.error(f"未找到事件: {incident_id}"))
        return

    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner(f"🚨 事件详情: {Colorizer.trace_id(incident_id)}"))
    echo(Colorizer.banner("=" * 60))
    echo()

    status = incident["status"]
    status_str = Colorizer.success(status) if status == "open" else Colorizer.error(status)
    echo(f"   {Colorizer.summary_key('标题:')} {Colorizer.summary_value(incident['title'])}")
    echo(f"   {Colorizer.summary_key('严重程度:')} {_color_severity(incident['severity'])}")
    echo(f"   {Colorizer.summary_key('状态:')} {status_str}")
    echo(f"   {Colorizer.summary_key('创建时间:')} {Colorizer.timestamp(incident['created_at'])}")
    echo(f"   {Colorizer.summary_key('更新时间:')} {Colorizer.timestamp(incident['updated_at'])}")
    if incident.get("closed_at"):
        echo(f"   {Colorizer.summary_key('关闭时间:')} {Colorizer.timestamp(incident['closed_at'])}")
    echo(f"   {Colorizer.summary_key('记录总数:')} {Colorizer.summary_value(str(len(incident['entries'])), highlight=True)}")
    echo()

    if not incident["entries"]:
        echo(Colorizer.warning("暂无日志记录，使用 incident add 追加"))
        return

    entries = incident["entries"]
    sorted_entries = sorted(entries, key=lambda e: e["timestamp"])

    summary = _compute_summary(sorted_entries)

    echo(Colorizer.banner("-" * 60))
    echo(Colorizer.banner("📊 事件摘要"))
    echo(Colorizer.banner("-" * 60))
    echo()

    error_count = sum(1 for e in sorted_entries if e["level"] in ("ERROR", "FATAL", "CRITICAL"))
    warn_count = sum(1 for e in sorted_entries if e["level"] in ("WARN", "WARNING"))
    echo(f"   {Colorizer.summary_key('错误数:')} {Colorizer.error_code(str(error_count)) if error_count > 0 else '0'}")
    echo(f"   {Colorizer.summary_key('警告数:')} {Colorizer.summary_value(str(warn_count), highlight=warn_count > 10)}")

    if summary["error_codes"]:
        echo()
        echo(f"   {Colorizer.summary_key('错误码列表:')}")
        for code, count in sorted(summary["error_codes"].items(), key=lambda x: -x[1]):
            echo(f"     • {Colorizer.error_code(code)} × {count}")

    if summary["slow_requests"]:
        echo()
        echo(f"   {Colorizer.summary_key('慢请求列表:')}")
        for req in summary["slow_requests"][:10]:
            echo(
                f"     • {Colorizer.timestamp(req['timestamp'][:19])} "
                f"[{Colorizer.service(req['service'])}] "
                f"耗时: {Colorizer.summary_value(req['duration'], highlight=True)}"
            )

    if summary["trace_ids"]:
        echo()
        echo(f"   {Colorizer.summary_key('相关 Trace:')}")
        for tid, count in sorted(summary["trace_ids"].items(), key=lambda x: -x[1])[:15]:
            has_error = summary["error_trace_ids"].get(tid, False)
            icon = "❌ " if has_error else ""
            echo(f"     • {icon}{Colorizer.trace_id(tid)} ({count} 条)")

    if summary["service_path"]:
        echo()
        echo(f"   {Colorizer.summary_key('服务路径:')}")
        echo("     " + " → ".join(Colorizer.service(s) for s in summary["service_path"]))

    echo()
    echo(Colorizer.banner("-" * 60))
    echo(Colorizer.banner("📋 时间线"))
    echo(Colorizer.banner("-" * 60))
    echo()

    for i, entry in enumerate(sorted_entries, 1):
        _print_incident_entry(entry, i)

    echo()


@incident_cmd.command("list")
def list_incidents():
    """列出所有事件"""
    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner("📋 事件列表"))
    echo(Colorizer.banner("=" * 60))
    echo()

    if not INCIDENT_DIR.exists():
        echo(Colorizer.warning("暂无事件记录"))
        return

    files = sorted(INCIDENT_DIR.glob("*.json"), reverse=True)
    if not files:
        echo(Colorizer.warning("暂无事件记录"))
        return

    echo(f"   {'事件ID':<22} {'标题':<20} {'严重程度':<8} {'状态':<8} {'记录数':<8} {'更新时间'}")
    echo("   " + "-" * 90)

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            title = data.get("title", "")
            if len(title) > 18:
                title = title[:15] + "..."
            severity = data.get("severity", "中")
            status = data.get("status", "open")
            status_str = Colorizer.success(status) if status == "open" else Colorizer.error(status)
            entry_count = len(data.get("entries", []))
            updated = data.get("updated_at", "")[:19]
            echo(
                f"   {Colorizer.trace_id(data['id']):<22} "
                f"{title:<20} "
                f"{_color_severity(severity):<14} "
                f"{status_str:<14} "
                f"{Colorizer.summary_value(str(entry_count)):<8} "
                f"{Colorizer.timestamp(updated)}"
            )
        except Exception as e:
            echo(f"   {filepath.stem}: 读取失败 ({e})")


@incident_cmd.command("close")
@click.option("--incident-id", "-i", required=True, help="事件 ID")
def close_incident(incident_id):
    """关闭事件（标记状态为 closed）"""
    incident = _load_incident(incident_id)
    if not incident:
        echo(Colorizer.error(f"未找到事件: {incident_id}"))
        return

    if incident["status"] == "closed":
        echo(Colorizer.warning(f"事件 {incident_id} 已经处于关闭状态"))
        return

    incident["status"] = "closed"
    incident["closed_at"] = format_timestamp(datetime.now())
    incident["updated_at"] = format_timestamp(datetime.now())
    _save_incident(incident)

    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner(f"🔒 事件已关闭"))
    echo(Colorizer.banner("=" * 60))
    echo()
    echo(f"   {Colorizer.summary_key('事件ID:')} {Colorizer.trace_id(incident_id)}")
    echo(f"   {Colorizer.summary_key('标题:')} {Colorizer.summary_value(incident['title'])}")
    echo(f"   {Colorizer.summary_key('关闭时间:')} {Colorizer.timestamp(incident['closed_at'])}")
    echo(f"   {Colorizer.summary_key('总记录数:')} {Colorizer.summary_value(str(len(incident['entries'])), highlight=True)}")
    echo()
    echo(Colorizer.success(f"✓ 事件 {incident_id} 已关闭"))


@incident_cmd.command("export-report")
@click.option("--incident-id", "-i", required=True, help="事件 ID")
@click.option("--output", "-o", required=True, help="输出文件路径")
@click.option("--format", "-f", "fmt", type=click.Choice(["text", "json", "markdown", "html"]), default="text", help="导出格式")
def export_report(incident_id, output, fmt):
    """将事件导出为完整报告"""
    incident = _load_incident(incident_id)
    if not incident:
        echo(Colorizer.error(f"未找到事件: {incident_id}"))
        return

    if not incident["entries"]:
        echo(Colorizer.warning("事件中暂无日志记录，无法导出报告"))
        return

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "text":
        content = _report_text(incident)
    elif fmt == "json":
        content = _report_json(incident)
    elif fmt == "markdown":
        content = _report_markdown(incident)
    elif fmt == "html":
        content = _report_html(incident)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    echo(Colorizer.success(f"✓ 报告已导出到: {output_path}"))


def _generate_incident_id():
    now = datetime.now()
    date_part = now.strftime("%Y%m%d")
    seq_part = f"{random.randint(0, 9999):04d}"
    return f"INC-{date_part}-{seq_part}"


def _load_incident(incident_id):
    filepath = INCIDENT_DIR / f"{incident_id}.json"
    if not filepath.exists():
        return None
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_incident(incident):
    INCIDENT_DIR.mkdir(parents=True, exist_ok=True)
    filepath = INCIDENT_DIR / f"{incident['id']}.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(incident, f, ensure_ascii=False, indent=2)


def _entry_to_dict(entry, source):
    return {
        "timestamp": format_timestamp(entry.timestamp, "%Y-%m-%d %H:%M:%S.%f"),
        "level": entry.level,
        "service": entry.service,
        "trace_id": entry.trace_id,
        "message": entry.message,
        "raw_line": entry.raw_line,
        "error_code": entry.error_code,
        "duration_ms": entry.duration_ms,
        "source_file": entry.source_file,
        "source_type": source,
    }


def _compute_summary(entries):
    error_codes = {}
    slow_requests = []
    trace_ids = {}
    error_trace_ids = {}
    services = []
    seen_services = set()

    for entry in entries:
        if entry.get("error_code"):
            error_codes[entry["error_code"]] = error_codes.get(entry["error_code"], 0) + 1

        if entry.get("duration_ms") and entry["duration_ms"] > 3000:
            slow_requests.append({
                "timestamp": entry["timestamp"],
                "service": entry["service"],
                "duration": f"{entry['duration_ms']:.0f}ms",
                "trace_id": entry.get("trace_id", ""),
                "message": entry.get("message", ""),
            })

        tid = entry.get("trace_id", "")
        if tid:
            trace_ids[tid] = trace_ids.get(tid, 0) + 1
            if entry["level"] in ("ERROR", "FATAL", "CRITICAL"):
                error_trace_ids[tid] = True

        svc = entry.get("service", "")
        if svc and svc not in seen_services:
            services.append(svc)
            seen_services.add(svc)

    return {
        "error_codes": error_codes,
        "slow_requests": sorted(slow_requests, key=lambda r: r["timestamp"]),
        "trace_ids": trace_ids,
        "error_trace_ids": error_trace_ids,
        "service_path": services,
    }


def _print_incident_entry(entry, index):
    timestamp = entry["timestamp"][:-3] if len(entry["timestamp"]) > 3 else entry["timestamp"]
    level_str = Colorizer.level(entry["level"])
    ts_str = Colorizer.timestamp(timestamp)
    svc_str = Colorizer.service(entry["service"])
    tid_str = Colorizer.trace_id(entry.get("trace_id", ""))
    source_str = Colorizer.summary_value(entry.get("source_type", ""))

    prefix = "   "
    if entry["level"] in ("ERROR", "FATAL", "CRITICAL"):
        prefix = "❌ "
    elif entry["level"] in ("WARN", "WARNING"):
        prefix = "⚠️  "

    line = f"{prefix}{index:>3}. [{ts_str}] [{level_str}] [{svc_str}] [{tid_str}] {entry['message']}"
    if entry.get("error_code"):
        line += f" (错误码: {Colorizer.error_code(entry['error_code'])})"
    if entry.get("duration_ms"):
        line += f" [{entry['duration_ms']:.0f}ms]"
    line += f" [{source_str}]"
    echo(line)


def _color_severity(severity):
    color_map = {
        "低": Colorizer.success(severity),
        "中": Colorizer.summary_value(severity),
        "高": Colorizer.warning(severity),
        "紧急": Colorizer.error_code(severity),
    }
    return color_map.get(severity, Colorizer.summary_value(severity))


def _report_text(incident):
    lines = []
    lines.append("=" * 60)
    lines.append("事件报告")
    lines.append("=" * 60)
    lines.append(f"事件ID: {incident['id']}")
    lines.append(f"标题: {incident['title']}")
    lines.append(f"严重程度: {incident['severity']}")
    lines.append(f"状态: {incident['status']}")
    lines.append(f"创建时间: {incident['created_at']}")
    lines.append(f"更新时间: {incident['updated_at']}")
    if incident.get("closed_at"):
        lines.append(f"关闭时间: {incident['closed_at']}")
    lines.append(f"总记录数: {len(incident['entries'])}")
    lines.append("")

    sorted_entries = sorted(incident["entries"], key=lambda e: e["timestamp"])
    summary = _compute_summary(sorted_entries)

    lines.append("-" * 60)
    lines.append("事件摘要")
    lines.append("-" * 60)
    error_count = sum(1 for e in sorted_entries if e["level"] in ("ERROR", "FATAL", "CRITICAL"))
    warn_count = sum(1 for e in sorted_entries if e["level"] in ("WARN", "WARNING"))
    lines.append(f"错误数: {error_count}")
    lines.append(f"警告数: {warn_count}")

    if summary["error_codes"]:
        lines.append("")
        lines.append("错误码列表:")
        for code, count in sorted(summary["error_codes"].items(), key=lambda x: -x[1]):
            lines.append(f"  {code}: {count} 次")

    if summary["slow_requests"]:
        lines.append("")
        lines.append("慢请求列表:")
        for req in summary["slow_requests"][:10]:
            lines.append(f"  {req['timestamp'][:19]} [{req['service']}] 耗时: {req['duration']}")

    if summary["trace_ids"]:
        lines.append("")
        lines.append("相关 Trace:")
        for tid, count in sorted(summary["trace_ids"].items(), key=lambda x: -x[1]):
            err = " (含错误)" if summary["error_trace_ids"].get(tid) else ""
            lines.append(f"  {tid}: {count} 条{err}")

    if summary["service_path"]:
        lines.append("")
        lines.append("服务路径:")
        lines.append("  " + " → ".join(summary["service_path"]))

    lines.append("")
    lines.append("-" * 60)
    lines.append("时间线详情")
    lines.append("-" * 60)
    lines.append("")

    for i, entry in enumerate(sorted_entries, 1):
        ts = entry["timestamp"][:-3]
        line = f"{i:>3}. [{ts}] [{entry['level']}] [{entry['service']}] [{entry.get('trace_id', '')}] {entry['message']}"
        if entry.get("error_code"):
            line += f" (错误码: {entry['error_code']})"
        if entry.get("duration_ms"):
            line += f" [{entry['duration_ms']:.0f}ms]"
        line += f" [{entry.get('source_type', '')}]"
        lines.append(line)

    return "\n".join(lines) + "\n"


def _report_json(incident):
    sorted_entries = sorted(incident["entries"], key=lambda e: e["timestamp"])
    summary = _compute_summary(sorted_entries)

    data = {
        "id": incident["id"],
        "title": incident["title"],
        "severity": incident["severity"],
        "status": incident["status"],
        "created_at": incident["created_at"],
        "updated_at": incident["updated_at"],
        "closed_at": incident.get("closed_at"),
        "total_entries": len(incident["entries"]),
        "summary": {
            "error_count": sum(1 for e in sorted_entries if e["level"] in ("ERROR", "FATAL", "CRITICAL")),
            "warn_count": sum(1 for e in sorted_entries if e["level"] in ("WARN", "WARNING")),
            "error_codes": summary["error_codes"],
            "slow_requests": summary["slow_requests"],
            "trace_ids": summary["trace_ids"],
            "service_path": summary["service_path"],
        },
        "entries": sorted_entries,
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


def _report_markdown(incident):
    lines = []
    lines.append(f"# 事件报告: {incident['title']}")
    lines.append("")
    lines.append(f"- **事件ID**: {incident['id']}")
    lines.append(f"- **严重程度**: {incident['severity']}")
    lines.append(f"- **状态**: {incident['status']}")
    lines.append(f"- **创建时间**: {incident['created_at']}")
    lines.append(f"- **更新时间**: {incident['updated_at']}")
    if incident.get("closed_at"):
        lines.append(f"- **关闭时间**: {incident['closed_at']}")
    lines.append(f"- **总记录数**: {len(incident['entries'])}")
    lines.append("")

    sorted_entries = sorted(incident["entries"], key=lambda e: e["timestamp"])
    summary = _compute_summary(sorted_entries)

    error_count = sum(1 for e in sorted_entries if e["level"] in ("ERROR", "FATAL", "CRITICAL"))
    warn_count = sum(1 for e in sorted_entries if e["level"] in ("WARN", "WARNING"))

    lines.append("## 事件摘要")
    lines.append("")
    lines.append(f"- 错误数: {error_count}")
    lines.append(f"- 警告数: {warn_count}")

    if summary["error_codes"]:
        lines.append("")
        lines.append("### 错误码统计")
        lines.append("")
        lines.append("| 错误码 | 次数 |")
        lines.append("|--------|------|")
        for code, count in sorted(summary["error_codes"].items(), key=lambda x: -x[1]):
            lines.append(f"| {code} | {count} |")

    if summary["slow_requests"]:
        lines.append("")
        lines.append("### 慢请求列表")
        lines.append("")
        lines.append("| 时间 | 服务 | 耗时 | 消息 |")
        lines.append("|------|------|------|------|")
        for req in summary["slow_requests"][:10]:
            msg = req["message"][:60].replace("|", "\\|")
            lines.append(f"| {req['timestamp'][:19]} | {req['service']} | {req['duration']} | {msg} |")

    if summary["trace_ids"]:
        lines.append("")
        lines.append("### 相关 Trace")
        lines.append("")
        lines.append("| Trace ID | 记录数 | 含错误 |")
        lines.append("|----------|--------|--------|")
        for tid, count in sorted(summary["trace_ids"].items(), key=lambda x: -x[1]):
            has_err = "是" if summary["error_trace_ids"].get(tid) else "否"
            lines.append(f"| {tid} | {count} | {has_err} |")

    if summary["service_path"]:
        lines.append("")
        lines.append("### 服务路径")
        lines.append("")
        lines.append(" → ".join(summary["service_path"]))

    lines.append("")
    lines.append("## 时间线详情")
    lines.append("")
    lines.append("| # | 时间 | 级别 | 服务 | Trace ID | 消息 | 来源 |")
    lines.append("|---|------|------|------|----------|------|------|")
    for i, entry in enumerate(sorted_entries, 1):
        msg = entry["message"][:80].replace("|", "\\|")
        if entry.get("error_code"):
            msg += f" (错误码: {entry['error_code']})"
        if entry.get("duration_ms"):
            msg += f" [{entry['duration_ms']:.0f}ms]"
        lines.append(
            f"| {i} | {entry['timestamp'][:19]} | {entry['level']} | {entry['service']} "
            f"| {entry.get('trace_id', '')} | {msg} | {entry.get('source_type', '')} |"
        )

    return "\n".join(lines) + "\n"


def _report_html(incident):
    sorted_entries = sorted(incident["entries"], key=lambda e: e["timestamp"])
    summary = _compute_summary(sorted_entries)

    error_count = sum(1 for e in sorted_entries if e["level"] in ("ERROR", "FATAL", "CRITICAL"))
    warn_count = sum(1 for e in sorted_entries if e["level"] in ("WARN", "WARNING"))

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>事件报告: {incident['title']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; background: #fafafa; }}
        h1 {{ color: #333; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #fff; padding: 15px; border-radius: 8px; border-left: 4px solid #e74c3c; margin-bottom: 20px; }}
        .severity-low {{ color: #27ae60; }} .severity-mid {{ color: #f39c12; }} .severity-high {{ color: #e67e22; }} .severity-critical {{ color: #e74c3c; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; background: #fff; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
        .ERROR {{ color: #dc3545; font-weight: bold; }}
        .WARN {{ color: #ffc107; }}
        .INFO {{ color: #28a745; }}
        .DEBUG {{ color: #17a2b8; }}
        tr:hover {{ background: #f9f9f9; }}
        .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; }}
        .tag-error {{ background: #ffeaea; color: #dc3545; }}
        .tag-warn {{ background: #fff8e1; color: #f39c12; }}
        .tag-slow {{ background: #fff3e0; color: #e67e22; }}
    </style>
</head>
<body>
    <h1>🚨 事件报告: {incident['title']}</h1>
    <div class="summary">
        <p><strong>事件ID:</strong> <code>{incident['id']}</code></p>
        <p><strong>严重程度:</strong> {incident['severity']}</p>
        <p><strong>状态:</strong> {incident['status']}</p>
        <p><strong>创建时间:</strong> {incident['created_at']}</p>
        <p><strong>更新时间:</strong> {incident['updated_at']}</p>
"""
    if incident.get("closed_at"):
        html += f"        <p><strong>关闭时间:</strong> {incident['closed_at']}</p>\n"
    html += f"""        <p><strong>总记录数:</strong> {len(incident['entries'])}</p>
        <p><strong>错误数:</strong> {error_count} | <strong>警告数:</strong> {warn_count}</p>
    </div>
"""
    if summary["error_codes"]:
        html += """
    <h2>🏷️ 错误码统计</h2>
    <table>
        <tr><th>错误码</th><th>次数</th></tr>
"""
        for code, count in sorted(summary["error_codes"].items(), key=lambda x: -x[1]):
            html += f"        <tr><td><span class=\"tag tag-error\">{code}</span></td><td>{count}</td></tr>\n"
        html += "    </table>\n"

    if summary["slow_requests"]:
        html += """
    <h2>🐢 慢请求列表</h2>
    <table>
        <tr><th>时间</th><th>服务</th><th>耗时</th><th>消息</th></tr>
"""
        for req in summary["slow_requests"][:10]:
            msg = req["message"][:80].replace("<", "&lt;").replace(">", "&gt;")
            html += f"        <tr><td>{req['timestamp'][:19]}</td><td>{req['service']}</td><td><span class=\"tag tag-slow\">{req['duration']}</span></td><td>{msg}</td></tr>\n"
        html += "    </table>\n"

    if summary["trace_ids"]:
        html += """
    <h2>🔗 相关 Trace</h2>
    <table>
        <tr><th>Trace ID</th><th>记录数</th><th>含错误</th></tr>
"""
        for tid, count in sorted(summary["trace_ids"].items(), key=lambda x: -x[1]):
            has_err = "是" if summary["error_trace_ids"].get(tid) else "否"
            err_class = "tag-error" if has_err else ""
            html += f"        <tr><td><code>{tid}</code></td><td>{count}</td><td><span class=\"tag {err_class}\">{has_err}</span></td></tr>\n"
        html += "    </table>\n"

    if summary["service_path"]:
        html += f"""
    <h2>🏗️ 服务路径</h2>
    <p>{' → '.join(summary['service_path'])}</p>
"""

    html += """
    <h2>📋 时间线详情</h2>
    <table>
        <tr><th>#</th><th>时间</th><th>级别</th><th>服务</th><th>Trace ID</th><th>消息</th><th>来源</th></tr>
"""
    for i, entry in enumerate(sorted_entries, 1):
        msg = entry["message"][:100].replace("<", "&lt;").replace(">", "&gt;")
        if entry.get("error_code"):
            msg += f" (错误码: {entry['error_code']})"
        if entry.get("duration_ms"):
            msg += f" [{entry['duration_ms']:.0f}ms]"
        html += f"""        <tr>
            <td>{i}</td>
            <td>{entry['timestamp'][:19]}</td>
            <td class="{entry['level']}">{entry['level']}</td>
            <td>{entry['service']}</td>
            <td><code>{entry.get('trace_id', '')}</code></td>
            <td>{msg}</td>
            <td>{entry.get('source_type', '')}</td>
        </tr>
"""
    html += """
    </table>
</body>
</html>
"""
    return html
