import click
from typing import List
from datetime import datetime
from ..parser import LogParser
from ..models import LogEntry
from ..utils import Colorizer, format_timestamp, parse_time_range, mask_sensitive_data
from ..output import echo


@click.command()
@click.argument("files", nargs=-1, required=True)
@click.option("--start", "-s", help="开始时间，格式: '2024-01-01 12:00:00' 或相对时间 '30m'")
@click.option("--end", "-e", help="结束时间，格式同上")
@click.option("--last", "-l", help="查询最近时间段，如 '30m', '2h', '1d'")
@click.option("--level", "-L", multiple=True, help="按日志级别过滤，可重复: -L ERROR -L WARN")
@click.option("--tail", "-n", type=int, help="显示最后 N 条记录")
@click.option("--no-color", is_flag=True, help="禁用彩色输出")
@click.option("--hide-sensitive", "-H", is_flag=True, help="隐藏敏感字段（密码、token等）")
@click.option("--service", "-S", help="按服务名过滤")
@click.option("--show-summary/--no-summary", default=True, help="是否显示摘要信息")
@click.option("--follow", "-f", is_flag=True, help="实时跟踪日志（类似 tail -f）")
def scan_cmd(
    files,
    start,
    end,
    last,
    level,
    tail,
    no_color,
    hide_sensitive,
    service,
    show_summary,
    follow,
):
    """按时间范围扫描日志，支持多文件合并"""
    parser = LogParser()

    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner("📊 日志扫描工具"))
    echo(Colorizer.banner("=" * 60))

    start_time, end_time = parse_time_range(start, end, last)
    _print_time_range(start_time, end_time)

    all_entries, file_stats = parser.parse_files(list(files))
    _print_file_stats(file_stats)

    if not all_entries:
        echo(Colorizer.warning("未找到任何日志记录"))
        return

    entries = _filter_entries(all_entries, start_time, end_time, level, service)

    if not entries:
        echo(Colorizer.warning("没有符合条件的日志记录"))
        return

    if tail and tail > 0:
        entries = entries[-tail:]

    if show_summary:
        _print_summary(entries, start_time, end_time, file_stats)

    echo("\n" + Colorizer.banner("-" * 60))
    echo(Colorizer.banner("📋 日志记录"))
    echo(Colorizer.banner("-" * 60) + "\n")

    _print_entries(entries, no_color, hide_sensitive)

    if follow:
        echo("\n" + Colorizer.warning("实时跟踪模式（Ctrl+C 退出）..."))
        _follow_mode(files, parser, level, service, no_color, hide_sensitive)


def _filter_entries(entries, start_time, end_time, levels, service_name):
    filtered = []
    for entry in entries:
        if not entry.in_time_range(start_time, end_time):
            continue
        if levels and entry.level not in levels:
            continue
        if service_name and entry.service != service_name:
            continue
        filtered.append(entry)
    return filtered


def _print_time_range(start, end):
    echo()
    if start and end:
        echo(
            f"⏰ {Colorizer.summary_key('时间范围:')} "
            f"{Colorizer.timestamp(format_timestamp(start))} "
            f"→ "
            f"{Colorizer.timestamp(format_timestamp(end))}"
        )
    elif start:
        echo(
            f"⏰ {Colorizer.summary_key('开始时间:')} "
            f"{Colorizer.timestamp(format_timestamp(start))}"
        )
    elif end:
        echo(
            f"⏰ {Colorizer.summary_key('结束时间:')} "
            f"{Colorizer.timestamp(format_timestamp(end))}"
        )
    echo()


def _print_file_stats(file_stats):
    if not file_stats:
        return
    echo(f"📁 {Colorizer.summary_key('扫描文件:')}")
    for filepath, line_count in file_stats.items():
        echo(
            f"   • {filepath} "
            f"({Colorizer.summary_value(str(line_count) + ' 行')})"
        )
    echo()


def _print_summary(entries, start_time, end_time, file_stats):
    level_counts = {}
    service_counts = {}
    error_count = 0
    warn_count = 0

    for entry in entries:
        level_counts[entry.level] = level_counts.get(entry.level, 0) + 1
        service_counts[entry.service] = service_counts.get(entry.service, 0) + 1
        if entry.is_error:
            error_count += 1
        if entry.is_warn:
            warn_count += 1

    max_level = max(level_counts.values()) if level_counts else 1

    echo(Colorizer.banner("📈 扫描摘要"))
    echo(Colorizer.banner("-" * 40))

    echo(
        f"   {Colorizer.summary_key('总记录数:')} "
        f"{Colorizer.summary_value(str(len(entries)), highlight=True)}"
    )
    echo(
        f"   {Colorizer.summary_key('错误数:')} "
        f"{Colorizer.summary_value(str(error_count), highlight=error_count > 0)}"
    )
    echo(
        f"   {Colorizer.summary_key('警告数:')} "
        f"{Colorizer.summary_value(str(warn_count), highlight=warn_count > 10)}"
    )
    echo()

    echo(f"   {Colorizer.summary_key('级别分布:')}")
    for level in ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"]:
        if level in level_counts:
            count = level_counts[level]
            bar = Colorizer.bar(count, max_level)
            echo(
                f"     {Colorizer.level(level):<18} "
                f"{bar} {count:>5}"
            )
    echo()

    if len(service_counts) > 1:
        echo(f"   {Colorizer.summary_key('服务分布:')}")
        max_svc = max(service_counts.values())
        for svc, count in sorted(service_counts.items(), key=lambda x: -x[1]):
            bar = Colorizer.bar(count, max_svc, width=15)
            echo(
                f"     {Colorizer.service(svc):<20} "
                f"{bar} {count:>5}"
            )
        echo()


def _print_entries(entries, no_color, hide_sensitive):
    for i, entry in enumerate(entries, 1):
        _print_single_entry(entry, i, no_color, hide_sensitive)


def _print_single_entry(entry, index, no_color, hide_sensitive):
    timestamp = format_timestamp(entry.timestamp, "%Y-%m-%d %H:%M:%S.%f")[:-3]
    message = entry.message

    if hide_sensitive:
        message = mask_sensitive_data(message)

    if no_color:
        echo(
            f"[{timestamp}] [{entry.level}] [{entry.service}] "
            f"[{entry.trace_id}] {message}"
        )
    else:
        level_str = Colorizer.level(entry.level)
        ts_str = Colorizer.timestamp(timestamp)
        svc_str = Colorizer.service(entry.service)
        tid_str = Colorizer.trace_id(entry.trace_id)

        prefix = ""
        if entry.is_error:
            prefix = f"❌ "
        elif entry.is_warn:
            prefix = f"⚠️  "

        line = f"{prefix}[{ts_str}] [{level_str}] [{svc_str}] [{tid_str}] {message}"
        if entry.error_code:
            line += f" (错误码: {Colorizer.error_code(entry.error_code)})"
        if entry.duration_ms:
            line += f" [{entry.duration_ms:.0f}ms]"
        echo(line)


def _follow_mode(files, parser, levels, service_name, no_color, hide_sensitive):
    import time
    import os

    file_positions = {}
    for f in files:
        if os.path.isfile(f):
            file_positions[f] = os.path.getsize(f)

    try:
        while True:
            for filepath in files:
                if not os.path.isfile(filepath):
                    continue
                current_size = os.path.getsize(filepath)
                if filepath in file_positions and current_size > file_positions[filepath]:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(file_positions[filepath])
                        for line in f:
                            entry = parser.parse_line(line, source_file=filepath)
                            if entry:
                                if levels and entry.level not in levels:
                                    continue
                                if service_name and entry.service != service_name:
                                    continue
                                _print_single_entry(entry, 0, no_color, hide_sensitive)
                    file_positions[filepath] = current_size
            time.sleep(0.5)
    except KeyboardInterrupt:
        echo("\n" + Colorizer.success("已退出实时跟踪模式"))
