import click
from collections import defaultdict
from ..parser import LogParser
from ..models import TraceContext
from ..utils import (
    Colorizer,
    format_timestamp,
    parse_time_range,
    mask_sensitive_data,
)
from .scan import _filter_entries, _print_time_range, _print_file_stats
from ..output import echo


@click.command()
@click.argument("files", nargs=-1, required=True)
@click.option("--trace-id", "-t", help="指定 trace_id 追踪（可从错误日志中获取）")
@click.option("--find-errors", "-E", is_flag=True, help="自动查找所有包含错误的 trace")
@click.option("--start", "-s", help="开始时间")
@click.option("--end", "-e", help="结束时间")
@click.option("--last", "-l", help="最近时间段，如 '30m'")
@click.option("--hide-sensitive", "-H", is_flag=True, help="隐藏敏感字段")
@click.option("--no-color", is_flag=True, help="禁用彩色输出")
@click.option("--show-timeline/--no-timeline", default=True, help="显示时间线")
@click.option("--limit", "-n", type=int, default=10, help="显示前 N 个 trace")
def trace_cmd(
    files,
    trace_id,
    find_errors,
    start,
    end,
    last,
    hide_sensitive,
    no_color,
    show_timeline,
    limit,
):
    """按请求编号串联上下文，追踪调用链路"""
    parser = LogParser()

    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner("🔗 调用链追踪工具"))
    echo(Colorizer.banner("=" * 60))

    start_time, end_time = parse_time_range(start, end, last)
    _print_time_range(start_time, end_time)

    all_entries, file_stats = parser.parse_files(list(files))
    _print_file_stats(file_stats)

    if not all_entries:
        echo(Colorizer.warning("未找到任何日志记录"))
        return

    entries = _filter_entries(all_entries, start_time, end_time, None, None)

    trace_map = defaultdict(list)
    for entry in entries:
        if entry.trace_id:
            trace_map[entry.trace_id].append(entry)

    if trace_id:
        if trace_id not in trace_map:
            echo(Colorizer.error(f"未找到 trace_id: {trace_id}"))
            return
        contexts = [TraceContext(trace_id=trace_id, entries=trace_map[trace_id])]
    elif find_errors:
        error_traces = []
        for tid, t_entries in trace_map.items():
            if any(e.is_error for e in t_entries):
                error_traces.append(TraceContext(trace_id=tid, entries=t_entries))
        contexts = sorted(error_traces, key=lambda c: c.start_time or format_timestamp, reverse=True)[:limit]
        if not contexts:
            echo(Colorizer.success("没有发现包含错误的 trace"))
            return
        echo(Colorizer.warning(f"发现 {len(contexts)} 个包含错误的 trace:\n"))
    else:
        contexts = sorted(
            [TraceContext(trace_id=tid, entries=ents) for tid, ents in trace_map.items()],
            key=lambda c: len(c.entries),
            reverse=True,
        )[:limit]

    for i, ctx in enumerate(contexts, 1):
        _print_trace_context(ctx, i, hide_sensitive, no_color, show_timeline)
        if i < len(contexts):
            echo()


def _print_trace_context(ctx, index, hide_sensitive, no_color, show_timeline):
    echo(Colorizer.banner(f"{'=' * 60}"))
    status_icon = "❌" if ctx.has_error else "✅"
    echo(
        Colorizer.banner(
            f"{status_icon} Trace #{index}: {Colorizer.trace_id(ctx.trace_id)}"
        )
    )
    echo(Colorizer.banner(f"{'=' * 60}"))

    echo()
    echo(f"   {Colorizer.summary_key('总记录数:')} {Colorizer.summary_value(str(len(ctx.entries)), highlight=True)}")
    if ctx.start_time and ctx.end_time:
        echo(
            f"   {Colorizer.summary_key('开始时间:')} "
            f"{Colorizer.timestamp(format_timestamp(ctx.start_time))}"
        )
        echo(
            f"   {Colorizer.summary_key('结束时间:')} "
            f"{Colorizer.timestamp(format_timestamp(ctx.end_time))}"
        )
        duration = (ctx.end_time - ctx.start_time).total_seconds() * 1000
        echo(
            f"   {Colorizer.summary_key('持续时间:')} "
            f"{Colorizer.summary_value(f'{duration:.0f}ms', highlight=duration > 3000)}"
        )
    if ctx.total_duration_ms > 0:
        echo(
            f"   {Colorizer.summary_key('累计耗时:')} "
            f"{Colorizer.summary_value(f'{ctx.total_duration_ms:.0f}ms', highlight=ctx.total_duration_ms > 3000)}"
        )
    echo(
        f"   {Colorizer.summary_key('服务路径:')} "
        + " → ".join(Colorizer.service(s) for s in ctx.service_path)
    )

    error_count = sum(1 for e in ctx.entries if e.is_error)
    warn_count = sum(1 for e in ctx.entries if e.is_warn)
    if error_count > 0:
        echo(f"   {Colorizer.summary_key('错误数:')} {Colorizer.error_code(str(error_count))}")
    if warn_count > 0:
        echo(f"   {Colorizer.summary_key('警告数:')} {Colorizer.summary_value(str(warn_count), highlight=True)}")

    echo()

    if show_timeline and len(ctx.service_path) > 1:
        _print_timeline(ctx)
        echo()

    echo(Colorizer.banner("📋 详细日志:"))
    echo(Colorizer.banner("-" * 40))

    sorted_entries = sorted(ctx.entries, key=lambda e: e.timestamp)
    for i, entry in enumerate(sorted_entries, 1):
        _print_trace_entry(entry, i, hide_sensitive, no_color)

    echo()


def _print_timeline(ctx):
    echo(f"   {Colorizer.summary_key('调用时间线:')}")
    sorted_entries = sorted(ctx.entries, key=lambda e: e.timestamp)
    base_time = sorted_entries[0].timestamp
    max_offset = (sorted_entries[-1].timestamp - base_time).total_seconds() * 1000
    if max_offset == 0:
        max_offset = 1

    width = 40
    last_service = None
    for entry in sorted_entries:
        offset = (entry.timestamp - base_time).total_seconds() * 1000
        pos = min(int(width * offset / max_offset), width - 1)

        marker = "●"
        if entry.is_error:
            marker = Colorizer.error_code("✗")
        elif entry.is_warn:
            marker = Colorizer.warning("⚠").split(" ")[0]

        service_change = ""
        if last_service and entry.service != last_service:
            service_change = f" → {Colorizer.service(entry.service)}"
        last_service = entry.service

        line = " " * pos + marker
        echo(
            f"   {Colorizer.timestamp(format_timestamp(entry.timestamp, '%H:%M:%S.%f')[:-3])} "
            f"{line:<{width + 10}} {Colorizer.level(entry.level):<15} {entry.message[:50]}{service_change}"
        )


def _print_trace_entry(entry, index, hide_sensitive, no_color):
    timestamp = format_timestamp(entry.timestamp, "%Y-%m-%d %H:%M:%S.%f")[:-3]
    message = entry.message

    if hide_sensitive:
        message = mask_sensitive_data(message)

    if no_color:
        echo(
            f"  {index:>3}. [{timestamp}] [{entry.level}] [{entry.service}] "
            f"{message}"
        )
    else:
        level_str = Colorizer.level(entry.level)
        ts_str = Colorizer.timestamp(timestamp)
        svc_str = Colorizer.service(entry.service)

        prefix = "   "
        if entry.is_error:
            prefix = "❌ "
        elif entry.is_warn:
            prefix = "⚠️  "

        line = f"{prefix}{index:>3}. [{ts_str}] [{level_str}] [{svc_str}] {message}"
        if entry.duration_ms:
            line += f" [{entry.duration_ms:.0f}ms]"
        if entry.error_code:
            line += f" (错误码: {Colorizer.error_code(entry.error_code)})"
        echo(line)
