import click
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from ..parser import LogParser
from ..utils import (
    Colorizer,
    format_timestamp,
    parse_time_range,
)
from .scan import _filter_entries, _print_time_range, _print_file_stats
from ..output import echo


@click.command()
@click.argument("files", nargs=-1, required=True)
@click.option("--start", "-s", help="开始时间")
@click.option("--end", "-e", help="结束时间")
@click.option("--last", "-l", help="最近时间段，如 '30m'")
@click.option("--level", "-L", multiple=True, help="日志级别过滤")
@click.option("--service", "-S", help="按服务名过滤")
@click.option("--slow-threshold", type=int, default=3000, help="慢请求阈值(ms)，默认3000ms")
@click.option("--top-error-codes", type=int, default=10, help="显示前N个错误码")
@click.option("--top-slow-requests", type=int, default=10, help="显示前N个慢请求")
@click.option("--peak-interval", type=click.Choice(["1m", "5m", "10m", "15m", "1h"]), default="5m", help="峰值分析时间间隔")
@click.option("--no-color", is_flag=True, help="禁用彩色输出")
def stats_cmd(
    files,
    start,
    end,
    last,
    level,
    service,
    slow_threshold,
    top_error_codes,
    top_slow_requests,
    peak_interval,
    no_color,
):
    """统计分析：错误码、慢请求、峰值时段"""
    parser = LogParser()

    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner("📊 日志统计分析"))
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

    echo(Colorizer.banner("-" * 60))
    _print_overall_stats(entries)
    echo()

    echo(Colorizer.banner("-" * 60))
    _print_error_code_stats(entries, top_error_codes)
    echo()

    echo(Colorizer.banner("-" * 60))
    _print_slow_request_stats(entries, slow_threshold, top_slow_requests)
    echo()

    echo(Colorizer.banner("-" * 60))
    _print_peak_hour_stats(entries, peak_interval)
    echo()

    echo(Colorizer.banner("-" * 60))
    _print_service_stats(entries)


def _print_overall_stats(entries):
    echo(Colorizer.banner("📈 总体统计"))

    total = len(entries)
    error_count = sum(1 for e in entries if e.is_error)
    warn_count = sum(1 for e in entries if e.is_warn)
    info_count = sum(1 for e in entries if e.level == "INFO")
    debug_count = sum(1 for e in entries if e.level == "DEBUG")

    error_rate = (error_count / total * 100) if total > 0 else 0

    stats = [
        ("总请求数", str(total), True),
        ("错误数", str(error_count), error_count > 0),
        ("警告数", str(warn_count), warn_count > 50),
        ("错误率", f"{error_rate:.2f}%", error_rate > 5),
    ]

    max_key_len = max(len(k) for k, _, _ in stats)
    for key, value, highlight in stats:
        echo(
            f"   {Colorizer.summary_key(key + ':'):<{max_key_len + 6}}"
            f"{Colorizer.summary_value(value, highlight=highlight)}"
        )

    echo()
    echo(f"   {Colorizer.summary_key('级别分布:')}")
    max_count = max(total, 1)
    for level, count, color in [
        ("ERROR", error_count, Fore.RED),
        ("WARN", warn_count, Fore.YELLOW),
        ("INFO", info_count, Fore.GREEN),
        ("DEBUG", debug_count, Fore.CYAN),
    ]:
        if count > 0:
            bar = Colorizer.bar(count, max_count)
            pct = count / total * 100 if total > 0 else 0
            echo(
                f"     {Colorizer.level(level):<12} "
                f"{bar} {count:>5} ({pct:>5.1f}%)"
            )

    if entries:
        durations = [e.duration_ms for e in entries if e.duration_ms]
        if durations:
            avg_dur = sum(durations) / len(durations)
            max_dur = max(durations)
            min_dur = min(durations)
            echo()
            echo(f"   {Colorizer.summary_key('响应时间:')}")
            echo(
                f"     平均: {Colorizer.summary_value(f'{avg_dur:.0f}ms', highlight=avg_dur > 1000)}"
                f" | 最小: {Colorizer.summary_value(f'{min_dur:.0f}ms')}"
                f" | 最大: {Colorizer.summary_value(f'{max_dur:.0f}ms', highlight=max_dur > 3000)}"
            )

            durations.sort()
            p95 = durations[int(len(durations) * 0.95)]
            p99 = durations[int(len(durations) * 0.99)]
            echo(
                f"     P95: {Colorizer.summary_value(f'{p95:.0f}ms', highlight=p95 > 2000)}"
                f" | P99: {Colorizer.summary_value(f'{p99:.0f}ms', highlight=p99 > 5000)}"
            )


def _print_error_code_stats(entries, top_n):
    echo(Colorizer.banner(f"🏷️  错误码统计 (Top {top_n})"))

    error_entries = [e for e in entries if e.error_code]
    if not error_entries:
        echo(Colorizer.success("   未发现错误码"))
        return

    code_counter = Counter(e.error_code for e in error_entries)
    max_count = max(code_counter.values())

    echo(f"   {Colorizer.summary_key('总错误码出现次数:')} {Colorizer.summary_value(str(len(error_entries)), highlight=True)}")
    echo()

    for i, (code, count) in enumerate(code_counter.most_common(top_n), 1):
        sample = next((e.message for e in error_entries if e.error_code == code), "")
        bar = Colorizer.bar(count, max_count, width=15)
        pct = count / len(error_entries) * 100
        echo(
            f"   {i:>2}. {Colorizer.error_code(code):<15} "
            f"{bar} {count:>5} ({pct:>5.1f}%)"
        )
        if sample:
            echo(f"       示例: {sample[:80]}")


def _print_slow_request_stats(entries, threshold_ms, top_n):
    echo(Colorizer.banner(f"🐢 慢请求分析 (>{threshold_ms}ms, Top {top_n})"))

    slow_entries = [e for e in entries if e.duration_ms and e.duration_ms > threshold_ms]
    if not slow_entries:
        echo(Colorizer.success(f"   未发现超过 {threshold_ms}ms 的慢请求"))
        return

    slow_entries.sort(key=lambda e: e.duration_ms, reverse=True)

    echo(
        f"   {Colorizer.summary_key('慢请求总数:')} "
        f"{Colorizer.summary_value(str(len(slow_entries)), highlight=True)}"
        f" / {len(entries)} "
        f"({Colorizer.summary_value(f'{len(slow_entries)/len(entries)*100:.2f}%', highlight=len(slow_entries)/len(entries)*100 > 5)})"
    )
    echo()

    for i, entry in enumerate(slow_entries[:top_n], 1):
        ts = format_timestamp(entry.timestamp, "%Y-%m-%d %H:%M:%S")
        duration_str = Colorizer.summary_value(f"{entry.duration_ms:.0f}ms", highlight=entry.duration_ms > 10000)
        trace_id = entry.trace_id or "N/A"
        echo(
            f"   {i:>2}. {Colorizer.timestamp(ts)} "
            f"[{Colorizer.service(entry.service)}] "
            f"耗时: {duration_str}"
        )
        echo(f"       {Colorizer.trace_id(trace_id)}")
        echo(f"       {entry.message[:100]}")
        if i < min(top_n, len(slow_entries)):
            echo()


def _print_peak_hour_stats(entries, interval_str):
    echo(Colorizer.banner(f"⚡ 峰值时段分析 (间隔: {interval_str})"))

    if not entries:
        return

    interval_map = {
        "1m": 60,
        "5m": 300,
        "10m": 600,
        "15m": 900,
        "1h": 3600,
    }
    interval_seconds = interval_map.get(interval_str, 300)

    time_buckets = defaultdict(lambda: {"total": 0, "error": 0, "slow": 0})

    for entry in entries:
        ts = entry.timestamp
        bucket_ts = ts - timedelta(
            seconds=ts.second % interval_seconds,
            microseconds=ts.microsecond
        )
        bucket_key = bucket_ts.strftime("%Y-%m-%d %H:%M")
        time_buckets[bucket_key]["total"] += 1
        if entry.is_error:
            time_buckets[bucket_key]["error"] += 1
        if entry.duration_ms and entry.duration_ms > 3000:
            time_buckets[bucket_key]["slow"] += 1

    sorted_buckets = sorted(time_buckets.items(), key=lambda x: x[1]["total"], reverse=True)

    if not sorted_buckets:
        return

    peak_bucket = sorted_buckets[0]
    max_total = peak_bucket[1]["total"]

    echo(
        f"   {Colorizer.summary_key('峰值时段:')} "
        f"{Colorizer.timestamp(peak_bucket[0])} "
        f"{Colorizer.summary_value(str(max_total) + ' 次请求', highlight=True)}"
    )
    echo()

    echo(f"   {Colorizer.summary_key('Top 5 高峰时段:')}")
    for i, (bucket, data) in enumerate(sorted_buckets[:5], 1):
        bar = Colorizer.bar(data["total"], max_total, width=15)
        error_part = f" | 错误: {data['error']}" if data["error"] > 0 else ""
        slow_part = f" | 慢请求: {data['slow']}" if data["slow"] > 0 else ""
        echo(
            f"   {i:>2}. {Colorizer.timestamp(bucket):<18} "
            f"{bar} {data['total']:>5}"
            f"{error_part}{slow_part}"
        )

    echo()
    echo(f"   {Colorizer.summary_key('时间趋势:')}")
    for bucket, data in sorted(time_buckets.items())[-12:]:
        bar = Colorizer.bar(data["total"], max_total, width=25)
        error_flag = Colorizer.error_code(" ❌") if data["error"] > 0 else ""
        echo(f"   {Colorizer.timestamp(bucket):<18} {bar} {data['total']:>5}{error_flag}")


def _print_service_stats(entries):
    echo(Colorizer.banner("🏗️  服务维度统计"))

    service_stats = defaultdict(lambda: {"total": 0, "error": 0, "warn": 0, "durations": []})

    for entry in entries:
        svc = entry.service or "unknown"
        service_stats[svc]["total"] += 1
        if entry.is_error:
            service_stats[svc]["error"] += 1
        if entry.is_warn:
            service_stats[svc]["warn"] += 1
        if entry.duration_ms:
            service_stats[svc]["durations"].append(entry.duration_ms)

    if not service_stats:
        return

    sorted_svcs = sorted(service_stats.items(), key=lambda x: x[1]["total"], reverse=True)
    max_total = max(s["total"] for s in service_stats.values())

    for svc, data in sorted_svcs:
        total = data["total"]
        errors = data["error"]
        warns = data["warn"]
        error_rate = errors / total * 100 if total > 0 else 0

        avg_dur = 0
        if data["durations"]:
            avg_dur = sum(data["durations"]) / len(data["durations"])

        bar = Colorizer.bar(total, max_total, width=12)
        echo(
            f"   {Colorizer.service(svc):<20} "
            f"{bar} {total:>5} "
            f"| 错误: {Colorizer.error_code(str(errors)) if errors > 0 else '0':<8} "
            f"| 错误率: {Colorizer.summary_value(f'{error_rate:.1f}%', highlight=error_rate > 5):<10} "
            + (f"| 平均耗时: {Colorizer.summary_value(f'{avg_dur:.0f}ms', highlight=avg_dur > 1000)}" if avg_dur > 0 else "")
        )


from colorama import Fore
