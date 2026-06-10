import click
from ..parser import LogParser
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
@click.option("--keyword", "-k", multiple=True, required=True, help="关键词，可重复指定")
@click.option("--exclude", "-x", multiple=True, help="排除关键词，可重复指定")
@click.option("--case-sensitive", "-c", is_flag=True, help="区分大小写")
@click.option("--start", "-s", help="开始时间")
@click.option("--end", "-e", help="结束时间")
@click.option("--last", "-l", help="最近时间段，如 '30m'")
@click.option("--level", "-L", multiple=True, help="日志级别过滤")
@click.option("--hide-sensitive", "-H", is_flag=True, help="隐藏敏感字段")
@click.option("--no-color", is_flag=True, help="禁用彩色输出")
@click.option("--context", "-C", type=int, default=0, help="显示匹配行前后 N 行上下文")
@click.option("--count-only", is_flag=True, help="仅显示匹配数量")
@click.option("--highlight", is_flag=True, default=True, help="高亮匹配关键词")
def filter_cmd(
    files,
    keyword,
    exclude,
    case_sensitive,
    start,
    end,
    last,
    level,
    hide_sensitive,
    no_color,
    context,
    count_only,
    highlight,
):
    """按关键词过滤日志"""
    parser = LogParser()

    echo(Colorizer.banner("=" * 60))
    echo(Colorizer.banner("🔍 日志过滤工具"))
    echo(Colorizer.banner("=" * 60))

    start_time, end_time = parse_time_range(start, end, last)
    _print_time_range(start_time, end_time)

    echo(f"🔑 {Colorizer.summary_key('包含关键词:')} " + ", ".join(Colorizer.summary_value(kw, highlight=True) for kw in keyword))
    if exclude:
        echo(f"🚫 {Colorizer.summary_key('排除关键词:')} " + ", ".join(Colorizer.error_code(kw) for kw in exclude))
    echo()

    all_entries, file_stats = parser.parse_files(list(files))
    _print_file_stats(file_stats)

    if not all_entries:
        echo(Colorizer.warning("未找到任何日志记录"))
        return

    entries = _filter_entries(all_entries, start_time, end_time, level, None)
    matched_indices = []

    for i, entry in enumerate(entries):
        if entry.matches_keywords(list(keyword), case_sensitive):
            if exclude and entry.matches_keywords(list(exclude), case_sensitive):
                continue
            matched_indices.append(i)

    if not matched_indices:
        echo(Colorizer.warning("没有找到匹配的日志记录"))
        return

    if count_only:
        echo(Colorizer.success(f"找到 {len(matched_indices)} 条匹配记录"))
        return

    context_entries = set()
    if context > 0:
        for idx in matched_indices:
            for j in range(max(0, idx - context), min(len(entries), idx + context + 1)):
                context_entries.add(j)
    else:
        context_entries = set(matched_indices)

    display_entries = [entries[i] for i in sorted(context_entries)]

    echo(Colorizer.banner("-" * 60))
    echo(
        Colorizer.banner(
            f"📋 匹配结果: {len(matched_indices)} 条"
            + (f" (含上下文共 {len(display_entries)} 条)" if context > 0 else "")
        )
    )
    echo(Colorizer.banner("-" * 60) + "\n")

    for entry in display_entries:
        _print_filtered_entry(
            entry,
            list(keyword),
            highlight and not no_color,
            no_color,
            hide_sensitive,
            entry in [entries[i] for i in matched_indices],
        )

    echo("\n" + Colorizer.success(f"共找到 {len(matched_indices)} 条匹配记录"))


def _print_filtered_entry(entry, keywords, do_highlight, no_color, hide_sensitive, is_match):
    timestamp = format_timestamp(entry.timestamp, "%Y-%m-%d %H:%M:%S.%f")[:-3]
    message = entry.message

    if hide_sensitive:
        message = mask_sensitive_data(message)

    if do_highlight:
        message = Colorizer.highlight_all(message, keywords)

    if no_color:
        marker = ">>>" if is_match else "   "
        echo(
            f"{marker} [{timestamp}] [{entry.level}] [{entry.service}] "
            f"[{entry.trace_id}] {message}"
        )
    else:
        level_str = Colorizer.level(entry.level)
        ts_str = Colorizer.timestamp(timestamp)
        svc_str = Colorizer.service(entry.service)
        tid_str = Colorizer.trace_id(entry.trace_id)

        prefix = "📍 " if is_match else "   "
        if is_match and entry.is_error:
            prefix = "❌ "
        elif is_match and entry.is_warn:
            prefix = "⚠️  "

        line = f"{prefix}[{ts_str}] [{level_str}] [{svc_str}] [{tid_str}] {message}"
        if entry.error_code:
            line += f" (错误码: {Colorizer.error_code(entry.error_code)})"
        echo(line)
