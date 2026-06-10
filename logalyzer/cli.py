import click
import sys
from . import __version__
from .commands import scan_cmd, filter_cmd, trace_cmd, stats_cmd, export_cmd
from .output import echo


@click.group()
@click.version_option(__version__, "-V", "--version")
@click.option("--no-color", is_flag=True, help="禁用彩色输出")
@click.option("--config", "-c", help="配置文件路径")
def main(no_color, config):
    """
    Logalyzer - 日志分析平台命令行工具

    快速定位线上问题，无需打开复杂后台。

    常用命令:
      scan    按时间范围扫描日志
      filter  按关键词过滤日志
      trace   按请求编号追踪调用链
      stats   统计分析（错误码、慢请求、峰值）
      export  导出分析结果和排查记录

    示例:
      logalyzer scan app.log --last 30m -L ERROR
      logalyzer filter app.log -k "NullPointerException" -C 5
      logalyzer trace app.log --trace-id abc123xyz
      logalyzer stats app.log --last 1h
      logalyzer export app.log -o report.txt --save-investigation
    """
    if no_color:
        import os
        os.environ["NO_COLOR"] = "1"


main.add_command(scan_cmd, "scan")
main.add_command(filter_cmd, "filter")
main.add_command(trace_cmd, "trace")
main.add_command(stats_cmd, "stats")
main.add_command(export_cmd, "export")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        echo("\n已取消操作")
        sys.exit(1)
    except Exception as e:
        echo(f"\n错误: {e}", err=True)
        sys.exit(1)
