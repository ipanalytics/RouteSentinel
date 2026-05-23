from __future__ import annotations

from pathlib import Path

import click

from routesentinel.io import download_file, parse_mrt_with_bgpdump
from routesentinel.pipeline import run_snapshot


def log_progress(message: str) -> None:
    click.echo(f"[routesentinel] {message}", err=True)


@click.group()
def main() -> None:
    """RouteSentinel daily route-security dataset builder."""


@main.command()
@click.argument("url")
@click.argument("output", type=click.Path(path_type=Path))
def fetch(url: str, output: Path) -> None:
    """Download a source dump with a responsible User-Agent."""

    click.echo(download_file(url, output, progress=log_progress))


@main.command("parse-mrt")
@click.argument("mrt_path", type=click.Path(exists=True, path_type=Path))
@click.argument("output_csv", type=click.Path(path_type=Path))
@click.option("--collector", required=True, help="Collector label, e.g. rrc00 or route-views2.")
def parse_mrt(mrt_path: Path, output_csv: Path, collector: str) -> None:
    """Normalize an MRT RIB dump to RouteSentinel CSV."""

    click.echo(parse_mrt_with_bgpdump(mrt_path, output_csv, collector, progress=log_progress))


@main.command("snapshot")
@click.option("--announcements", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--vrps", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--out", "output_dir", required=True, type=click.Path(path_type=Path))
def snapshot(announcements: Path, vrps: Path, output_dir: Path) -> None:
    """Build daily RPKI status and suspected-event outputs."""

    run_snapshot(announcements, vrps, output_dir, progress=log_progress)
    click.echo(output_dir)


if __name__ == "__main__":
    main()
