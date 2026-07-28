"""CLI entry point for LazyHound."""

from __future__ import annotations

import click

from lazyhound import __version__


@click.group(invoke_without_command=True)
@click.option("--config", "-c", default=None, help="Path to YAML config file")
@click.option("--profile", "-p", default=None, help="Config profile name")
@click.pass_context
def main(ctx: click.Context, config: str | None, profile: str | None) -> None:
    """LazyHound – Active Directory & Entra attack-path analysis."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["profile"] = profile

    if ctx.invoked_subcommand is None:
        # Launch interactive shell
        from lazyhound.config import Config
        cfg = Config.load(path=config, profile=profile)
        from lazyhound.shell import InteractiveShell
        shell = InteractiveShell(config=cfg)
        shell.run()


@main.command()
def version() -> None:
    """Show version information."""
    from lazyhound.formatting import _render_logo, console
    _render_logo()
    console.print(f"\n[bold]LazyHound[/bold] v{__version__}")


def _scaffold_project(project_dir, force: bool = False, echo=None):
    """Create/verify a project folder: config, subdirs, and databases.

    Everything (config, databases, logs, reports) lives inside the
    project folder so nothing is scattered across the system.  The written
    config pins ``paths.base_dir`` to the folder's *absolute* path, so all
    relative paths resolve there regardless of the current working directory.

    Returns the path to the project's ``lazyhound.yml``.  *echo* is an optional
    ``callable(str)`` used for progress output (e.g. ``click.echo``).
    """
    from pathlib import Path
    from lazyhound.config import Config

    echo = echo or (lambda _msg: None)
    project = Path(project_dir).expanduser().resolve()
    project.mkdir(parents=True, exist_ok=True)

    # 1. Write YAML config inside project folder, base_dir pinned to it.
    config_path = project / "lazyhound.yml"
    if config_path.exists() and not force:
        echo(f"Config already exists: {config_path} (use --force to overwrite)")
    else:
        template = Config.generate_template(base_dir=str(project))
        config_path.write_text(template, encoding="utf-8")
        echo(f"Config: {config_path}")

    # 2. Create subdirectories (all under the project folder).
    subdirs = {
        "logs":        project / "logs",
        "reports":     project / "reports",
        "exports":     project / "exports",
    }
    for label, d in subdirs.items():
        d.mkdir(parents=True, exist_ok=True)
        echo(f"  {label + '/':15s} {d}")

    # 2b. Drop editable report templates (one Markdown file per report type).
    from lazyhound.finder.reports.report_template import scaffold_templates
    templates_dir = project / "templates"
    written = scaffold_templates(templates_dir)
    echo(f"  {'templates/':15s} {templates_dir}  ({len(written)} report templates)")

    # 3. Initialize the local history/state DB.
    from lazyhound.storage.history import HistoryStore
    db_path = project / "lazyhound_history.db"
    HistoryStore(db_path).close()
    echo(f"  {'history.db':15s} {db_path}")

    # 4. Initialize finder (scan + collection) history DB.
    from lazyhound.finder.storage.history import ScanHistory
    finder_db = project / "lazyhound_finder_history.db"
    finder_history = ScanHistory(finder_db)
    finder_history.open()
    finder_history.close()
    echo(f"  {'scanner.db':15s} {finder_db}")

    return config_path


@main.command()
@click.argument("project_dir", default=".")
@click.option("--force", is_flag=True, help="Overwrite existing config")
def init(project_dir: str, force: bool) -> None:
    """Initialize a project folder with config, directories, and databases.

    \b
    Usage:
      lazyhound init /opt/engagements/acme
      lazyhound init .          # current directory
      lazyhound init            # same as '.'

    Everything (config, databases, logs, reports) lives
    inside the project folder so nothing is scattered across the system.
    """
    from pathlib import Path

    config_path = _scaffold_project(project_dir, force=force, echo=click.echo)
    project = config_path.parent
    click.echo(f"\nProject initialized: {project}")
    click.echo(f"Start with: cd {project} && lazyhound")


if __name__ == "__main__":
    main()
