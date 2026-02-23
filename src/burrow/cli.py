"""Command-line interface for Burrow (Python Wrapper to Go binary)."""
import os
import sys
import subprocess
import click

from burrow import __version__

def get_go_bin() -> str:
    import platform
    import shutil
    
    if os.path.isfile("./burrow") and os.access("./burrow", os.X_OK):
        return "./burrow"
        
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    arch = "amd64"
    if machine in ["aarch64", "arm64"]:
        arch = "arm64"
        
    ext = ".exe" if system == "windows" else ""
    cross_bin = f"burrow-{system}-{arch}{ext}"
    
    search_paths = [
        os.path.join(".", "build", "burrow"),
        os.path.join(".", "build", cross_bin),
        os.path.join(project_root, "build", "burrow"),
        os.path.join(project_root, "build", cross_bin)
    ]
    
    for path in search_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
            
    if shutil.which("burrow"):
        return "burrow"
        
    return "burrow"

GO_BIN = get_go_bin()

@click.group(context_settings={"ignore_unknown_options": True}, invoke_without_command=True)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def main(args: tuple[str, ...]) -> None:
    """Burrow -- Network pivoting and tunneling."""
    if not args:
        try:
            subprocess.run([GO_BIN, "--help"])
        except FileNotFoundError:
            click.echo(f"[!] Go binary '{GO_BIN}' not found in PATH or current directory.", err=True)
            click.echo("Please build the Go backend first: 'go mod tidy && go build -o burrow main.go'", err=True)
        return
        
    # Proxy 'web' command to launch the Python FastAPI wrapper
    if args[0] == "web":
        try:
            import uvicorn
            from burrow.web import create_app
        except ImportError:
            click.echo("[!] Missing dependencies. Run 'pip install uvicorn httpx fastapi'", err=True)
            sys.exit(1)
            
        click.echo("[*] Starting Python MCP Web Wrapper on 127.0.0.1:8000...")
        click.echo("[*] Make sure BURROW_API_TOKEN and BURROW_API_URL are set to communicate with the Go backend.")
        uvicorn.run(create_app(), host="127.0.0.1", port=8000)
    else:
        # Pass-through any other commands strictly to the high-performance Go binary
        # This preserves EVERY existing technique natively written in Go (pivot, relay, discover, etc)
        try:
            subprocess.run([GO_BIN, *args])
        except FileNotFoundError:
            click.echo(f"[!] Go binary '{GO_BIN}' not found in PATH or current directory.", err=True)
            click.echo("Please build the Go backend first: 'go build -o burrow main.go'", err=True)
            sys.exit(1)

if __name__ == "__main__":
    main()
