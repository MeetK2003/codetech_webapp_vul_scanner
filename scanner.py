import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Display a colorful welcome banner
def show_banner():
    console.print(Panel.fit(
        "[bold green]🛡️ Python Web Scanner[/bold green]\n"
        "[yellow]By CodeTech • Testing for SQLi & XSS[/yellow]",
        box=box.DOUBLE, style="bold blue"))

# Scan a website and test all forms for vulnerabilities
def scan_website(url):
    show_banner()
    console.print(f"[bold blue]🌐 Scanning:[/] {url}\n")

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")
        console.print(f"[green]✅ Found {len(forms)} form(s)[/green]")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Form #")
        table.add_column("SQL Injection")
        table.add_column("XSS")

        for i, form in enumerate(forms):
            sql_result = test_sql_injection(url, form)
            xss_result = test_xss(url, form)

            table.add_row(f"{i+1}", sql_result, xss_result)

        console.print("\n[bold]🔍 Scan Results:[/bold]")
        console.print(table)

    except Exception as e:
        console.print(f"[bold red]❌ Error:[/] {e}")

# Test for SQL Injection
def test_sql_injection(base_url, form):
    data = {}
    for input_tag in form.find_all("input"):
        name = input_tag.get("name")
        if name:
            data[name] = "' OR '1'='1"

    action = form.get("action")
    method = form.get("method", "get").lower()
    full_url = urljoin(base_url, action) if action else base_url

    try:
        if method == "post":
            response = requests.post(full_url, data=data)
        else:
            response = requests.get(full_url, params=data)

        if "error" in response.text.lower() or "sql" in response.text.lower():
            return "[bold red]⚠️ Vulnerable[/bold red]"
        else:
            return "[green]✔️ Safe[/green]"
    except Exception as e:
        return "[yellow]❌ Error[/yellow]"

# Test for XSS
def test_xss(base_url, form):
    xss_payload = "<script>alert('XSS')</script>"
    data = {}
    for input_tag in form.find_all("input"):
        name = input_tag.get("name")
        if name:
            data[name] = xss_payload

    action = form.get("action")
    method = form.get("method", "get").lower()
    full_url = urljoin(base_url, action) if action else base_url

    try:
        if method == "post":
            response = requests.post(full_url, data=data)
        else:
            response = requests.get(full_url, params=data)

        if xss_payload in response.text:
            return "[bold red]⚠️ Vulnerable[/bold red]"
        else:
            return "[green]✔️ Safe[/green]"
    except Exception as e:
        return "[yellow]❌ Error[/yellow]"

# Start program
if __name__ == "__main__":
    console.print("[cyan]Enter a website to scan (e.g., http://testphp.vulnweb.com):[/cyan]")
    website_to_scan = input(">> ").strip()
    if not website_to_scan.startswith("http"):
        website_to_scan = "http://" + website_to_scan
    scan_website(website_to_scan)
