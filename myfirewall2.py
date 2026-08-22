# myfirewall2.py
"""
GORT Firewall - Autonomous Linux Endpoint Defense & Connection Inspector
Powered by Textual TUI, Linux Kernel Netfilter, Zero-Trust Engine & Google Antigravity AI
"""

import sys
import time
import asyncio
import ipaddress
from threading import Thread

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import (
    Header,
    Footer,
    DataTable,
    Input,
    Static,
    Tabs,
    Tab,
    Label,
    Button,
)
from textual.screen import ModalScreen
from textual.binding import Binding
from textual.reactive import reactive
from rich.text import Text

import myfirewall_core as core
from process_resolver import get_detailed_process_info
import zero_trust_engine as zte
import ai_advisor as aia


def fmt_duration(first_seen):
    """Formats seconds elapsed since first_seen into a compact string."""
    secs = int(time.time() - first_seen)
    if secs < 0:
        secs = 0
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m{secs % 60:02d}s"
    h = secs // 3600
    m = (secs % 3600) // 60
    return f"{h}h{m:02d}m"


def fmt_pkts(n):
    """Formats a packet count compactly (None → '—')."""
    if n is None:
        return "—"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def fmt_bytes_rate(rate):
    """Formats byte/sec rate into KB/s or MB/s."""
    if rate is None or rate < 0:
        rate = 0
    if rate >= 1_048_576:
        return f"{rate / 1_048_576:.2f} MB/s"
    if rate >= 1024:
        return f"{rate / 1024:.1f} KB/s"
    return f"{rate:.0f} B/s"


# --- Modal Screens ---

class BlockModal(ModalScreen):
    """Modal for manually blocking/unblocking an IP or CIDR."""

    CSS = """
    BlockModal {
        align: center middle;
    }
    #block-dialog {
        width: 60;
        height: auto;
        border: thick $error;
        background: $surface;
        padding: 1 2;
    }
    #block-title {
        text-style: bold;
        color: $error;
        margin-bottom: 1;
        text-align: center;
    }
    #block-input {
        margin-bottom: 1;
    }
    #block-buttons {
        align: right middle;
        height: auto;
    }
    #block-buttons Button {
        margin-left: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, default_ip: str = ""):
        super().__init__()
        self.default_ip = default_ip

    def compose(self) -> ComposeResult:
        with Vertical(id="block-dialog"):
            yield Label("🛡️ Block / Unblock Remote IP (Netfilter)", id="block-title")
            yield Label("Enter IP address or CIDR range to toggle:")
            yield Input(value=self.default_ip, placeholder="e.g. 142.250.190.46 or 192.168.1.0/24", id="block-input")
            with Horizontal(id="block-buttons"):
                yield Button("Toggle Block", variant="error", id="btn-block")
                yield Button("Cancel", variant="default", id="btn-cancel")

    def on_mount(self) -> None:
        self.query_one("#block-input", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-block":
            val = self.query_one("#block-input", Input).value.strip()
            if val:
                core.toggle_ip_block(val)
            self.dismiss(val)
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        val = event.value.strip()
        if val:
            core.toggle_ip_block(val)
        self.dismiss(val)


class IgnoreModal(ModalScreen):
    """Modal for ignoring/un-ignoring a process name or IP."""

    CSS = """
    IgnoreModal {
        align: center middle;
    }
    #ignore-dialog {
        width: 60;
        height: auto;
        border: thick $warning;
        background: $surface;
        padding: 1 2;
    }
    #ignore-title {
        text-style: bold;
        color: $warning;
        margin-bottom: 1;
        text-align: center;
    }
    #ignore-input {
        margin-bottom: 1;
    }
    #ignore-buttons {
        align: right middle;
        height: auto;
    }
    #ignore-buttons Button {
        margin-left: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, default_name: str = ""):
        super().__init__()
        self.default_name = default_name

    def compose(self) -> ComposeResult:
        with Vertical(id="ignore-dialog"):
            yield Label("🙈 Ignore / Hide Process or IP", id="ignore-title")
            yield Label("Enter Process Name (e.g. 'chrome') or IP/CIDR to hide:")
            yield Input(value=self.default_name, placeholder="e.g. chrome, discord, or 10.0.0.0/8", id="ignore-input")
            with Horizontal(id="ignore-buttons"):
                yield Button("Toggle Ignore", variant="warning", id="btn-ignore")
                yield Button("Cancel", variant="default", id="btn-cancel")

    def on_mount(self) -> None:
        self.query_one("#ignore-input", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-ignore":
            self._handle_submit()
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._handle_submit()

    def _handle_submit(self) -> None:
        val = self.query_one("#ignore-input", Input).value.strip()
        if val:
            if "/" in val:
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if net in core.ignored_cidrs:
                        core.ignored_cidrs.remove(net)
                    else:
                        core.ignored_cidrs.append(net)
                    core.save_config()
                except ValueError:
                    pass
            else:
                try:
                    ipaddress.ip_address(val)
                    core.toggle_ip_ignore(val)
                except ValueError:
                    core.toggle_proc_ignore(val)
        self.dismiss(val)


class ExplainModal(ModalScreen):
    """Modal showing real-time AI safety explanation for a connection."""

    CSS = """
    ExplainModal {
        align: center middle;
    }
    #explain-dialog {
        width: 75;
        height: auto;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #explain-title {
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
        text-align: center;
    }
    #explain-content {
        margin-bottom: 1;
        height: auto;
    }
    #explain-buttons {
        align: center middle;
        height: auto;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("enter", "dismiss", "Close"),
    ]

    def __init__(self, conn: dict):
        super().__init__()
        self.conn = conn

    def compose(self) -> ComposeResult:
        with Vertical(id="explain-dialog"):
            yield Label("🤖 Gort AI & Zero-Trust Safety Analysis", id="explain-title")
            yield Static("⏳ Consulting Gort AI Agent & evaluating Zero-Trust telemetry...", id="explain-content")
            with Horizontal(id="explain-buttons"):
                yield Button("Close (Esc)", variant="primary", id="btn-close")

    def on_mount(self) -> None:
        self.run_worker(self._fetch_explanation(), exclusive=True)

    async def _fetch_explanation(self) -> None:
        exp = await aia.advisor.explain_connection(self.conn)
        zt = zte.evaluate_zero_trust(self.conn)
        anom_str = f"\n[bold yellow]Anomalies:[/] {', '.join(zt['anomalies'])}" if zt["anomalies"] else ""
        
        full_text = (
            f"[bold cyan]Process:[/] [green]{self.conn.get('name', 'Unknown')}[/] (PID: {self.conn.get('pid', '?')})\n"
            f"[bold cyan]Destination:[/] {self.conn.get('remote_ip')}:{self.conn.get('remote_port')} ({self.conn.get('geo', 'Unknown')})\n"
            f"[bold cyan]Zero-Trust Zone:[/] {zt['zone_desc']}\n"
            f"[bold cyan]Trust Score:[/] {zt['badge']}{anom_str}\n\n"
            f"[bold white]AI Safety Assessment:[/] \n{exp}"
        )
        self.query_one("#explain-content", Static).update(full_text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def on_key(self, event) -> None:
        if event.key in ("escape", "enter", "q"):
            self.dismiss()


class CopilotModal(ModalScreen):
    """Interactive Ask Gort AI Copilot modal."""

    CSS = """
    CopilotModal {
        align: center middle;
    }
    #copilot-dialog {
        width: 80;
        height: auto;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #copilot-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
        text-align: center;
    }
    #copilot-input {
        margin-bottom: 1;
    }
    #copilot-response {
        height: 7;
        overflow-y: auto;
        background: $surface-darken-1;
        padding: 1;
        margin-bottom: 1;
        border: solid $accent-darken-2;
    }
    #copilot-buttons {
        align: right middle;
        height: auto;
    }
    #copilot-buttons Button {
        margin-left: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Close"),
    ]

    def __init__(self, active_conns: list):
        super().__init__()
        self.active_conns = active_conns

    def compose(self) -> ComposeResult:
        with Vertical(id="copilot-dialog"):
            yield Label("💬 Ask Gort AI Copilot (Google Gemini / Antigravity)", id="copilot-title")
            yield Input(placeholder="Ask anything: e.g. 'Is my connection secure?', 'Why is Chrome sending data?'", id="copilot-input")
            yield Static("Ask a question above to get real-time security advice and firewall guidance.", id="copilot-response")
            with Horizontal(id="copilot-buttons"):
                yield Button("Ask", variant="primary", id="btn-ask")
                yield Button("Close (Esc)", variant="default", id="btn-close")

    def on_mount(self) -> None:
        self.query_one("#copilot-input", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-ask":
            self._submit_question()
        else:
            self.dismiss()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit_question()

    def _submit_question(self) -> None:
        q = self.query_one("#copilot-input", Input).value.strip()
        if not q:
            return
        resp_widget = self.query_one("#copilot-response", Static)
        resp_widget.update("⏳ Thinking...")
        self.run_worker(self._ask_worker(q), exclusive=True)

    async def _ask_worker(self, q: str) -> None:
        ans = await aia.advisor.ask_copilot(q, self.active_conns)
        self.query_one("#copilot-response", Static).update(ans)


class HelpModal(ModalScreen):
    """Modal displaying keyboard navigation and shortcuts."""

    CSS = """
    HelpModal {
        align: center middle;
    }
    #help-dialog {
        width: 75;
        height: auto;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #help-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
        text-align: center;
    }
    #help-content {
        margin-bottom: 1;
    }
    #help-buttons {
        align: center middle;
        height: auto;
    }
    """

    def compose(self) -> ComposeResult:
        help_text = (
            "[bold cyan]Navigation & Zero-Trust Shortcuts:[/]\n\n"
            "• [bold white]↑ / ↓ / PgUp / PgDn / Mouse[/] : Scroll & navigate connections\n"
            "• [bold green]E[/] : [bold green]Explain with AI[/] (Antigravity & Zero-Trust Plain English Breakdown)\n"
            "• [bold cyan]A / Space[/] : [bold cyan]Ask Gort Copilot[/] (Interactive AI security assistant)\n"
            "• [bold yellow]B[/] : Block / Unblock highlighted remote IP (Netfilter iptables)\n"
            "• [bold yellow]I[/] : Ignore / Hide highlighted process or IP\n"
            "• [bold green]/[/] : Search & filter by process, IP, port, host, or protocol\n"
            "• [bold white]Esc[/] : Clear search filter & refocus table\n"
            "• [bold white]1 - 6[/] : Switch tabs (All / Outbound / Inbound / Zero-Trust / Blocked / Ignored)\n"
            "• [bold white]R[/] : Reload saved config\n"
            "• [bold white]H / ?[/] : Open this Help dialog\n"
            "• [bold red]Q / Ctrl+C[/] : Quit Gort Firewall cleanly\n"
        )
        with Vertical(id="help-dialog"):
            yield Label("🤖 Gort Firewall Keyboard Shortcuts", id="help-title")
            yield Static(help_text, id="help-content")
            with Horizontal(id="help-buttons"):
                yield Button("Close (Esc)", variant="primary", id="btn-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def on_key(self, event) -> None:
        if event.key in ("escape", "enter", "q"):
            self.dismiss()


# --- Main Application ---

class GortFirewallApp(App):
    """Main Textual Application for Gort Firewall."""

    TITLE = "GORT - Autonomous Linux Firewall & Network Inspector"
    SUB_TITLE = "Zero-Trust Packet Filtering & Antigravity AI Engine (\"Klaatu barada nikto\")"

    CSS = """
    Screen {
        background: $background;
        layout: vertical;
    }

    #metrics-bar {
        height: 1;
        background: $surface-darken-1;
        color: $text-muted;
        padding: 0 1;
    }

    #filter-container {
        height: 3;
        layout: horizontal;
        padding: 0 1;
        margin-top: 1;
    }

    #search-input {
        width: 1fr;
        height: 3;
        border: tall $accent;
    }

    #search-input:focus {
        border: tall $primary;
    }

    #tabs-bar {
        height: 3;
        dock: top;
        background: $surface;
    }

    #table-container {
        height: 1fr;
        padding: 0 1;
    }

    DataTable {
        height: 1fr;
        border: round $primary;
        scrollbar-gutter: stable;
    }

    DataTable > .datatable--cursor {
        background: $accent-darken-2;
        color: $text;
        text-style: bold;
    }

    #detail-panel {
        height: 8;
        border: round $accent;
        background: $surface;
        padding: 0 1;
        margin: 0 1 1 1;
    }

    #detail-header {
        text-style: bold;
        color: $accent;
        height: 1;
    }

    #detail-body {
        height: 5;
        overflow-y: auto;
    }

    .stat-badge {
        text-style: bold;
        color: $primary;
    }
    """

    BINDINGS = [
        Binding("q", "quit_app", "Quit", priority=True),
        Binding("e", "explain_ai", "Explain (AI)", show=True),
        Binding("a", "ask_copilot", "Ask Copilot", show=True),
        Binding("space", "ask_copilot", "Ask Copilot", show=False),
        Binding("b", "block", "Block IP", show=True),
        Binding("i", "ignore", "Ignore Process", show=True),
        Binding("slash", "search", "Search / Filter", show=True),
        Binding("escape", "clear_filter", "Clear Filter", show=True),
        Binding("1", "tab_all", "All Conns", show=False),
        Binding("2", "tab_out", "Outbound", show=False),
        Binding("3", "tab_in", "Inbound", show=False),
        Binding("4", "tab_zt", "Zero-Trust", show=False),
        Binding("5", "tab_blocked", "Blocked", show=False),
        Binding("6", "tab_ignored", "Ignored", show=False),
        Binding("r", "reload", "Reload Config", show=True),
        Binding("h", "help", "Help", show=True),
        Binding("question_mark", "help", "Help", show=False),
    ]

    filter_query = reactive("")
    active_tab = reactive("tab-all")
    selected_conn = reactive(None)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="metrics-bar")
        yield Tabs(
            Tab("All Connections", id="tab-all"),
            Tab("Outbound Only", id="tab-out"),
            Tab("Inbound Only", id="tab-in"),
            Tab("Zero-Trust Alerts", id="tab-zt"),
            Tab("Blocked Rules", id="tab-blocked"),
            Tab("Ignored Rules", id="tab-ignored"),
            id="tabs-bar"
        )
        with Horizontal(id="filter-container"):
            yield Input(
                placeholder="🔍 Filter by process, IP, port, host, protocol... (Press '/' to focus, 'Esc' to clear)",
                id="search-input"
            )
        with Vertical(id="table-container"):
            yield DataTable(id="conns-table", cursor_type="row", zebra_stripes=True)
        with Vertical(id="detail-panel"):
            yield Label("🔎 Selected Connection & Zero-Trust Telemetry Inspector", id="detail-header")
            yield Static("Select a connection row above to inspect detailed telemetry.", id="detail-body")
        yield Footer()

    def on_mount(self) -> None:
        # Initialize table columns
        table = self.query_one("#conns-table", DataTable)
        table.add_column("#", key="idx", width=4)
        table.add_column("Zero-Trust", key="zt_risk", width=16)
        table.add_column("Proto", key="proto", width=6)
        table.add_column("Dir", key="dir", width=5)
        table.add_column("Process", key="proc", width=20)
        table.add_column("PID", key="pid", width=7)
        table.add_column("Remote Endpoint", key="remote", width=22)
        table.add_column("Geo / Hostname", key="geo", width=26)
        table.add_column("Duration", key="duration", width=9)
        table.add_column("Pkts ↑", key="pkts_tx", width=7)
        table.add_column("Pkts ↓", key="pkts_rx", width=7)
        table.add_column("Status", key="status", width=10)

        # Start periodic UI update (every 0.5s)
        self.set_interval(0.5, self.refresh_dashboard)
        table.focus()

    def get_filtered_connections(self):
        """Filters connections according to active tab and search query."""
        all_conns = list(core.connections_cache)
        filtered = []

        q = self.filter_query.strip().lower()

        for c in all_conns:
            ip = c.get("remote_ip", "")
            name = c.get("name", "Unknown")

            # Check if ignored
            is_ignored = (
                ip in core.ignored_ips
                or name in core.ignored_names
                or any(
                    (lambda: (True if ipaddress.ip_address(ip) in net else False)())()
                    for net in core.ignored_cidrs
                    if not core.is_local_ip(ip)
                )
            )

            is_blocked = ip in core.blocked_ips
            direction = c.get("direction", "OUTBOUND")

            # Tab filtering
            if self.active_tab == "tab-all":
                if core.is_local_ip(ip) and not is_blocked:
                    continue
                if is_ignored:
                    continue
            elif self.active_tab == "tab-out":
                if direction != "OUTBOUND" or is_ignored or (core.is_local_ip(ip) and not is_blocked):
                    continue
            elif self.active_tab == "tab-in":
                if direction != "INBOUND" or is_ignored or (core.is_local_ip(ip) and not is_blocked):
                    continue
            elif self.active_tab == "tab-zt":
                if is_ignored or (core.is_local_ip(ip) and not is_blocked):
                    continue
                zt = zte.evaluate_zero_trust(c)
                if zt["score"] >= 80 and not zt["anomalies"]:
                    continue  # Only show flagged / unverified connections
            elif self.active_tab == "tab-blocked":
                if not is_blocked:
                    continue
            elif self.active_tab == "tab-ignored":
                if not is_ignored:
                    continue

            # Query filtering
            if q:
                proto = c.get("protocol", "").lower()
                pid = str(c.get("pid", "")).lower()
                port = str(c.get("remote_port", "")).lower()
                geo = core.geo_cache.get(ip, c.get("geo", "")).lower()
                host = core.rdns_cache.get(ip, "").lower()
                target_str = f"{proto} {direction.lower()} {name.lower()} {pid} {ip} {port} {geo} {host}"
                if q not in target_str:
                    continue

            filtered.append(c)

        return filtered

    def refresh_dashboard(self) -> None:
        """Periodic sync of network stats, connections table, and detail panel."""
        # 1. Update Metrics Bar
        rx_str = fmt_bytes_rate(core.global_rx)
        tx_str = fmt_bytes_rate(core.global_tx)
        active_count = sum(1 for c in core.connections_cache if c.get("status") == "ACTIVE")
        inactive_count = sum(1 for c in core.connections_cache if c.get("status") == "INACTIVE")
        blocked_count = len(core.blocked_ips)
        ignored_count = len(core.ignored_ips) + len(core.ignored_names) + len(core.ignored_cidrs)

        mock_str = " [bold red](MOCK MODE)[/]" if core.is_mock_mode() else " [bold green](FIREWALL ACTIVE)[/]"
        ai_str = " [bold magenta]🤖 AI: ACTIVE[/]" if aia.HAS_ANTIGRAVITY_SDK else " [dim]🤖 AI: HEURISTIC[/]"

        metrics_text = (
            f" ⚡ [bold cyan]Bandwidth:[/] Rx: [green]{rx_str}[/] | Tx: [yellow]{tx_str}[/]  "
            f"│  📊 [bold cyan]Connections:[/] [white]{active_count}[/] active, [dim]{inactive_count}[/] inactive  "
            f"│  🛡️ [bold red]{blocked_count}[/] blocked, [bold yellow]{ignored_count}[/] ignored"
            f"{mock_str}{ai_str}"
        )
        self.query_one("#metrics-bar", Static).update(metrics_text)

        # 2. Update Table Rows
        conns = self.get_filtered_connections()
        table = self.query_one("#conns-table", DataTable)

        now = time.time()
        current_keys = set()
        selected_key = None

        if table.cursor_row is not None and table.row_count > 0:
            try:
                selected_key = list(table.rows.keys())[table.cursor_row]
            except IndexError:
                pass

        for i, c in enumerate(conns):
            proto = c.get("protocol", "TCP")
            local_ip = c.get("local_ip", "0.0.0.0")
            local_port = c.get("local_port", 0)
            remote_ip = c.get("remote_ip", "")
            remote_port = c.get("remote_port", 0)
            row_key = f"{proto}_{local_ip}_{local_port}_{remote_ip}_{remote_port}"
            current_keys.add(row_key)

            dir_val = c.get("direction", "OUTBOUND")
            dir_text = Text("IN", style="bold green") if dir_val == "INBOUND" else Text("OUT", style="bold blue")

            pid_str = str(c["pid"]) if c.get("pid") else "?"
            is_blocked = remote_ip in core.blocked_ips

            # Zero-Trust Evaluation
            zt = zte.evaluate_zero_trust(c)
            zt_badge_text = Text.from_markup(zt["badge"])

            if is_blocked:
                proc_text = Text(f"{c['name']} [BLKD]", style="bold strike red")
                remote_disp = Text(f"{remote_ip}:{remote_port}", style="bold red")
                status_text = Text("BLOCKED", style="bold red")
            elif c.get("status") == "INACTIVE":
                proc_text = Text(c['name'], style="dim")
                remote_disp = Text(f"{remote_ip}:{remote_port}", style="dim")
                status_text = Text("CLOSED", style="dim italic")
            else:
                proc_text = Text(c['name'], style="green")
                remote_disp = Text(f"{remote_ip}:{remote_port}", style="white")
                status_text = Text("ESTABLISHED", style="bold green")

            geo = core.geo_cache.get(remote_ip, c.get("geo", ""))
            hostname = core.rdns_cache.get(remote_ip, "")
            geo_disp = f"{geo} ({hostname})" if hostname else geo

            duration_str = fmt_duration(c.get("first_seen", now))
            pkts_tx_str = fmt_pkts(c.get("packets_tx"))
            pkts_rx_str = fmt_pkts(c.get("packets_rx"))

            row_data = [
                str(i + 1),
                zt_badge_text,
                proto,
                dir_text,
                proc_text,
                pid_str,
                remote_disp,
                geo_disp,
                duration_str,
                pkts_tx_str,
                pkts_rx_str,
                status_text
            ]

            if row_key in table.rows:
                for col_k, cell_v in zip(["idx", "zt_risk", "proto", "dir", "proc", "pid", "remote", "geo", "duration", "pkts_tx", "pkts_rx", "status"], row_data):
                    table.update_cell(row_key, col_k, cell_v)
            else:
                table.add_row(*row_data, key=row_key)

        # Remove stale rows
        existing_keys = set(table.rows.keys())
        for old_k in existing_keys - current_keys:
            table.remove_row(old_k)

        # Update detail view for the highlighted row
        self._update_detail_view(conns, table)

    def _update_detail_view(self, conns, table: DataTable) -> None:
        """Renders rich details about the selected connection."""
        detail_static = self.query_one("#detail-body", Static)

        if not conns or table.cursor_row is None or table.cursor_row >= len(conns):
            detail_static.update("[dim]No connection selected or feed is empty. Use ↑/↓ to browse.[/]")
            self.selected_conn = None
            return

        conn = conns[table.cursor_row]
        self.selected_conn = conn

        pid = conn.get("pid")
        proc_name = conn.get("name", "Unknown")
        remote_ip = conn.get("remote_ip", "")
        remote_port = conn.get("remote_port", 0)
        local_ip = conn.get("local_ip", "")
        local_port = conn.get("local_port", 0)
        proto = conn.get("protocol", "TCP")
        direction = conn.get("direction", "OUTBOUND")
        inode = conn.get("inode", "N/A")

        is_blocked = remote_ip in core.blocked_ips
        block_status = "[bold red]BLOCKED[/]" if is_blocked else "[bold green]ALLOWED[/]"

        geo = core.geo_cache.get(remote_ip, conn.get("geo", "Unknown"))
        hostname = core.rdns_cache.get(remote_ip, "N/A")

        # Process metadata
        exe_path = "N/A"
        cmdline = "N/A"
        user = "N/A"
        if pid:
            try:
                pinfo = get_detailed_process_info(pid)
                exe_path = pinfo.get("exe", "N/A")
                cmdline = pinfo.get("cmdline", "N/A")
                user = pinfo.get("username", "N/A")
            except Exception:
                pass

        # Zero-Trust Evaluation
        zt = zte.evaluate_zero_trust(conn)
        anom_str = f" │ [bold yellow]Anomalies:[/] {', '.join(zt['anomalies'])}" if zt["anomalies"] else ""

        pkts_tx = fmt_pkts(conn.get("packets_tx"))
        pkts_rx = fmt_pkts(conn.get("packets_rx"))
        bytes_tx = core.format_bytes(conn.get("bytes_tx"))
        bytes_rx = core.format_bytes(conn.get("bytes_rx"))
        duration = fmt_duration(conn.get("first_seen", time.time()))

        detail_markup = (
            f"[bold cyan]Process:[/] [green]{proc_name}[/] (PID: [yellow]{pid or '?'}[/], User: [magenta]{user}[/])  "
            f"│  [bold cyan]Trust:[/] {zt['badge']} ({zt['zone_desc']}){anom_str}\n"
            f"[bold cyan]Firewall:[/] {block_status}  │  [bold cyan]Duration:[/] [white]{duration}[/]  │  "
            f"[bold cyan]Socket:[/] [bold blue]{proto}[/] {direction}  │  "
            f"Local: [white]{local_ip}:{local_port}[/] ➔ Remote: [bold yellow]{remote_ip}:{remote_port}[/] (Inode: {inode})\n"
            f"[bold cyan]Host/Geo:[/] [magenta]{geo}[/] │ rDNS: [white]{hostname}[/]  │  "
            f"[bold cyan]Traffic:[/] Tx: [green]{bytes_tx}[/] ({pkts_tx} pkts) | Rx: [yellow]{bytes_rx}[/] ({pkts_rx} pkts)\n"
            f"[bold cyan]Binary:[/] [dim]{exe_path}[/]\n"
            f"[bold cyan]Command:[/] [dim]{cmdline}[/]"
        )

        detail_static.update(detail_markup)

    # --- Event Handlers & Actions ---

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        self.active_tab = event.tab.id
        table = self.query_one("#conns-table", DataTable)
        table.clear()
        self.refresh_dashboard()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self.filter_query = event.value
            table = self.query_one("#conns-table", DataTable)
            table.clear()
            self.refresh_dashboard()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        conns = self.get_filtered_connections()
        table = self.query_one("#conns-table", DataTable)
        self._update_detail_view(conns, table)

    def action_search(self) -> None:
        """Focus the search input bar."""
        self.query_one("#search-input", Input).focus()

    def action_clear_filter(self) -> None:
        """Clear the filter input or refocus table."""
        search_input = self.query_one("#search-input", Input)
        if search_input.has_focus:
            search_input.value = ""
            self.filter_query = ""
            self.query_one("#conns-table", DataTable).focus()
        else:
            if self.filter_query:
                search_input.value = ""
                self.filter_query = ""
            self.query_one("#conns-table", DataTable).focus()

    def action_tab_all(self) -> None:
        self.query_one("#tabs-bar", Tabs).active = "tab-all"

    def action_tab_out(self) -> None:
        self.query_one("#tabs-bar", Tabs).active = "tab-out"

    def action_tab_in(self) -> None:
        self.query_one("#tabs-bar", Tabs).active = "tab-in"

    def action_tab_zt(self) -> None:
        self.query_one("#tabs-bar", Tabs).active = "tab-zt"

    def action_tab_blocked(self) -> None:
        self.query_one("#tabs-bar", Tabs).active = "tab-blocked"

    def action_tab_ignored(self) -> None:
        self.query_one("#tabs-bar", Tabs).active = "tab-ignored"

    def action_explain_ai(self) -> None:
        """Opens AI Explain modal for highlighted connection."""
        if not self.selected_conn:
            self.notify("Please select a connection row to explain.", title="Gort AI", severity="warning")
            return
        self.push_screen(ExplainModal(self.selected_conn))

    def action_ask_copilot(self) -> None:
        """Opens interactive Ask Copilot dialog."""
        conns = self.get_filtered_connections()
        self.push_screen(CopilotModal(conns))

    def action_block(self) -> None:
        """Prompt or toggle block on selected IP."""
        default_ip = self.selected_conn.get("remote_ip", "") if self.selected_conn else ""
        self.push_screen(BlockModal(default_ip=default_ip))

    def action_ignore(self) -> None:
        """Prompt or toggle ignore on selected process."""
        default_name = self.selected_conn.get("name", "") if self.selected_conn else ""
        self.push_screen(IgnoreModal(default_name=default_name))

    def action_reload(self) -> None:
        """Reload firewall configuration from disk."""
        core.load_config()
        self.refresh_dashboard()
        self.notify("Configuration reloaded from disk.", title="Gort Firewall")

    def action_help(self) -> None:
        """Show keyboard shortcuts and help modal."""
        self.push_screen(HelpModal())

    def action_quit_app(self) -> None:
        """Clean shutdown of background threads and app."""
        core.running = False
        core.stop_events_monitor.set()
        self.exit()


MyFirewallApp = GortFirewallApp


# --- Application Entry Point ---

def main():
    core.load_config()
    core.start_core_threads()
    time.sleep(0.3)

    app = GortFirewallApp()
    try:
        app.run()
    finally:
        core.running = False
        core.stop_events_monitor.set()
        time.sleep(0.2)


if __name__ == "__main__":
    main()
