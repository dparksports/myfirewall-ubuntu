# myfirewall2.py
"""
GORT Firewall - Autonomous Linux Endpoint Defense & Connection Inspector
Textual Application Controller & Data Diffing Engine
"""

import sys
import time
import ipaddress
from threading import Thread

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Header,
    Footer,
    DataTable,
    Input,
    Static,
    Tabs,
    Tab,
    Label,
)
from textual.binding import Binding
from textual.reactive import reactive
from rich.text import Text

import myfirewall_core as core
from process_resolver import get_detailed_process_info
import zero_trust_engine as zte
import ai_advisor as aia
import autonomous_sentinel as autosent
from ui_helpers import fmt_duration, fmt_pkts, fmt_bytes_rate
from ui_modals import BlockModal, IgnoreModal, ExplainModal, CopilotModal, HelpModal, RollbackModal, LoginModal
from auth_manager import auth_manager


class GortFirewallApp(App):
    """Main Textual Application Controller for Gort Firewall."""

    TITLE = "GORT - Autonomous Linux Firewall & Network Inspector"
    SUB_TITLE = "Zero-Trust Packet Filtering & Antigravity AI Engine (Made with ❤️ in California)"

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
        Binding("l", "login_google", "Google Login", show=True),
        Binding("u", "rollback", "Unfreeze / Rollback", show=True),
        Binding("b", "block", "Block IP", show=True),
        Binding("i", "ignore", "Ignore Process", show=True),
        Binding("slash", "search", "Search / Filter", show=True),
        Binding("escape", "clear_filter", "Clear Filter", show=True),
        Binding("1", "tab_all", "All Conns", show=False),
        Binding("2", "tab_out", "Outbound", show=False),
        Binding("3", "tab_in", "Inbound", show=False),
        Binding("4", "tab_zt", "Zero-Trust", show=False),
        Binding("5", "tab_auto", "Auto-Defense", show=False),
        Binding("6", "tab_blocked", "Blocked", show=False),
        Binding("7", "tab_ignored", "Ignored", show=False),
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
            Tab("Auto-Defense Incidents", id="tab-auto"),
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

        autosent.sentinel.start()
        self.set_interval(0.5, self.refresh_dashboard)
        table.focus()

    def get_filtered_connections(self):
        """Filters connections according to active tab and search query."""
        all_conns = list(core.connections_cache)
        filtered = []
        q = self.filter_query.strip().lower()

        # Gather active incident IPs and frozen PIDs for tab-auto
        incident_ips = {inc.network_info.get("remote_ip") for inc in autosent.sentinel.active_incidents}
        frozen_pids = set(autosent.sentinel.frozen_pids.keys())

        for c in all_conns:
            ip = c.get("remote_ip", "")
            name = c.get("name", "Unknown")
            pid = c.get("pid")

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
                    continue
            elif self.active_tab == "tab-auto":
                # Show connections that triggered an autonomous incident or frozen PID
                if not (ip in incident_ips or pid in frozen_pids or ip in autosent.sentinel.temporary_drops):
                    continue
            elif self.active_tab == "tab-blocked":
                if not is_blocked:
                    continue
            elif self.active_tab == "tab-ignored":
                if not is_ignored:
                    continue

            if q:
                proto = c.get("protocol", "").lower()
                pid_str = str(c.get("pid", "")).lower()
                port = str(c.get("remote_port", "")).lower()
                geo = core.geo_cache.get(ip, c.get("geo", "")).lower()
                host = core.rdns_cache.get(ip, "").lower()
                target_str = f"{proto} {direction.lower()} {name.lower()} {pid_str} {ip} {port} {geo} {host}"
                if q not in target_str:
                    continue

            filtered.append(c)

        return filtered

    def refresh_dashboard(self) -> None:
        """Periodic sync of network stats, connections table, and detail panel."""
        rx_str = fmt_bytes_rate(core.global_rx)
        tx_str = fmt_bytes_rate(core.global_tx)
        active_count = sum(1 for c in core.connections_cache if c.get("status") == "ACTIVE")
        inactive_count = sum(1 for c in core.connections_cache if c.get("status") == "INACTIVE")
        blocked_count = len(core.blocked_ips)
        ignored_count = len(core.ignored_ips) + len(core.ignored_names) + len(core.ignored_cidrs)

        # Autonomous Sentinel real-time evaluation
        for c in core.connections_cache:
            if c.get("status") == "ACTIVE":
                autosent.sentinel.evaluate_and_respond(c)

        inc_count = len([i for i in autosent.sentinel.active_incidents if not i.rolled_back])
        frozen_count = len(autosent.sentinel.frozen_pids)
        if inc_count > 0:
            auto_str = f" │ 🛡️ [bold red]Auto-Defense: {inc_count} incidents ({frozen_count} frozen)[/]"
        else:
            auto_str = " │ 🛡️ [bold green]Auto-Defense: Clean (0 incidents)[/]"

        mock_str = " [bold red](MOCK MODE)[/]" if core.is_mock_mode() else " [bold green](FIREWALL ACTIVE)[/]"
        ai_str = " [bold magenta]🤖 AI: ACTIVE[/]" if aia.HAS_ANTIGRAVITY_SDK else " [dim]🤖 AI: HEURISTIC[/]"

        metrics_text = (
            f" ⚡ [bold cyan]Bandwidth:[/] Rx: [green]{rx_str}[/] | Tx: [yellow]{tx_str}[/]  "
            f"│  📊 [bold cyan]Connections:[/] [white]{active_count}[/] active, [dim]{inactive_count}[/] inactive  "
            f"│  🛡️ [bold red]{blocked_count}[/] blocked, [bold yellow]{ignored_count}[/] ignored"
            f"{auto_str}{mock_str}{ai_str}"
        )
        self.query_one("#metrics-bar", Static).update(metrics_text)

        conns = self.get_filtered_connections()
        table = self.query_one("#conns-table", DataTable)

        now = time.time()
        current_keys = set()

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

            pid = c.get("pid")
            pid_str = str(pid) if pid else "?"
            is_blocked = remote_ip in core.blocked_ips
            is_frozen = pid in autosent.sentinel.frozen_pids

            zt = zte.evaluate_zero_trust(c)
            zt_badge_text = Text.from_markup(zt["badge"])

            if is_frozen:
                proc_text = Text(f"{c['name']} [FROZEN]", style="bold orange1")
                remote_disp = Text(f"{remote_ip}:{remote_port}", style="bold orange1")
                status_text = Text("SIGSTOP", style="bold orange1")
            elif is_blocked:
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

        existing_keys = set(table.rows.keys())
        for old_k in existing_keys - current_keys:
            table.remove_row(old_k)

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
        is_frozen = pid in autosent.sentinel.frozen_pids
        if is_frozen:
            block_status = "[bold orange1]FROZEN (SIGSTOP)[/]"
        elif is_blocked:
            block_status = "[bold red]BLOCKED[/]"
        else:
            block_status = "[bold green]ALLOWED[/]"

        geo = core.geo_cache.get(remote_ip, conn.get("geo", "Unknown"))
        hostname = core.rdns_cache.get(remote_ip, "N/A")

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
            f"[bold cyan]Firewall:[/] {block_status}  │  [bold cyan]Duration:[/] [white]{duration}[/]\n"
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
        self.query_one("#search-input", Input).focus()

    def action_clear_filter(self) -> None:
        search_input = self.query_one("#search-input", Input)
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

    def action_tab_auto(self) -> None:
        self.query_one("#tabs-bar", Tabs).active = "tab-auto"

    def action_tab_blocked(self) -> None:
        self.query_one("#tabs-bar", Tabs).active = "tab-blocked"

    def action_tab_ignored(self) -> None:
        self.query_one("#tabs-bar", Tabs).active = "tab-ignored"

    def action_explain_ai(self) -> None:
        if not self.selected_conn:
            self.notify("Please select a connection row to explain.", title="Gort AI", severity="warning")
            return
        self.push_screen(ExplainModal(self.selected_conn))

    def action_ask_copilot(self) -> None:
        conns = self.get_filtered_connections()
        self.push_screen(CopilotModal(conns))

    def action_login_google(self) -> None:
        """Opens modal for Google Account login and API key management."""
        self.push_screen(LoginModal())

    def action_rollback(self) -> None:
        """Opens modal for reviewing and rolling back autonomous incidents."""
        incidents = list(autosent.sentinel.active_incidents)
        selected_inc = None
        if self.selected_conn:
            sel_ip = self.selected_conn.get("remote_ip")
            sel_pid = self.selected_conn.get("pid")
            selected_inc = next((inc for inc in incidents if inc.network_info.get("remote_ip") == sel_ip or inc.process_info.get("pid") == sel_pid), None)
        self.push_screen(RollbackModal(incidents, selected_inc))

    def action_block(self) -> None:
        default_ip = self.selected_conn.get("remote_ip", "") if self.selected_conn else ""
        self.push_screen(BlockModal(default_ip=default_ip))

    def action_ignore(self) -> None:
        default_name = self.selected_conn.get("name", "") if self.selected_conn else ""
        self.push_screen(IgnoreModal(default_name=default_name))

    def action_reload(self) -> None:
        core.load_config()
        self.refresh_dashboard()
        self.notify("Configuration reloaded from disk.", title="Gort Firewall")

    def action_help(self) -> None:
        self.push_screen(HelpModal())

    def action_quit_app(self) -> None:
        core.running = False
        core.stop_events_monitor.set()
        autosent.sentinel.stop()
        self.exit()


MyFirewallApp = GortFirewallApp


# --- Application Entry Point ---

def main():
    if "--login" in sys.argv:
        success = auth_manager.interactive_terminal_login()
        sys.exit(0 if success else 1)

    core.load_config()
    core.start_core_threads()
    time.sleep(0.3)

    app = GortFirewallApp()
    try:
        app.run()
    finally:
        core.running = False
        core.stop_events_monitor.set()
        autosent.sentinel.stop()
        time.sleep(0.2)


if __name__ == "__main__":
    main()
