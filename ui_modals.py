"""
Interactive Modal Dialogs for Gort Firewall Textual UI.
Encapsulates BlockModal, IgnoreModal, ExplainModal, CopilotModal, and HelpModal.
"""

import ipaddress
from typing import Optional, List, Dict, Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Label, Button, Input, Static
from textual.screen import ModalScreen
from textual.binding import Binding

import myfirewall_core as core
import zero_trust_engine as zte
import ai_advisor as aia
from auth_manager import auth_manager


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

    def __init__(self, conn: Dict[str, Any]):
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

    def __init__(self, active_conns: List[Dict[str, Any]]):
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


class RollbackModal(ModalScreen):
    """Modal for reviewing autonomous incidents and triggering 1-click rollback/unfreeze."""

    CSS = """
    RollbackModal {
        align: center middle;
    }
    #rollback-dialog {
        width: 80;
        height: auto;
        border: thick $warning;
        background: $surface;
        padding: 1 2;
    }
    #rollback-title {
        text-style: bold;
        color: $warning;
        margin-bottom: 1;
        text-align: center;
    }
    #rollback-body {
        margin-bottom: 1;
        height: auto;
        max-height: 12;
        overflow-y: auto;
    }
    #rollback-buttons {
        align: center middle;
        height: auto;
    }
    #rollback-buttons Button {
        margin: 0 1;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
    ]

    def __init__(self, incidents: List[Any], selected_incident: Optional[Any] = None):
        super().__init__()
        self.incidents = incidents
        self.target_incident = selected_incident or (incidents[-1] if incidents else None)

    def compose(self) -> ComposeResult:
        with Vertical(id="rollback-dialog"):
            yield Label("🛡️ Gort Autonomous Defense & Incident Rollback", id="rollback-title")
            if not self.target_incident:
                yield Static("No autonomous incidents recorded yet. System state is clean.", id="rollback-body")
                with Horizontal(id="rollback-buttons"):
                    yield Button("Close (Esc)", variant="default", id="btn-close")
            else:
                inc = self.target_incident
                proc = inc.process_info
                net = inc.network_info
                status_str = "[strike bold red]ROLLED BACK[/]" if inc.rolled_back else "[bold green]ACTIVE INTERVENTION[/]"
                body_text = (
                    f"[bold cyan]Incident ID:[/] {inc.incident_id}  │  [bold cyan]Status:[/] {status_str}\n"
                    f"[bold cyan]Action Tier:[/] [bold red]{inc.action_tier}[/] (Confidence: {inc.confidence_score}%)\n"
                    f"[bold cyan]Threat Type:[/] [yellow]{inc.threat_type}[/]\n"
                    f"[bold cyan]Process:[/] [green]{proc.get('name')}[/] (PID: {proc.get('pid')}, User: {proc.get('user')})\n"
                    f"[bold cyan]Remote:[/] {net.get('remote_ip')}:{net.get('remote_port')}\n"
                    f"[bold cyan]Evidence:[/] {', '.join(inc.evidence)}\n"
                    f"[bold cyan]Actions Taken:[/] {', '.join(inc.actions_taken)}\n\n"
                    f"[bold white]1-Click Rollback will unfreeze process (SIGCONT), remove temporary Netfilter drop, and whitelist IP.[/]"
                )
                yield Static(body_text, id="rollback-body")
                with Horizontal(id="rollback-buttons"):
                    if not inc.rolled_back:
                        yield Button("↩️ Unfreeze & Rollback", variant="warning", id="btn-rollback")
                    yield Button("Close (Esc)", variant="default", id="btn-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-rollback" and self.target_incident:
            import autonomous_sentinel
            autonomous_sentinel.sentinel.rollback_incident(self.target_incident.incident_id)
            self.dismiss(True)
        else:
            self.dismiss(None)


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
            "[bold cyan]Navigation, AI & Autonomous Defense Shortcuts:[/]\n\n"
            "• [bold white]↑ / ↓ / PgUp / PgDn / Mouse[/] : Scroll & navigate connections\n"
            "• [bold green]E[/] : [bold green]Explain with AI[/] (Antigravity & Zero-Trust Plain English Breakdown)\n"
            "• [bold cyan]A / Space[/] : [bold cyan]Ask Gort Copilot[/] (Interactive AI security assistant)\n"
            "• [bold cyan]L[/] : [bold cyan]Google Login[/] (1-Click Browser OAuth Sign-In & API Key Config)\n"
            "• [bold yellow]U[/] : [bold yellow]Unfreeze / Rollback[/] Autonomous Defense Incidents (1-Click Restore)\n"
            "• [bold yellow]B[/] : Block / Unblock highlighted remote IP (Netfilter iptables)\n"
            "• [bold yellow]I[/] : Ignore / Hide highlighted process or IP\n"
            "• [bold green]/[/] : Search & filter by process, IP, port, host, or protocol\n"
            "• [bold white]Esc[/] : Clear search filter & refocus table\n"
            "• [bold white]1 - 7[/] : Switch tabs (All / Outbound / Inbound / Zero-Trust / Auto-Defense / Blocked / Ignored)\n"
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


class LoginModal(ModalScreen):
    """Modal for 1-click Google Account login or manual API key configuration."""

    CSS = """
    LoginModal {
        align: center middle;
    }
    #login-dialog {
        width: 76;
        height: auto;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #login-title {
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
        text-align: center;
    }
    #login-status {
        margin-bottom: 1;
        padding: 1;
        background: $boost;
        border: solid $accent;
    }
    #login-input-box {
        margin-top: 1;
        margin-bottom: 1;
        height: auto;
    }
    #login-buttons {
        align: center middle;
        height: auto;
        margin-top: 1;
    }
    #login-buttons Button {
        margin: 0 1;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        is_auth, auth_desc = auth_manager.is_authenticated()
        status_style = "bold green" if is_auth else "bold yellow"

        status_text = (
            f"• [bold white]Active Status:[/] [{status_style}]{auth_desc}[/]\n"
            f"• [bold cyan]Google Antigravity SDK:[/] {'✅ Installed' if aia.HAS_ANTIGRAVITY_SDK else '⚠️ Standalone Mode'}\n"
            "• Connect your Google account to enable real-time AI security advice!"
        )

        with Vertical(id="login-dialog"):
            yield Label("🌐 Google Gemini AI Configuration", id="login-title")
            yield Static(status_text, id="login-status")
            yield Static("[bold white]Step 1: Get Free Key from Google AI Studio[/]")
            yield Static("Click below to open Google AI Studio in your browser and generate a key with your Google account:")
            with Horizontal(id="login-buttons"):
                yield Button("🌐 Open Google AI Studio Key Page", variant="success", id="btn-open-studio")
            
            yield Static("\n[bold white]Step 2: Paste Gemini API Key[/]", id="login-input-box")
            yield Input(placeholder="Paste AIzaSy... key here", id="login-api-key")
            with Horizontal(id="login-bottom-buttons"):
                yield Button("Save & Test Key", variant="primary", id="btn-save-key")
                yield Button("Close (Esc)", variant="default", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn-open-studio":
            auth_manager.open_browser_safe("https://aistudio.google.com/app/apikey")
            status_widget = self.query_one("#login-status", Static)
            status_widget.update(
                "[bold cyan]🌐 Opened Google AI Studio in your browser![/]\n"
                "[italic text-muted]Sign in with Google, click 'Create API key', then paste it below.[/]"
            )

        elif button_id == "btn-save-key":
            key_val = self.query_one("#login-api-key", Input).value.strip()
            if not key_val:
                self.notify("Please paste your Gemini API key first.", severity="warning")
                return

            status_widget = self.query_one("#login-status", Static)
            status_widget.update("[bold cyan]⏳ Testing key with Google Gemini API...[/]")

            def do_validate():
                valid, msg, best_model, flash_models = auth_manager.validate_api_key(key_val)
                def update_ui():
                    if valid:
                        auth_manager.save_api_key(key_val, active_model=best_model)
                        model_str = f" (Model: {best_model})" if best_model else ""
                        status_widget.update(f"✅ [bold green]{msg}[/]{model_str}\nKey & model saved to ~/.config/myfirewall/config.json")
                        self.notify("Google Gemini AI is now active!", title="Connected", severity="information")
                    else:
                        status_widget.update(f"❌ [bold red]{msg}[/]\nPlease check the key and try again.")
                self.app.call_from_thread(update_ui)

            import threading
            threading.Thread(target=do_validate, daemon=True).start()

        elif button_id == "btn-cancel":
            self.dismiss()

    def action_cancel(self) -> None:
        self.dismiss()

