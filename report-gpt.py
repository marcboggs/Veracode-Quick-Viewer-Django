import xml.etree.ElementTree as ET
import xml.dom.minidom
import requests
import csv
from datetime import datetime, timedelta
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Input, Static, ListView, ListItem, Select, Button, Log
from textual.containers import Container, Horizontal
from textual.scroll_view import ScrollView

from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

NS = {'v': 'https://www.veracode.com/schema/reports/export/1.0'}
BL_NS = {'bl': 'https://analysiscenter.veracode.com/schema/2.0/buildlist'}

API_BASE = "https://api.veracode.com"
LEGACY_API_BASE = "https://analysiscenter.veracode.com/api/5.0"

API_HEADERS = {
    "Authorization": "Bearer YOUR_ACCESS_TOKEN",
    "Accept": "application/json"
}

class VeracodeReportApp(App):
    CSS_PATH = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Veracode Profiles", id="app_title")
        yield Horizontal(
            Container(
                Input(placeholder="Filter apps...", id="app_filter"),
                ListView(id="app_selector")
            ),
            ListView(id="build_selector")
        )
        yield Horizontal(
            Input(placeholder="Filter by severity (e.g., 5)...", id="severity_filter"),
            Input(placeholder="Filter by CWE ID (e.g., 89)...", id="cwe_filter")
        )
        yield Select(options=[
            ("Summary", "summary"),
            ("Static Findings", "static"),
            ("SCA Findings", "sca"),
            ("Raw XML", "rawxml"),
            ("Compliance", "compliance")
        ], id="tab_selector")
        yield ScrollView(Static("Summary will be displayed here.", id="summary_content"), id="summary_tab")
        yield Container(DataTable(id="report_table"), Button("Export Static CSV", id="export_static"), id="static_tab")
        yield Container(DataTable(id="sca_table"), Button("Export SCA CSV", id="export_sca"), id="sca_tab")
        yield ScrollView(Log(id="xml_viewer", highlight=True), id="rawxml_tab")
        yield ScrollView(Static("Compliance status will be displayed here.", id="compliance_content"), id="compliance_tab")
        yield Static(id="flaw_detail")
        yield Footer()

    def on_mount(self):
        self.table = self.query_one("#report_table", DataTable)
        self.table.cursor_type = "row"
        self.table.zebra_stripes = True
        self.table.add_columns("ID", "Severity", "CWE", "Category", "File", "Line", "Function", "Status", "Module", "Grace Period")

        self.sca_table = self.query_one("#sca_table", DataTable)
        self.sca_table.cursor_type = "row"
        self.sca_table.zebra_stripes = True
        self.sca_table.add_columns("Component", "Version", "CPE", "Vendor", "Description")

        self.query_one("#static_tab").display = False
        self.query_one("#sca_tab").display = False
        self.query_one("#rawxml_tab").display = False

        self.flaws = []
        self.sca_components = []
        self.raw_xml = ""
        self.load_applications()

    def load_applications(self):
        try:
            response = requests.get(f"{API_BASE}/appsec/v1/applications?size=1000", auth=RequestsAuthPluginVeracodeHMAC(), headers=API_HEADERS)
            apps = response.json().get("_embedded", {}).get("applications", [])
            self.app_map = {app['profile']['name']: app['id'] for app in apps}
            self.update_app_list()
        except Exception as e:
            self.query_one("#app_title", Static).update(f"Error loading applications: {e}")

    def update_app_list(self):
        app_filter = self.query_one("#app_filter", Input).value.strip().lower()
        app_list = self.query_one("#app_selector", ListView)
        app_list.clear()
        for name in self.app_map:
            if app_filter in name.lower():
                app_list.append(ListItem(Static(name)))

    def handle_app_selection(self, app_name):
        app_id = self.app_map[app_name]
        response = requests.get(f"{LEGACY_API_BASE}/getbuildlist.do?app_id={app_id}", auth=RequestsAuthPluginVeracodeHMAC(), headers=API_HEADERS)
        root = ET.fromstring(response.content)
        builds = root.findall("bl:build", BL_NS)
        self.build_map = {f"{b.get('version')} ({b.get('build_id')})": b.get('build_id') for b in builds}
        build_list = self.query_one("#build_selector", ListView)
        build_list.clear()
        for label in self.build_map:
            build_list.append(ListItem(Static(label)))

    def handle_build_selection(self, build_label):
        build_id = self.build_map[build_label]
        response = requests.get(f"{LEGACY_API_BASE}/detailedreport.do?build_id={build_id}", auth=RequestsAuthPluginVeracodeHMAC(), headers=API_HEADERS)
        self.raw_xml = response.content.decode("utf-8")
        self.flaws, self.sca_components = self.parse_findings_from_xml(self.raw_xml)
        self.load_table(self.flaws)
        self.load_sca_table(self.sca_components)
        self.update_summary()
        self.update_compliance()
        #self.display_raw_xml()

    def load_table(self, flaws):
        self.table.clear()
        for flaw in flaws:
            self.table.add_row(
                flaw["ID"], flaw["Severity"], flaw["CWE"], flaw["Category"],
                flaw["File"], flaw["Line"], flaw["Function"], flaw["Status"],
                flaw["Module"], flaw.get("grace_period_expires", "")
            )

    def load_sca_table(self, components):
        self.sca_table.clear()
        for c in components:
            self.sca_table.add_row(c['Component'], c['Version'], c['CPE'], c['Vendor'], c['Description'])

    def update_summary(self):
        # Summary update code placeholder (previously implemented)
        pass

    def update_compliance(self):
        def parse_date(date_str):
            try:
                return datetime.strptime(date_str, "%Y-%m-%d")
            except:
                return None

        generation_date = None
        try:
            root = ET.fromstring(self.raw_xml.encode("utf-8"))
            generation_date = parse_date(root.get("generation_date"))
        except:
            pass

        now = datetime.utcnow()
        expired = False
        high_or_critical = False
        expired_reasons = []
        severity_reasons = []

        for flaw in self.flaws:
            status = flaw['Status'].lower()
            severity = flaw['Severity']
            grace = parse_date(flaw.get('grace_period_expires', ''))
            if status in ("open", "new", "reopen"):
                if severity in ("4", "5"):
                    high_or_critical = True
                    severity_reasons.append(f"Finding {flaw['ID']} - Severity {severity}")
                if grace and grace < now:
                    expired = True
                    expired_reasons.append(f"Finding {flaw['ID']} expired on {grace.date()}")

        lines = ["📋 Compliance Check"]

        if not generation_date:
            lines.append("❌ Missing or invalid generation_date in XML.")
        elif generation_date < now - timedelta(days=30):
            lines.append(f"❌ Last scan was on {generation_date.date()} (>30 days ago)")
        else:
            lines.append(f"✅ Last scan on {generation_date.date()} (within 30 days)")

        if expired:
            lines.append("\n❌ There are open findings with expired grace periods:")
            lines.extend([f"  - {reason}" for reason in expired_reasons])
        else:
            lines.append("\n✅ No expired open findings.")

        if high_or_critical:
            lines.append("\n❌ Open findings with severity 4 or 5 exist:")
            lines.extend([f"  - {reason}" for reason in severity_reasons])
        else:
            lines.append("\n✅ No open severity 4 or 5 findings.")

        self.query_one("#compliance_content", Static).update("\n".join(lines))

    def display_raw_xml(self):
        formatted = xml.dom.minidom.parseString(self.raw_xml).toprettyxml()
        xml_viewer = self.query_one("#xml_viewer", Log)
        xml_viewer.clear()
        for line in formatted.splitlines():
            if line.strip():
                xml_viewer.write(line)

    def parse_findings_from_xml(self, xml_data):
        try:
            root = ET.fromstring(xml_data.encode("utf-8"))
        except Exception as e:
            print("Failed to parse XML:", e)
            return [], []

        flaws, sca_components = [], []

        for severity in root.findall('.//v:severity', NS):
            severity_level = severity.get('level', 'Unknown')
            for category in severity.findall('v:category', NS):
                category_name = category.get('categoryname', 'Unknown')
                for cwe in category.findall('v:cwe', NS):
                    cwe_id = cwe.get('cweid', 'N/A')
                    cwe_name = cwe.get('cwename', 'Unknown')
                    static_flaws = cwe.find('v:staticflaws', NS)
                    if static_flaws is not None:
                        for flaw in static_flaws.findall('v:flaw', NS):
                            flaws.append({
                                'ID': flaw.get('issueid', ''),
                                'Severity': severity_level,
                                'CWE': f"{cwe_id} - {cwe_name}",
                                'Category': category_name,
                                'File': flaw.get('sourcefile', ''),
                                'Line': flaw.get('line', ''),
                                'Function': flaw.get('functionprototype', ''),
                                'Status': flaw.get('remediation_status', ''),
                                'Module': flaw.get('module', ''),
                                'Description': flaw.get('description', ''),
                                'grace_period_expires': flaw.get('grace_period_expires', '')
                            })

        for comp in root.findall('.//v:software_composition_analysis/v:component', NS):
            sca_components.append({
                'Component': comp.get('component_name', ''),
                'Version': comp.get('version', ''),
                'CPE': comp.get('cpe', ''),
                'Vendor': comp.get('vendor', ''),
                'Description': comp.get('description', '')
            })

        return flaws, sca_components


    def load_table(self, data):
        self.table.clear()
        for flaw in data:
            self.table.add_row(
                flaw["ID"], flaw["Severity"], flaw["CWE"], flaw["Category"],
                flaw["File"], flaw["Line"], flaw["Function"], flaw["Status"],
                flaw["Module"], flaw.get("Grace Period", "")
            )


    def load_sca_table(self, components):
        self.sca_table.clear()
        for comp in components:
            self.sca_table.add_row(
                comp["Component"], comp["Version"], comp["CPE"], comp["Vendor"], comp["Description"]
            )

    def update_summary(self):
        from collections import Counter

        def bar(count, total, width=20):
            proportion = count / total if total else 0
            bars = int(proportion * width)
            return f"{'▇' * bars}{' ' * (width - bars)} {count} ({proportion:.0%})"

        static_open = [f for f in self.flaws if f['Status'].lower() in ("open", "new", "reopen")]
        sca_count = len(self.sca_components)

        sev_counter = Counter(f['Severity'] for f in static_open)
        cwe_counter = Counter(f['CWE'] for f in static_open)
        category_counter = Counter(f['Category'] for f in static_open)
        vendor_counter = Counter(c['Vendor'] for c in self.sca_components if c['Vendor'])

        lines = []
        lines.append("📊 Summary Report")
        total_static = len(static_open)
        lines.append(f"\n\n🔒 Open Static Findings: {total_static}")

        lines.append("\nSeverity Breakdown:")
        for severity, count in sorted(sev_counter.items(), key=lambda x: -int(x[0]) if x[0].isdigit() else 0):
            lines.append(f"\n  - Severity {severity}: {bar(count, total_static)}")

        lines.append("Top CWEs:")
        for cwe, count in cwe_counter.most_common(5):
            lines.append(f"\n  - {cwe}: {bar(count, total_static)}")

        lines.append("Top Categories:")
        for cat, count in category_counter.most_common(5):
            lines.append(f"\n  - {cat}: {bar(count, total_static)}")

        lines.append(f"\n📦 SCA Components Found: {sca_count}")

        lines.append("Top Vendors:")
        for vendor, count in vendor_counter.most_common(5):
            lines.append(f"\n  - {vendor}: {bar(count, sca_count)}")

        self.query_one("#summary_content", Static).update("".join(lines))

    def on_list_view_selected(self, event):
        widget_id = event.control.id
        label_widget = event.item.query_one(Static)
        label = label_widget.renderable
        if not isinstance(label, str):
            label = str(label)

        label = label.strip()

        if widget_id == "app_selector":
            self.handle_app_selection(label)
        elif widget_id == "build_selector":
            if label in self.build_map:
                self.handle_build_selection(label)
            else:
                print(f"[WARN] Selected build label not found: {label}")

    def on_input_changed(self, event: Input.Changed):
        if event.input.id == "app_filter":
            self.update_app_list()
            return

        severity_filter = self.query_one("#severity_filter", Input).value.strip()
        cwe_filter = self.query_one("#cwe_filter", Input).value.strip()
        filtered = self.flaws
        if severity_filter:
            filtered = [f for f in filtered if f['Severity'] == severity_filter]
        if cwe_filter:
            filtered = [f for f in filtered if cwe_filter in f['CWE']]

        # Sort by severity descending, then status alphabetically
        def sort_key(f):
            try:
                sev = int(f['Severity'])
            except ValueError:
                sev = 0
            return (-sev, f['Status'])

        filtered.sort(key=sort_key)
        self.load_table(filtered)

    def on_select_changed(self, event: Select.Changed):
        selected = event.value
        self.query_one("#summary_tab").display = (selected == "summary")
        self.query_one("#static_tab").display = (selected == "static")
        self.query_one("#sca_tab").display = (selected == "sca")
        self.query_one("#rawxml_tab").display = (selected == "rawxml")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "export_static":
            with open("static_findings.csv", "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Severity", "CWE", "Category", "File", "Line", "Function", "Status", "Module"])
                for row in self.flaws:
                    writer.writerow([
                        row["ID"], row["Severity"], row["CWE"], row["Category"],
                        row["File"], row["Line"], row["Function"], row["Status"], row["Module"]
                    ])

        elif event.button.id == "export_sca":
            with open("sca_components.csv", "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Component", "Version", "CPE", "Vendor", "Description"])
                for row in self.sca_components:
                    writer.writerow([
                        row["Component"], row["Version"], row["CPE"], row["Vendor"], row["Description"]
                    ])

if __name__ == "__main__":
    VeracodeReportApp().run()
