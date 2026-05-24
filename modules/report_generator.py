"""
Report Generator Module
========================
Generates comprehensive forensic reports in multiple formats
including HTML, JSON, and structured text.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class ForensicReport:
    """Complete forensic report aggregating all analysis modules."""
    report_id: str = ""
    generated_at: str = ""
    device_info: Dict[str, Any] = field(default_factory=dict)
    baseband_info: Dict[str, Any] = field(default_factory=dict)
    security_audit: Dict[str, Any] = field(default_factory=dict)
    current_radio_state: Dict[str, Any] = field(default_factory=dict)
    sim_data: List[Dict[str, Any]] = field(default_factory=list)
    nr_analysis: Dict[str, Any] = field(default_factory=dict)
    cell_tower_map: Dict[str, Any] = field(default_factory=dict)
    signal_timeline: List[Dict] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    event_statistics: Dict[str, Any] = field(default_factory=dict)
    forensic_notes: List[str] = field(default_factory=list)


class ReportGenerator:
    """Generates forensic reports in multiple formats."""

    @staticmethod
    def generate_report_id() -> str:
        """Generate a unique report ID."""
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        return f"BBF-{ts}"

    def compile_report(self, report_id: str,
                        device_info: Any,
                        baseband_info: Any,
                        security_audit: Any,
                        radio_state: Any,
                        sim_info: List[Any],
                        nr_analysis: Any,
                        tower_map: Any,
                        signal_timeline: List[Dict],
                        anomalies: List[str],
                        event_stats: Dict[str, Any]) -> ForensicReport:
        """Compile all analysis modules into a unified forensic report."""
        report = ForensicReport(
            report_id=report_id,
            generated_at=datetime.now().isoformat(),
        )
        
        # Device info
        if hasattr(device_info, '__dataclass_fields__'):
            report.device_info = asdict(device_info)
        else:
            report.device_info = dict(device_info) if device_info else {}
        
        # Baseband info
        if hasattr(baseband_info, '__dataclass_fields__'):
            report.baseband_info = asdict(baseband_info)
        else:
            report.baseband_info = dict(baseband_info) if baseband_info else {}
        
        # Security audit
        if hasattr(security_audit, '__dataclass_fields__'):
            report.security_audit = asdict(security_audit)
        else:
            report.security_audit = dict(security_audit) if security_audit else {}
        
        # Radio state
        if hasattr(radio_state, '__dataclass_fields__'):
            report.current_radio_state = asdict(radio_state)
        else:
            report.current_radio_state = dict(radio_state) if radio_state else {}
        
        # SIM data
        report.sim_data = []
        for sim in (sim_info or []):
            if hasattr(sim, '__dataclass_fields__'):
                report.sim_data.append(asdict(sim))
            else:
                report.sim_data.append(dict(sim) if sim else {})
        
        # NR analysis
        if hasattr(nr_analysis, '__dataclass_fields__'):
            report.nr_analysis = asdict(nr_analysis)
        else:
            report.nr_analysis = dict(nr_analysis) if nr_analysis else {}
        
        # Tower map
        if hasattr(tower_map, '__dataclass_fields__'):
            report.cell_tower_map = asdict(tower_map)
        else:
            report.cell_tower_map = dict(tower_map) if tower_map else {}
        
        # Signal timeline
        report.signal_timeline = signal_timeline or []
        
        # Anomalies
        report.anomalies = anomalies or []
        
        # Event statistics
        report.event_statistics = event_stats or {}
        
        return report

    def to_json(self, report: ForensicReport, pretty: bool = True) -> str:
        """Export report as JSON string."""
        return json.dumps(asdict(report), indent=2 if pretty else None, default=str)

    def to_html(self, report: ForensicReport) -> str:
        """Generate an HTML report."""
        # Create human-readable labels
        risk_colors = {
            "CRITICAL": "#dc3545", "HIGH": "#fd7e14", 
            "MEDIUM": "#ffc107", "LOW": "#28a745",
            "MINIMAL": "#17a2b8", "Unknown": "#6c757d"
        }
        
        risk_level = report.security_audit.get('risk_level', 'Unknown')
        risk_color = risk_colors.get(risk_level, "#6c757d")
        risk_score = report.security_audit.get('risk_score', 0)
        
        # Radio state
        rs = report.current_radio_state
        sims = report.sim_data
        bb = report.baseband_info
        
        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Baseband Forensic Report — {report.report_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0e17; color: #e1e4e8; padding: 20px; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        h1 {{ color: #58a6ff; font-size: 1.8em; margin-bottom: 5px; }}
        h2 {{ color: #79c0ff; font-size: 1.3em; margin: 25px 0 12px; border-bottom: 1px solid #21262d; padding-bottom: 8px; }}
        h3 {{ color: #a5d6ff; font-size: 1.05em; margin: 15px 0 8px; }}
        .header {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .header-meta {{ color: #8b949e; font-size: 0.9em; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }}
        .card-title {{ color: #79c0ff; font-size: 1em; font-weight: 600; margin-bottom: 10px; }}
        .kv {{ display: flex; justify-content: space-between; padding: 4px 0; font-size: 0.9em; border-bottom: 1px solid #21262d; }}
        .kv-key {{ color: #8b949e; }}
        .kv-value {{ color: #c9d1d9; text-align: right; word-break: break-all; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }}
        .risk-badge {{ background: {risk_color}; color: white; }}
        .tech-badge {{ background: #1f6feb; color: white; margin: 2px; }}
        .anomaly-list {{ list-style: none; }}
        .anomaly-list li {{ padding: 6px 10px; margin: 4px 0; background: #1a1f2b; border-left: 3px solid #fd7e14; border-radius: 0 4px 4px 0; font-size: 0.9em; }}
        .anomaly-list li::before {{ content: '⚠ '; color: #fd7e14; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
        th {{ background: #21262d; color: #8b949e; padding: 8px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #21262d; }}
        .signal-excellent {{ color: #28a745; }}
        .signal-good {{ color: #79c0ff; }}
        .signal-fair {{ color: #ffc107; }}
        .signal-poor {{ color: #fd7e14; }}
        .signal-bad {{ color: #dc3545; }}
        .footer {{ margin-top: 30px; color: #484f58; font-size: 0.8em; text-align: center; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>📡 Baseband & Cellular Forensics Report</h1>
        <p class="header-meta">Report ID: {report.report_id} | Generated: {report.generated_at}</p>
        <p class="header-meta">Device: {report.device_info.get('manufacturer', 'N/A')} {report.device_info.get('model', 'N/A')} | Android {report.device_info.get('android_version', 'N/A')}</p>
    </div>
    
    <h2>🔐 Security Posture</h2>
    <div class="grid">
        <div class="card">
            <div class="card-title">Risk Assessment</div>
            <div class="kv"><span class="kv-key">Risk Level</span><span class="kv-value"><span class="badge risk-badge">{risk_level}</span></span></div>
            <div class="kv"><span class="kv-key">Risk Score</span><span class="kv-value">{risk_score}/100</span></div>
            <div class="kv"><span class="kv-key">Root Access</span><span class="kv-value">{report.security_audit.get('root_access_detected', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Bootloader</span><span class="kv-value">{'Unlocked ⚠' if report.security_audit.get('bootloader_unlocked') else 'Locked ✓'}</span></div>
            <div class="kv"><span class="kv-key">SELinux</span><span class="kv-value">{report.security_audit.get('selinux_status', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">DM-Verity</span><span class="kv-value">{report.security_audit.get('dm_verity_status', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Encryption</span><span class="kv-value">{report.security_audit.get('encryption_status', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Security Patch</span><span class="kv-value">{bb.get('security_patch_date', 'N/A')} ({report.security_audit.get('patch_level_days_old', 'N/A')} days old)</span></div>
        </div>
        <div class="card">
            <div class="card-title">Baseband Information</div>
            <div class="kv"><span class="kv-key">Chipset Vendor</span><span class="kv-value">{bb.get('chipset_vendor', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Processor</span><span class="kv-value">{bb.get('baseband_processor', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Firmware</span><span class="kv-value" style="font-size:0.75em;">{bb.get('firmware_version', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">RIL Version</span><span class="kv-value">{bb.get('ril_version', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">HAL Version</span><span class="kv-value">{bb.get('hal_version', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Engineering Build</span><span class="kv-value">{bb.get('is_engineering_build', 'N/A')}</span></div>
        </div>
    </div>
    
    <h2>📶 Current Radio State</h2>
    <div class="grid">
        <div class="card">
            <div class="card-title">Network Connection</div>
            <div class="kv"><span class="kv-key">Technology</span><span class="kv-value"><span class="badge tech-badge">{rs.get('network_type', 'N/A')}</span></span></div>
            <div class="kv"><span class="kv-key">Operator</span><span class="kv-value">{rs.get('operator_name', 'N/A')} (MCC:{rs.get('mcc', 'N/A')} MNC:{rs.get('mnc', 'N/A')})</span></div>
            <div class="kv"><span class="kv-key">Data State</span><span class="kv-value">{rs.get('data_state', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Voice State</span><span class="kv-value">{rs.get('voice_state', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">5G Mode</span><span class="kv-value">{'SA (Standalone)' if rs.get('is_sa') else ('NSA (Non-Standalone)' if rs.get('is_nsa') else 'N/A')}</span></div>
        </div>
        <div class="card">
            <div class="card-title">Signal & Cell Info</div>
            <div class="kv"><span class="kv-key">Signal (dBm)</span><span class="kv-value"><strong class="signal-{'excellent' if rs.get('signal_dbm', -999) >= -85 else 'good' if rs.get('signal_dbm', -999) >= -95 else 'fair' if rs.get('signal_dbm', -999) >= -105 else 'poor'}">{rs.get('signal_dbm', 'N/A')} dBm</strong></span></div>
            <div class="kv"><span class="kv-key">ASU</span><span class="kv-value">{rs.get('signal_asu', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Band</span><span class="kv-value">{rs.get('band', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">ARFCN</span><span class="kv-value">{rs.get('arfcn', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">NR-ARFCN</span><span class="kv-value">{rs.get('nr_arfcn', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">PCI</span><span class="kv-value">{rs.get('pci', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">TAC</span><span class="kv-value">{rs.get('lac_tac', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Cell ID</span><span class="kv-value">{rs.get('cell_id', 'N/A')}</span></div>
        </div>
    </div>
    
    <h2>💳 SIM Card Analysis</h2>
"""
        for i, sim in enumerate(sims):
            html += f"""
    <div class="card" style="margin-bottom:10px;">
        <div class="card-title">SIM Slot {i+1}</div>
        <div class="grid">
            <div>
                <div class="kv"><span class="kv-key">ICCID</span><span class="kv-value">{sim.get('iccid', 'N/A')}</span></div>
                <div class="kv"><span class="kv-key">IMSI</span><span class="kv-value">{sim.get('imsi', 'N/A')}</span></div>
                <div class="kv"><span class="kv-key">MCC/MNC</span><span class="kv-value">{sim.get('mcc', 'N/A')}/{sim.get('mnc', 'N/A')}</span></div>
                <div class="kv"><span class="kv-key">Country</span><span class="kv-value">{sim.get('operator_country', 'N/A')}</span></div>
            </div>
            <div>
                <div class="kv"><span class="kv-key">Operator</span><span class="kv-value">{sim.get('operator_name', 'N/A')}</span></div>
                <div class="kv"><span class="kv-key">Type</span><span class="kv-value">{sim.get('sim_type', 'N/A')}</span></div>
                <div class="kv"><span class="kv-key">State</span><span class="kv-value">{sim.get('sim_state', 'N/A')}</span></div>
                <div class="kv"><span class="kv-key">Roaming</span><span class="kv-value">{sim.get('is_roaming', 'N/A')}</span></div>
            </div>
        </div>
    </div>"""
        
        html += """
    <h2>🔍 Detected Anomalies</h2>
    <div class="card">
"""
        if report.anomalies:
            html += '<ul class="anomaly-list">'
            for a in report.anomalies:
                html += f'<li>{a}</li>'
            html += '</ul>'
        else:
            html += '<p style="color:#8b949e;">No significant anomalies detected.</p>'
        
        html += """
    </div>
    
    <h2>📡 5G NR Analysis</h2>
    <div class="grid">
        <div class="card">
            <div class="card-title">5G Status</div>
"""
        nr = report.nr_analysis
        html += f"""
            <div class="kv"><span class="kv-key">NSA Active</span><span class="kv-value">{nr.get('is_nsa_active', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">SA Active</span><span class="kv-value">{nr.get('is_sa_active', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">EN-DC Supported</span><span class="kv-value">{nr.get('endc_supported', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">NR Bands</span><span class="kv-value">{nr.get('detected_bands', [])}</span></div>
"""
        
        serving = nr.get('serving_cell') or {}
        if serving:
            html += f"""
        </div>
        <div class="card">
            <div class="card-title">Serving NR Cell</div>
            <div class="kv"><span class="kv-key">NR-ARFCN</span><span class="kv-value">{serving.get('nr_arfcn', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">PCI</span><span class="kv-value">{serving.get('pci', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Band</span><span class="kv-value">n{serving.get('band', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">SCS</span><span class="kv-value">{serving.get('scs', 'N/A')} kHz</span></div>
            <div class="kv"><span class="kv-key">Bandwidth</span><span class="kv-value">{serving.get('bandwidth', 'N/A')} MHz</span></div>
            <div class="kv"><span class="kv-key">SS-RSRP</span><span class="kv-value">{serving.get('ss_rsrp', 'N/A')} dBm</span></div>
            <div class="kv"><span class="kv-key">Mode</span><span class="kv-value">{serving.get('connection_mode', 'N/A')}</span></div>
        </div>"""
        
        throughput = nr.get('throughput_estimation') or {}
        if throughput:
            html += f"""
        <div class="card">
            <div class="card-title">Estimated Throughput</div>
            <div class="kv"><span class="kv-key">DL Max</span><span class="kv-value">{throughput.get('estimated_dl_mbps', 'N/A')} Mbps</span></div>
            <div class="kv"><span class="kv-key">UL Max</span><span class="kv-value">{throughput.get('estimated_ul_mbps', 'N/A')} Mbps</span></div>
            <div class="kv"><span class="kv-key">PRBs</span><span class="kv-value">{throughput.get('num_prbs', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Layers</span><span class="kv-value">{throughput.get('num_layers_dl', 'N/A')}</span></div>
            <div class="kv"><span class="kv-key">Note</span><span class="kv-value" style="font-size:0.75em;">{throughput.get('note', '')}</span></div>
        </div>"""
        
        html += """
    </div>
    
    <h2>🗼 Cell Tower Map</h2>
"""
        towers = report.cell_tower_map
        html += f"""
    <div class="grid">
        <div class="card">
            <div class="card-title">Tower Statistics</div>
            <div class="kv"><span class="kv-key">Total Towers</span><span class="kv-value">{towers.get('total_towers', 0)}</span></div>
            <div class="kv"><span class="kv-key">Unique Cells</span><span class="kv-value">{towers.get('unique_cells', 0)}</span></div>
            <div class="kv"><span class="kv-key">Technologies</span><span class="kv-value">{', '.join(towers.get('technologies_detected', ['N/A']))}</span></div>
            <div class="kv"><span class="kv-key">Est. Coverage Area</span><span class="kv-value">{towers.get('coverage_area_km2', 0):.2f} km²</span></div>
        </div>
    </div>
"""
        
        # Tower list
        tower_list = towers.get('towers', [])
        if tower_list:
            html += """
    <div class="card" style="margin-top:10px;">
        <div class="card-title">Detected Towers</div>
        <table>
            <tr><th>MCC</th><th>MNC</th><th>LAC/TAC</th><th>Cell ID</th><th>PCI</th><th>Tech</th><th>Band</th><th>Signal</th><th>Service</th><th>Obs.</th></tr>
"""
            for t in tower_list[:50]:  # Limit to 50
                sig = t.get('signal_dbm', 0)
                sig_class = 'excellent' if sig >= -85 else 'good' if sig >= -95 else 'fair' if sig >= -105 else 'poor' if sig >= -120 else 'bad'
                html += f"""
            <tr>
                <td>{t.get('mcc', '-')}</td>
                <td>{t.get('mnc', '-')}</td>
                <td>{t.get('lac', '-')}</td>
                <td>{t.get('cell_id', '-')}</td>
                <td>{t.get('pci', '-')}</td>
                <td>{t.get('technology', '-')}</td>
                <td>{t.get('band', '-')}</td>
                <td class="signal-{sig_class}">{sig} dBm</td>
                <td>{'✓' if t.get('is_serving') else ''}</td>
                <td>{t.get('observation_count', 0)}</td>
            </tr>"""
            html += """
        </table>
    </div>"""
        
        html += f"""
    <div class="footer">
        <p>Baseband & Cellular Forensics Report</p>
        <p>This report is for authorized forensic analysis purposes only.</p>
    </div>
</div>
</body>
</html>"""
        
        return html


    def to_pdf(self, report: ForensicReport) -> bytes:
        """Generate a PDF report and return as bytes."""
        from fpdf import FPDF
        
        def s(text):
            """Sanitize text for Latin-1 PDF compatibility."""
            if text is None:
                return ""
            if isinstance(text, (int, float, bool)):
                text = str(text)
            if not isinstance(text, str):
                text = str(text) if text else ""
            # Remove all non-Latin-1 characters aggressively
            result = []
            for ch in text:
                try:
                    ch.encode("latin-1")
                    result.append(ch)
                except UnicodeEncodeError:
                    result.append("?")
            return "".join(result)
        
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # --- Title ---
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(30, 64, 175)
        pdf.cell(0, 12, s("Baseband & Cellular Forensics Report"), ln=True, align="C")
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(100, 100, 100)
        rid = s(report.report_id)
        gen = s(report.generated_at)
        pdf.cell(0, 6, s(f"Report ID: {rid}  |  Generated: {gen}"), ln=True, align="C")
        di = report.device_info
        pdf.cell(0, 6, s(f"Device: {di.get('manufacturer','?')} {di.get('model','?')}  |  Android {di.get('android_version','?')}"), ln=True, align="C")
        pdf.ln(6)
        
        # --- Security ---
        sa = report.security_audit
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(20, 20, 20)
        pdf.set_fill_color(240, 245, 255)
        pdf.cell(0, 10, s("1. Security Posture"), ln=True, fill=True)
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 6, s(f"Risk Level: {sa.get('risk_level','N/A')}  |  Score: {sa.get('risk_score',0)}/100"), ln=True)
        pdf.cell(0, 6, s(f"Root: {sa.get('root_access_detected','?')}  |  Bootloader: {'Unlocked' if sa.get('bootloader_unlocked') else 'Locked'}"), ln=True)
        pdf.cell(0, 6, s(f"SELinux: {sa.get('selinux_status','?')}  |  DM-Verity: {sa.get('dm_verity_status','?')}"), ln=True)
        pdf.cell(0, 6, s(f"Encryption: {sa.get('encryption_status','?')}  |  Patch age: {sa.get('patch_level_days_old','?')} days"), ln=True)
        pdf.ln(4)
        
        if sa.get("dangerous_services"):
            pdf.set_text_color(180, 50, 50)
            pdf.cell(0, 6, s(f"Dangerous services: {', '.join(sa['dangerous_services'])}"), ln=True)
        if sa.get("exposed_interfaces"):
            pdf.cell(0, 6, s(f"Exposed interfaces: {', '.join(sa['exposed_interfaces'])}"), ln=True)
        pdf.ln(4)
        
        # --- Baseband ---
        bb = report.baseband_info
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(20, 20, 20)
        pdf.set_fill_color(240, 245, 255)
        pdf.cell(0, 10, s("2. Baseband Information"), ln=True, fill=True)
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 6, s(f"Vendor: {bb.get('chipset_vendor','?')}  |  Processor: {bb.get('baseband_processor','?')}"), ln=True)
        fw = s(bb.get('firmware_version','?') or '')[:80]
        pdf.cell(0, 6, s(f"Firmware: {fw}"), ln=True)
        pdf.cell(0, 6, s(f"RIL: {bb.get('ril_version','?')}  |  HAL: {bb.get('hal_version','?')}"), ln=True)
        pdf.cell(0, 6, s(f"Security Patch: {bb.get('security_patch_date','?')}"), ln=True)
        techs = ', '.join(bb.get('supported_technologies',[])) or 'N/A'
        pdf.cell(0, 6, s(f"Technologies: {techs}"), ln=True)
        pdf.cell(0, 6, s(f"VoLTE: {bb.get('volte_supported','?')}  |  VoWiFi: {bb.get('vowifi_supported','?')}"), ln=True)
        pdf.cell(0, 6, s(f"5G NSA: {bb.get('nr_nsa_supported','?')}  |  5G SA: {bb.get('nr_sa_supported','?')}"), ln=True)
        pdf.ln(4)
        
        # --- Radio State ---
        rs = report.current_radio_state
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(20, 20, 20)
        pdf.set_fill_color(240, 245, 255)
        pdf.cell(0, 10, s("3. Current Radio State"), ln=True, fill=True)
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 6, s(f"Network: {rs.get('network_type','?')}  |  Technology: {rs.get('radio_technology','?')}"), ln=True)
        pdf.cell(0, 6, s(f"Operator: {rs.get('operator_name','?')}  |  MCC: {rs.get('mcc','?')}  MNC: {rs.get('mnc','?')}"), ln=True)
        pdf.cell(0, 6, s(f"Signal: {rs.get('signal_dbm','?')} dBm  |  ASU: {rs.get('signal_asu','?')}"), ln=True)
        pdf.cell(0, 6, s(f"Band: {rs.get('band','?')}  |  ARFCN: {rs.get('arfcn','?')}  |  NR-ARFCN: {rs.get('nr_arfcn','?')}"), ln=True)
        pdf.cell(0, 6, s(f"TAC: {rs.get('lac_tac','?')}  |  Cell ID: {rs.get('cell_id','?')}  |  PCI: {rs.get('pci','?')}"), ln=True)
        mode_5g = 'SA' if rs.get('is_sa') else ('NSA' if rs.get('is_nsa') else 'N/A')
        pdf.cell(0, 6, s(f"5G Mode: {mode_5g}"), ln=True)
        pdf.ln(4)
        
        # --- SIM Cards ---
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(20, 20, 20)
        pdf.set_fill_color(240, 245, 255)
        pdf.cell(0, 10, s("4. SIM Card Analysis"), ln=True, fill=True)
        pdf.ln(2)
        
        for i, sim in enumerate(report.sim_data):
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 7, s(f"SIM Slot {i+1}"), ln=True)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(50, 50, 50)
            pdf.cell(0, 6, s(f"ICCID: {sim.get('iccid','?')}  |  IMSI: {sim.get('imsi','?')}"), ln=True)
            pdf.cell(0, 6, s(f"Operator: {sim.get('operator_name','?')}  |  Country: {sim.get('operator_country','?')}"), ln=True)
            pdf.cell(0, 6, s(f"Type: {sim.get('sim_type','?')}  |  Roaming: {sim.get('is_roaming','?')}"), ln=True)
            pdf.ln(2)
        pdf.ln(2)
        
        # --- 5G NR ---
        nr = report.nr_analysis
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(20, 20, 20)
        pdf.set_fill_color(240, 245, 255)
        pdf.cell(0, 10, s("5. 5G NR Analysis"), ln=True, fill=True)
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 6, s(f"NSA Active: {nr.get('is_nsa_active','?')}  |  SA Active: {nr.get('is_sa_active','?')}"), ln=True)
        bands = str(nr.get('detected_bands',[]))
        pdf.cell(0, 6, s(f"EN-DC: {nr.get('endc_supported','?')}  |  Bands: {bands}"), ln=True)
        
        serving = nr.get("serving_cell") or {}
        if serving:
            pdf.cell(0, 6, s(f"Serving NR: PCI={serving.get('pci','?')}  n{serving.get('band','?')}  SCS={serving.get('scs','?')}kHz  BW={serving.get('bandwidth','?')}MHz"), ln=True)
            pdf.cell(0, 6, s(f"SS-RSRP: {serving.get('ss_rsrp','?')} dBm  |  Mode: {serving.get('connection_mode','?')}"), ln=True)
        
        tp = nr.get("throughput_estimation") or {}
        if tp:
            pdf.cell(0, 6, s(f"Est. DL: {tp.get('estimated_dl_mbps','?')} Mbps  |  UL: {tp.get('estimated_ul_mbps','?')} Mbps"), ln=True)
        pdf.ln(4)
        
        # --- Anomalies ---
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(20, 20, 20)
        pdf.set_fill_color(240, 245, 255)
        pdf.cell(0, 10, s("6. Detected Anomalies"), ln=True, fill=True)
        pdf.ln(2)
        
        if report.anomalies:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(180, 50, 50)
            for a in report.anomalies:
                pdf.multi_cell(180, 6, s(f"[!] {a}"))
        else:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(50, 150, 50)
            pdf.cell(0, 6, s("No significant anomalies detected."), ln=True)
        pdf.ln(4)
        
        # --- Cell Towers ---
        towers = report.cell_tower_map
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(20, 20, 20)
        pdf.set_fill_color(240, 245, 255)
        pdf.cell(0, 10, s("7. Cell Tower Map"), ln=True, fill=True)
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 6, s(f"Total towers: {towers.get('total_towers',0)}  |  Unique cells: {towers.get('unique_cells',0)}"), ln=True)
        techs = ', '.join(towers.get('technologies_detected',[])) or 'N/A'
        pdf.cell(0, 6, s(f"Technologies: {techs}"), ln=True)
        
        tower_list = towers.get("towers", [])[:30]
        if tower_list:
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(230, 230, 230)
            col_w = [16, 16, 22, 24, 14, 18, 14, 22, 14, 12]
            headers = ["MCC","MNC","LAC","Cell ID","PCI","Tech","Band","Signal","Srv","Obs"]
            for i, h in enumerate(headers):
                pdf.cell(col_w[i], 7, s(h), border=1, fill=True, align="C")
            pdf.ln()
            
            pdf.set_font("Helvetica", "", 8)
            for t in tower_list:
                row = [
                    str(t.get("mcc","")), str(t.get("mnc","")), str(t.get("lac","")),
                    str(t.get("cell_id",""))[:9], str(t.get("pci","")),
                    str(t.get("technology",""))[:6], str(t.get("band","")),
                    f"{t.get('signal_dbm',0)}dBm", "Y" if t.get("is_serving") else "",
                    str(t.get("observation_count",""))
                ]
                for i, val in enumerate(row):
                    pdf.cell(col_w[i], 6, s(val), border=1, align="C")
                pdf.ln()
        pdf.ln(6)
        
        # --- Footer ---
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 6, s("Baseband & Cellular Forensics Report - For Authorized Use Only"), ln=True, align="C")
        
        return bytes(pdf.output())

    def export_report(self, report: ForensicReport, 
                       format: str = "json") -> str:
        """Export the report in the specified format."""
        if format == "html":
            return self.to_html(report)
        elif format == "pdf":
            return self.to_pdf(report)
        else:
            return self.to_json(report)

