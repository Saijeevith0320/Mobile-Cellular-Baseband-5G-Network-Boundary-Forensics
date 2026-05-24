"""
Mobile Cellular Baseband & 5G Network Boundary Forensics
=========================================================
Streamlit Application for Real-World Android Device Forensics
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import time
from datetime import datetime
from io import BytesIO
import base64
import sys
sys.path.insert(0, '.')

# ---------------------------------------------------------------------------
# Page Config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Baseband & 5G Forensics",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* ====== GLOBAL ====== */
    .main .block-container { padding: 3rem 4rem !important; max-width: 1400px !important; }
    .main { background-color: #0a0e17; }
    .stApp { background-color: #0a0e17; }
    section[data-testid="stSidebar"] { background-color: #111827; }
    
    /* ====== HEADINGS - lots of breathing room ====== */
    h2 { margin-top: 3.5rem !important; margin-bottom: 1.5rem !important; }
    h3 { margin-top: 2.5rem !important; margin-bottom: 1.2rem !important; }
    
    /* ====== CARDS ====== */
    .forensic-card { 
        background: #111827; border: 1px solid #1f2937; border-radius: 12px; 
        padding: 28px; margin: 20px 0; 
    }
    .forensic-card h3 { color: #60a5fa; margin: 0 0 16px 0; font-size: 1.05rem; }
    
    /* ====== METRICS ROW ====== */
    .metric-card { 
        background: #111827; border: 1px solid #1f2937; border-radius: 12px; 
        padding: 24px 20px; text-align: center; margin-bottom: 16px;
    }
    .metric-value { font-size: 2rem; font-weight: 700; color: #e2e8f0; margin-bottom: 6px; }
    .metric-label { font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.1em; }
    
    /* ====== COLUMNS BREATHING ROOM ====== */
    [data-testid="column"] { padding: 0 14px !important; }
    
    /* ====== STATUS BADGES ====== */
    .status-active { color: #22c55e; font-weight: 600; }
    .status-warning { color: #f59e0b; font-weight: 600; }
    .status-critical { color: #ef4444; font-weight: 600; }
    .status-inactive { color: #6b7280; font-weight: 600; }
    
    /* ====== RISK BADGES ====== */
    .risk-critical { background: #ef4444; color: white; padding: 5px 14px; border-radius: 14px; font-weight: 600; }
    .risk-high { background: #f97316; color: white; padding: 5px 14px; border-radius: 14px; font-weight: 600; }
    .risk-medium { background: #eab308; color: #1a1a1a; padding: 5px 14px; border-radius: 14px; font-weight: 600; }
    .risk-low { background: #22c55e; color: white; padding: 5px 14px; border-radius: 14px; font-weight: 600; }
    .risk-minimal { background: #3b82f6; color: white; padding: 5px 14px; border-radius: 14px; font-weight: 600; }
    
    /* ====== CODE BLOCKS ====== */
    .stCodeBlock { background: #0d1117 !important; border: 1px solid #30363d !important; border-radius: 8px !important; margin: 16px 0 !important; }
    
    /* ====== DATAFRAMES - room to breathe ====== */
    .dataframe { font-size: 0.85rem !important; }
    [data-testid="stDataFrame"] { margin: 20px 0 !important; }
    
    /* ====== TABS - big, spacious ====== */
    .stTabs { margin-top: 3rem !important; }
    .stTabs [data-baseweb="tab-list"] { 
        gap: 10px; background: #111827; border-radius: 10px; padding: 10px 12px; 
        margin-bottom: 3rem !important;
    }
    .stTabs [data-baseweb="tab"] { 
        background: transparent; color: #94a3b8; border-radius: 8px; 
        padding: 12px 28px !important; font-size: 0.95rem; 
    }
    .stTabs [aria-selected="true"] { background: #1d4ed8 !important; color: white !important; }
    .stTabs [data-baseweb="tab-panel"] { 
        padding-top: 2.5rem !important; padding-bottom: 2rem !important; 
        padding-left: 1rem !important; padding-right: 1rem !important;
    }
    
    /* ====== METRICS INSIDE CARDS ====== */
    [data-testid="stMetricValue"] { font-size: 1.2rem !important; margin-bottom: 6px !important; }
    [data-testid="stMetricLabel"] { font-size: 0.75rem !important; }
    [data-testid="stMetric"] { margin-bottom: 16px !important; }
    
    /* ====== BUTTONS ====== */
    .stButton button { border-radius: 8px !important; padding: 10px 24px !important; margin: 8px 0 !important; }
    
    /* ====== EXPANDERS ====== */
    .streamlit-expanderHeader { padding: 14px 18px !important; border-radius: 8px !important; margin-top: 2rem !important; }
    .streamlit-expanderContent { padding: 18px 10px !important; }
    
    /* ====== ALERTS ====== */
    [data-testid="stAlert"] { margin: 1.5rem 0 !important; border-radius: 8px !important; padding: 14px !important; }
    
    /* ====== DIVIDER ====== */
    hr { margin: 3rem 0 !important; }
    
    /* ====== PLOTLY CHARTS ====== */
    .js-plotly-plot { margin: 18px 0 !important; }
    
    /* ====== GENERAL  CONTENT SPACING ====== */
    p { margin-bottom: 12px !important; }
    ul, ol { margin: 14px 0 !important; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Module Imports
# ---------------------------------------------------------------------------
MODULES_LOADED = False
ADBInterface = None

try:
    from modules.adb_interface import (
        ADBInterface, DeviceInfo, RadioState, parse_radio_state
    )
    from modules.radio_forensics import (
        RadioForensicsAnalyzer, RadioForensicReport
    )
    from modules.baseband_analyzer import (
        BasebandAnalyzer, BasebandInfo, BasebandSecurityAudit
    )
    from modules.network_scanner import (
        NRNetworkForensics, NRCell, NRNetworkAnalysis
    )
    from modules.sim_forensics import SIMForensics, SIMInfo
    from modules.cell_tower_mapper import CellTowerMapper, TowerRecord, TowerMap
    from modules.report_generator import ReportGenerator, ForensicReport
    MODULES_LOADED = True
except ImportError as e:
    st.error(f"Failed to load forensic modules: {e}")

# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------
for key, default in {
    'connected': False,
    'device': None,
    'adb_path_value': 'adb',
    'radio_state': None,
    'events': [],
    'forensic_report': None,
    'baseband_info': None,
    'security_audit': None,
    'sim_data': [],
    'nr_analysis': None,
    'tower_map': None,
    'report_json': None,
    'report_html': None,
    'report_pdf': None,
    'analysis_complete': False,
    'raw_radio_dump': '',
    'raw_telephony_dump': '',
    'raw_modem_logs': '',
    'raw_build_prop': '',
    'raw_logcat': '',
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

if 'adb' not in st.session_state and MODULES_LOADED:
    st.session_state.adb = ADBInterface()


# ---------------------------------------------------------------------------
# Helper: run_analysis
# ---------------------------------------------------------------------------
def run_analysis():
    if not st.session_state.connected:
        st.warning("Not connected to a device.")
        return

    adb = st.session_state.adb
    device = st.session_state.device

    with st.status("Running forensic analysis...", expanded=True) as status:
        # Step 1
        status.update(label="Collecting device dumps...", state="running")
        st.session_state.raw_radio_dump = adb.get_radio_dump()
        st.session_state.raw_telephony_dump = adb.get_telephony_dump()
        st.session_state.raw_modem_logs = adb.get_modem_logs(lines=3000)
        st.session_state.raw_build_prop = adb.shell("getprop")[1]
        st.session_state.raw_logcat = adb.get_baseband_logs(lines=5000)
        service_list = adb.get_service_list()
        radio_hal = adb.get_radio_hal_version()
        is_rooted = adb.check_root()

        # Step 2
        status.update(label="Parsing radio state...", state="running")
        st.session_state.radio_state = parse_radio_state(
            st.session_state.raw_radio_dump + "\n" + st.session_state.raw_telephony_dump
        )

        # Step 3
        status.update(label="Parsing radio events...", state="running")
        analyzer = RadioForensicsAnalyzer()
        st.session_state.events = analyzer.parse_logcat_radio_events(st.session_state.raw_logcat)

        # Step 4
        status.update(label="Analyzing SIM cards...", state="running")
        sim_raw = adb.get_sim_info()
        sim_forensics = SIMForensics()
        st.session_state.sim_data = sim_forensics.analyze_sim(
            sim_raw, st.session_state.raw_telephony_dump,
            st.session_state.raw_build_prop, device.serial
        )

        # Step 5
        status.update(label="Analyzing baseband...", state="running")
        bb_analyzer = BasebandAnalyzer()
        build_props = {}
        for line in st.session_state.raw_build_prop.strip().split("\n"):
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip().lstrip("[").rstrip("]")
                value = parts[1].strip().lstrip("[").rstrip("]")
                build_props[key] = value

        st.session_state.baseband_info = bb_analyzer.analyze_baseband(
            build_props, st.session_state.raw_build_prop,
            radio_hal, st.session_state.raw_modem_logs, device
        )
        st.session_state.security_audit = bb_analyzer.audit_security(
            build_props, st.session_state.raw_build_prop,
            service_list, st.session_state.baseband_info, is_rooted
        )

        # Step 6
        status.update(label="Analyzing 5G NR network...", state="running")
        nr_forensics = NRNetworkForensics()
        st.session_state.nr_analysis = nr_forensics.analyze_5g_network(
            st.session_state.raw_telephony_dump,
            st.session_state.raw_radio_dump,
            st.session_state.raw_modem_logs,
            st.session_state.radio_state
        )

        # Step 7
        status.update(label="Mapping cell towers...", state="running")
        mapper = CellTowerMapper()
        cell_history = analyzer.extract_cell_history(st.session_state.events)
        st.session_state.tower_map = mapper.map_towers(
            device.serial, cell_history,
            st.session_state.radio_state,
            st.session_state.raw_telephony_dump
        )

        # Step 8
        status.update(label="Generating forensic report...", state="running")
        report_gen = ReportGenerator()
        report_id = report_gen.generate_report_id()
        signal_timeline = analyzer.build_signal_timeline(st.session_state.events)
        anomalies = analyzer.detect_anomalies(st.session_state.events, st.session_state.radio_state)

        categories = {}
        event_types = {}
        for e in st.session_state.events:
            cat = e.get('category', 'other')
            etype = e.get('event_type', 'unknown')
            categories[cat] = categories.get(cat, 0) + 1
            event_types[etype] = event_types.get(etype, 0) + 1

        st.session_state.forensic_report = report_gen.compile_report(
            report_id, device, st.session_state.baseband_info,
            st.session_state.security_audit, st.session_state.radio_state,
            st.session_state.sim_data, st.session_state.nr_analysis,
            st.session_state.tower_map, signal_timeline, anomalies,
            {'categories': categories, 'event_types': event_types}
        )

        st.session_state.report_json = report_gen.to_json(st.session_state.forensic_report)
        st.session_state.report_html = report_gen.to_html(st.session_state.forensic_report)
        st.session_state.report_pdf = report_gen.to_pdf(st.session_state.forensic_report)
        st.session_state.analysis_complete = True

        status.update(label="Analysis complete!", state="complete")

    st.rerun()

# ---------------------------------------------------------------------------
# Main Content
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Sidebar — Device Connection
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("📡 Baseband & 5G Forensics")
    st.caption("Mobile Cellular Forensics Suite")
    st.divider()
    st.subheader("📱 Device Connection")

    if not MODULES_LOADED:
        st.stop()

    # ADB path input - always show
    adb_path = st.text_input(
        "ADB path (paste full path to adb.exe):",
        value=st.session_state.adb_path_value,
        key="adb_path_input"
    )

    if adb_path and adb_path != st.session_state.adb_path_value:
        st.session_state.adb_path_value = adb_path
        st.session_state.adb = ADBInterface(adb_path)

    adb_available = False
    try:
        adb_available = st.session_state.adb.check_adb_available()
    except Exception:
        adb_available = False

    if not adb_available:
        st.warning("ADB not found. Paste the full path to adb.exe above.")
    else:
        st.success("ADB connected")

    # Connection method
    conn_method = st.radio(
        "Connection method:",
        ["USB", "Wireless (TCP/IP)"],
        horizontal=True
    )

    if conn_method == "Wireless (TCP/IP)":
        ip = st.text_input("Device IP:", placeholder="192.168.1.100")
        port = st.number_input("Port:", value=5555, min_value=1, max_value=65535)
        if st.button("Connect via WiFi", use_container_width=True):
            success, msg = st.session_state.adb.connect_wireless(ip, port)
            if success:
                st.success(f"Connected: {msg}")
                time.sleep(1)
            else:
                st.error(f"Failed: {msg}")

    # Refresh device list
    if st.button("Scan for Devices", use_container_width=True):
        st.rerun()

    # List devices
    if not adb_available:
        st.info("Set ADB path above first.")
    else:
        devices = st.session_state.adb.list_devices()
        if not devices:
            st.warning("No devices detected. Connect via USB or WiFi.")
        else:
            st.success(f"Found {len(devices)} device(s)")
            device_options = {}
            for d in devices:
                label = f"{d.manufacturer} {d.model} ({d.serial})" if d.model else d.serial
                device_options[label] = d

            selected_label = st.selectbox(
                "Select device:",
                list(device_options.keys()),
                key="device_selector"
            )

            if selected_label:
                selected_device = device_options[selected_label]
                st.session_state.adb.set_device(selected_device.serial)
                st.session_state.device = selected_device
                st.session_state.connected = True

                st.divider()
                st.subheader("Device Info")
                st.markdown(f"**Model:** {selected_device.model or 'N/A'}")
                st.markdown(f"**Mfr:** {selected_device.manufacturer or 'N/A'}")
                st.markdown(f"**Android:** {selected_device.android_version or 'N/A'}")
                st.markdown(f"**Baseband:** {selected_device.baseband_version or 'N/A'}")

                st.divider()
                btn_label = "Run Full Analysis" if not st.session_state.analysis_complete else "Re-run Analysis"
                if st.button(btn_label, type="primary", use_container_width=True):
                    with st.spinner("Running forensic analysis..."):
                        run_analysis()

if not st.session_state.connected:
    st.title("Mobile Cellular Baseband & 5G Network Boundary Forensics")
    st.markdown("""
    ### A Real-World Android Forensic Analysis Platform

    This tool performs deep forensic analysis of Android cellular subsystems:

    - **Baseband Analysis** — Chipset identification, firmware version, security audit
    - **Radio Layer Forensics** — RIL events, cell history, signal timeline
    - **5G NR Analysis** — NSA/SA detection, carrier aggregation, beam management
    - **SIM/USIM Forensics** — ICCID/IMSI extraction, operator identification, roaming detection
    - **Cell Tower Mapping** — Serving & neighbor cell mapping, coverage estimation
    - **Security Audit** — Risk scoring, SELinux state, bootloader verification

    ### Getting Started

    1. Install **Android SDK Platform Tools** (ADB)
    2. Enable **USB Debugging** on your Android device
    3. Paste the full path to `adb.exe` in the sidebar
    4. Click **Scan for Devices** and select your device
    5. Run the analysis
    """)

elif st.session_state.analysis_complete:
    # Dashboard view
    report = st.session_state.forensic_report
    rs = st.session_state.radio_state
    bb = st.session_state.baseband_info
    sec = st.session_state.security_audit
    sims = st.session_state.sim_data
    nr = st.session_state.nr_analysis

    # --- Top Row: Key Metrics ---
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        net_type = rs.network_type if rs else "N/A"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="font-size:1.4rem;">{net_type}</div>
            <div class="metric-label">Network Type</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        sig = rs.signal_dbm if rs else 0
        sig_color = "#22c55e" if sig >= -85 else "#eab308" if sig >= -105 else "#ef4444"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color:{sig_color};">{sig} dBm</div>
            <div class="metric-label">Signal Strength</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        risk = sec.risk_level if sec else "N/A"
        risk_class = f"risk-{risk.lower()}" if risk != "N/A" else ""
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value"><span class="{risk_class}">{risk}</span></div>
            <div class="metric-label">Security Risk</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        towers = len(st.session_state.tower_map.towers) if st.session_state.tower_map else 0
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{towers}</div>
            <div class="metric-label">Cell Towers</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        anom = len(report.anomalies) if report else 0
        anom_color = "#22c55e" if anom == 0 else "#ef4444"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color:{anom_color};">{anom}</div>
            <div class="metric-label">Anomalies</div>
        </div>
        """, unsafe_allow_html=True)

    # --- Tabs ---
    tabs = st.tabs([
        "Radio State", "5G NR", "Security",
        "SIM Card", "Towers", "Events", "Report"
    ])

    # ============================================================
    # TAB 1: Radio State
    # ============================================================
    with tabs[0]:
        st.subheader("Current Radio Connection State")

        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("""<div class="forensic-card"><h3>Network Connection</h3>""", unsafe_allow_html=True)
            if rs:
                df_net = pd.DataFrame([
                    ("Network Type", rs.network_type or "N/A"),
                    ("Radio Technology", rs.radio_technology or "N/A"),
                    ("Data State", rs.data_state or "N/A"),
                    ("Voice State", rs.voice_state or "N/A"),
                    ("Operator", rs.operator_name or "N/A"),
                    ("MCC", rs.mcc or "N/A"),
                    ("MNC", rs.mnc or "N/A"),
                ], columns=["Parameter", "Value"])
                st.dataframe(df_net, use_container_width=True, hide_index=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with col_b:
            st.markdown("""<div class="forensic-card"><h3>Signal & Cell Identity</h3>""", unsafe_allow_html=True)
            if rs:
                sig_val = rs.signal_dbm or -120
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=abs(sig_val),
                    title={"text": "Signal Strength (-dBm)"},
                    gauge={
                        "axis": {"range": [40, 130]},
                        "bar": {"color": "#1f6feb"},
                        "steps": [
                            {"range": [40, 80], "color": "#22c55e"},
                            {"range": [80, 100], "color": "#eab308"},
                            {"range": [100, 120], "color": "#f97316"},
                            {"range": [120, 130], "color": "#ef4444"},
                        ],
                    },
                    number={"suffix": " dBm", "font": {"size": 32, "color": "#e2e8f0"}},
                ))
                fig.update_layout(height=220, margin=dict(t=40, b=10, l=20, r=20),
                                paper_bgcolor="#111827", font_color="#94a3b8")
                st.plotly_chart(fig, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # Cell details
        if rs:
            st.markdown("""<div class="forensic-card"><h3>Cell Tower Details</h3>""", unsafe_allow_html=True)
            col_c1, col_c2, col_c3 = st.columns(3)
            with col_c1:
                st.metric("TAC/LAC", rs.lac_tac or "N/A")
                st.metric("Cell ID", rs.cell_id or "N/A")
                st.metric("PCI", rs.pci or "N/A")
            with col_c2:
                st.metric("Band", f"n{rs.band}" if rs.band and rs.radio_technology == "NR" else rs.band or "N/A")
                st.metric("ARFCN", rs.arfcn or "N/A")
                st.metric("NR-ARFCN", rs.nr_arfcn or "N/A")
            with col_c3:
                st.metric("SCS", rs.scs or "N/A")
                st.metric("Bandwidth", rs.bandwidth or "N/A")
                st.metric("eNB/gNB ID", rs.enb_gnb_id or "N/A")
            st.markdown("</div>", unsafe_allow_html=True)

        # Raw dumps
        with st.expander("Raw Radio Dump"):
            if st.session_state.raw_radio_dump:
                st.code(st.session_state.raw_radio_dump[:10000], language="text")
            else:
                st.info("No radio dump data returned. Try USB connection or root access.")

    # ============================================================
    # TAB 2: 5G NR
    # ============================================================
    with tabs[1]:
        st.subheader("5G NR Network Forensics")

        if nr:
            nr_active = nr.is_nsa_active or nr.is_sa_active
            st.markdown(f"""
            **5G NR Active:** {'<span class="status-active">ACTIVE</span>' if nr_active else '<span class="status-inactive">Inactive</span>'}
            &nbsp; **NSA:** {'<span class="status-active">Yes</span>' if nr.is_nsa_active else '<span class="status-inactive">No</span>'}
            &nbsp; **SA:** {'<span class="status-active">Yes</span>' if nr.is_sa_active else '<span class="status-inactive">No</span>'}
            &nbsp; **EN-DC:** {'<span class="status-active">Supported</span>' if nr.endc_supported else '<span class="status-inactive">No</span>'}
            """, unsafe_allow_html=True)

            if nr.detected_bands:
                st.markdown(f"**Detected NR Bands:** {', '.join('n'+str(b) for b in nr.detected_bands)}")

            serving = nr.serving_cell
            if serving:
                st.markdown("""<div class="forensic-card"><h3>Serving NR Cell</h3>""", unsafe_allow_html=True)
                df_nr = pd.DataFrame([
                    ("NR-ARFCN", str(serving.nr_arfcn)),
                    ("PCI", str(serving.pci)),
                    ("Band", f"n{serving.band}" if serving.band else "N/A"),
                    ("SCS", f"{serving.scs} kHz" if serving.scs else "N/A"),
                    ("Bandwidth", f"{serving.bandwidth} MHz" if serving.bandwidth else "N/A"),
                    ("Mode", serving.connection_mode or "N/A"),
                    ("Frequency Range", serving.frequency_range or "N/A"),
                    ("SS-RSRP", f"{serving.ss_rsrp} dBm" if serving.ss_rsrp else "N/A"),
                ], columns=["Parameter", "Value"])
                st.dataframe(df_nr, use_container_width=True, hide_index=True)
                st.markdown("</div>", unsafe_allow_html=True)

            tp = nr.throughput_estimation
            if tp and tp.get('estimated_dl_mbps', 0) > 0:
                st.markdown("""<div class="forensic-card"><h3>Estimated Throughput</h3>""", unsafe_allow_html=True)
                col_t1, col_t2, col_t3 = st.columns(3)
                col_t1.metric("DL Max", f"{tp['estimated_dl_mbps']} Mbps")
                col_t2.metric("UL Max", f"{tp['estimated_ul_mbps']} Mbps")
                col_t3.metric("PRBs", tp.get('num_prbs', 'N/A'))
                st.caption(f"Assumptions: {tp.get('modulation','')} | {tp.get('note','')}")
                st.markdown("</div>", unsafe_allow_html=True)

            if nr.carrier_aggregation:
                st.markdown("""<div class="forensic-card"><h3>Carrier Aggregation</h3>""", unsafe_allow_html=True)
                ca_df = pd.DataFrame(nr.carrier_aggregation)
                if not ca_df.empty:
                    st.dataframe(ca_df, use_container_width=True)
                st.markdown("</div>", unsafe_allow_html=True)

            if nr.network_slicing_indicators:
                st.info("\n".join(nr.network_slicing_indicators))
        else:
            st.info("No 5G NR data available.")

    # ============================================================
    # TAB 3: Security
    # ============================================================
    with tabs[2]:
        st.subheader("Baseband Security Audit")

        col_s1, col_s2 = st.columns([1, 2])

        with col_s1:
            risk_score = sec.risk_score if sec else 0
            risk_level = sec.risk_level if sec else "Unknown"
            risk_color = {
                "CRITICAL": "#ef4444", "HIGH": "#f97316",
                "MEDIUM": "#eab308", "LOW": "#22c55e", "MINIMAL": "#3b82f6"
            }.get(risk_level, "#6b7280")

            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=risk_score,
                title={"text": "Risk Score", "font": {"size": 18, "color": "#94a3b8"}},
                delta={"reference": 30, "increasing": {"color": "#ef4444"}},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": risk_color},
                    "steps": [
                        {"range": [0, 25], "color": "#3b82f6"},
                        {"range": [25, 50], "color": "#22c55e"},
                        {"range": [50, 70], "color": "#eab308"},
                        {"range": [70, 100], "color": "#ef4444"},
                    ],
                }
            ))
            fig.update_layout(height=280, paper_bgcolor="#111827", font_color="#94a3b8")
            st.plotly_chart(fig, use_container_width=True)
            st.markdown(f"<h3 style='text-align:center;color:{risk_color};'>{risk_level}</h3>", unsafe_allow_html=True)

        with col_s2:
            if sec:
                st.markdown("""<div class="forensic-card"><h3>Security Details</h3>""", unsafe_allow_html=True)
                df_sec = pd.DataFrame([
                    ("Root Access", "DETECTED" if sec.root_access_detected else "Not detected"),
                    ("Bootloader", "UNLOCKED" if sec.bootloader_unlocked else "Locked"),
                    ("SELinux", sec.selinux_status or "N/A"),
                    ("DM-Verity", sec.dm_verity_status or "N/A"),
                    ("Encryption", sec.encryption_status or "N/A"),
                    ("Patch Age", f"{sec.patch_level_days_old} days" if sec.patch_level_days_old >= 0 else "N/A"),
                    ("Engineering Build", "YES" if (bb and bb.is_engineering_build) else "No"),
                ], columns=["Check", "Result"])
                st.dataframe(df_sec, use_container_width=True, hide_index=True)
                st.markdown("</div>", unsafe_allow_html=True)

                if sec.dangerous_services:
                    st.warning(f"Dangerous services: {', '.join(sec.dangerous_services)}")
                if sec.exposed_interfaces:
                    st.warning(f"Exposed interfaces: {', '.join(sec.exposed_interfaces)}")

        # Baseband info
        if bb:
            st.markdown("""<div class="forensic-card"><h3>Baseband Processor</h3>""", unsafe_allow_html=True)
            col_bb1, col_bb2, col_bb3 = st.columns(3)
            with col_bb1:
                st.metric("Vendor", bb.chipset_vendor or "N/A")
                st.metric("Processor", bb.baseband_processor or "N/A")
                st.metric("Model", bb.modem_model or "N/A")
            with col_bb2:
                st.metric("Firmware", (bb.firmware_version or "N/A")[:40])
                st.metric("RIL", bb.ril_version or "N/A")
                st.metric("HAL", bb.hal_version or "N/A")
            with col_bb3:
                st.metric("VoLTE", "Yes" if bb.volte_supported else "No")
                st.metric("VoWiFi", "Yes" if bb.vowifi_supported else "No")
                techs = ", ".join(bb.supported_technologies) if bb.supported_technologies else "N/A"
                st.metric("Technologies", techs)
            st.markdown("</div>", unsafe_allow_html=True)

            if bb.security_issues:
                st.warning("\n".join(f"* {i}" for i in bb.security_issues))

    # ============================================================
    # TAB 4: SIM Card
    # ============================================================
    with tabs[3]:
        st.subheader("SIM/USIM Card Forensics")

        if sims:
            for i, sim in enumerate(sims):
                st.markdown(f"""<div class="forensic-card"><h3>SIM Slot {i+1}</h3>""", unsafe_allow_html=True)
                col_sim1, col_sim2, col_sim3 = st.columns(3)
                with col_sim1:
                    st.metric("ICCID", sim.iccid or "N/A")
                    st.metric("IMSI", sim.imsi or "N/A")
                    st.metric("MCC/MNC", f"{sim.mcc}/{sim.mnc}" if sim.mcc else "N/A")
                with col_sim2:
                    st.metric("Operator", sim.operator_name or "N/A")
                    st.metric("Country", sim.operator_country or "N/A")
                    st.metric("Type", sim.sim_type or "N/A")
                with col_sim3:
                    st.metric("Roaming", "Yes" if sim.is_roaming else "No")
                    st.metric("MSISDN", sim.msisdn or "N/A")
                    st.metric("IMEI", sim.imei or "N/A")
                st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.info("No SIM card data available.")

        with st.expander("Raw Telephony Registry Dump"):
            if st.session_state.raw_telephony_dump:
                st.code(st.session_state.raw_telephony_dump[:10000], language="text")
            else:
                st.info("No telephony data returned.")

    # ============================================================
    # TAB 5: Towers
    # ============================================================
    with tabs[4]:
        st.subheader("Cell Tower Map & Analysis")

        tower_map = st.session_state.tower_map
        if tower_map and tower_map.towers:
            towers_data = []
            for t in tower_map.towers:
                towers_data.append({
                    'MCC': t.mcc, 'MNC': t.mnc, 'LAC': t.lac,
                    'Cell ID': hex(t.cell_id) if t.cell_id else 'N/A',
                    'PCI': t.pci, 'Technology': t.technology,
                    'Signal (dBm)': t.signal_dbm, 'Signal Quality': t.signal_quality,
                    'Est. Distance (m)': round(t.estimated_distance_m, 1),
                    'Serving': 'Yes' if t.is_serving else '',
                    'Observations': t.observation_count,
                })
            df_towers = pd.DataFrame(towers_data)
            st.dataframe(df_towers, use_container_width=True, height=400)

            col_v1, col_v2 = st.columns(2)
            with col_v1:
                tech_counts = df_towers['Technology'].value_counts()
                fig_tech = px.pie(values=tech_counts.values, names=tech_counts.index,
                                  title="Towers by Technology")
                fig_tech.update_layout(paper_bgcolor="#111827", font_color="#94a3b8",
                                      title_font_color="#e2e8f0")
                st.plotly_chart(fig_tech, use_container_width=True)
            with col_v2:
                sig_vals = [t.signal_dbm for t in tower_map.towers if t.signal_dbm != 0]
                if sig_vals:
                    fig_sig = px.histogram(x=sig_vals, nbins=20, title="Signal Strength Distribution")
                    fig_sig.update_layout(paper_bgcolor="#111827", font_color="#94a3b8",
                                         title_font_color="#e2e8f0")
                    st.plotly_chart(fig_sig, use_container_width=True)
        else:
            st.info("No cell tower data available.")

    # ============================================================
    # TAB 6: Events
    # ============================================================
    with tabs[5]:
        st.subheader("Radio Event Analysis")

        events = st.session_state.events
        if events:
            cats = {}
            for e in events:
                cats[e.get('category', 'other')] = cats.get(e.get('category', 'other'), 0) + 1

            col_ev1, col_ev2 = st.columns(2)
            with col_ev1:
                fig_cat = px.bar(x=list(cats.keys()), y=list(cats.values()),
                                title="Events by Category",
                                labels={'x': 'Category', 'y': 'Count'})
                fig_cat.update_layout(paper_bgcolor="#111827", font_color="#94a3b8",
                                     title_font_color="#e2e8f0", showlegend=False)
                st.plotly_chart(fig_cat, use_container_width=True)
            with col_ev2:
                etypes = {}
                for e in events:
                    etypes[e.get('event_type', 'unknown')] = etypes.get(e.get('event_type', 'unknown'), 0) + 1
                top = sorted(etypes.items(), key=lambda x: x[1], reverse=True)[:10]
                fig_etype = px.bar(x=[t[0] for t in top], y=[t[1] for t in top],
                                  title="Top Event Types",
                                  labels={'x': 'Event Type', 'y': 'Count'})
                fig_etype.update_layout(paper_bgcolor="#111827", font_color="#94a3b8",
                                       title_font_color="#e2e8f0", showlegend=False)
                st.plotly_chart(fig_etype, use_container_width=True)

            st.subheader(f"Parsed Events ({len(events)} total)")
            df_events = pd.DataFrame(events[:500])
            if not df_events.empty:
                display_cols = [c for c in ['timestamp','tag','category','event_type','message'] if c in df_events.columns]
                st.dataframe(df_events[display_cols], use_container_width=True, height=400)
        else:
            st.info("No radio events parsed.")

        with st.expander("Raw Logcat (Radio)"):
            if st.session_state.raw_logcat:
                st.code(st.session_state.raw_logcat[:15000], language="text")
            else:
                st.info("No radio logcat data returned.")

    # ============================================================
    # TAB 7: Report
    # ============================================================
    with tabs[6]:
        st.subheader("Forensic Report Export")
        st.markdown(f"**Report ID:** `{report.report_id}` | **Generated:** {report.generated_at}")

        if report.anomalies:
            st.error("### Detected Anomalies")
            for a in report.anomalies:
                st.markdown(f"* {a}")
        else:
            st.success("No significant anomalies detected.")

        col_dl1, col_dl2, col_dl3 = st.columns(3)

        with col_dl1:
            st.download_button(
                label="Download JSON Report",
                data=st.session_state.report_json,
                file_name=f"forensic_report_{report.report_id}.json",
                mime="application/json",
                use_container_width=True,
            )

        with col_dl2:
            st.download_button(
                label="Download HTML Report",
                data=st.session_state.report_html,
                file_name=f"forensic_report_{report.report_id}.html",
                mime="text/html",
                use_container_width=True,
            )

        with col_dl3:
            st.download_button(
                label="Download PDF Report",
                data=st.session_state.report_pdf,
                file_name=f"forensic_report_{report.report_id}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        with st.expander("HTML Report Preview"):
            st.components.v1.html(st.session_state.report_html, height=800, scrolling=True)

        with st.expander("JSON Report Preview"):
            try:
                st.json(json.loads(st.session_state.report_json))
            except Exception:
                st.code(st.session_state.report_json[:5000], language="json")

# Footer
st.divider()
st.caption("Mobile Cellular Baseband & 5G Network Boundary Forensics | For authorized use only")
