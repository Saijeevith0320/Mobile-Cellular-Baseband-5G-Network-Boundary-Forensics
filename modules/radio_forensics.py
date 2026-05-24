"""
Radio Layer Forensics Module
=============================
Deep analysis of Radio Interface Layer (RIL) and cellular protocol stacks.
Extracts forensic artifacts from Android's telephony framework.
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class CellRecord:
    """A record of a cell tower sighting/connection."""
    timestamp: str = ""
    mcc: str = ""
    mnc: str = ""
    lac_tac: int = 0
    cell_id: int = 0
    pci: int = 0
    technology: str = ""
    band: str = ""
    arfcn: int = 0
    signal_dbm: int = 0
    signal_asu: int = 0
    is_serving: bool = False
    is_registered: bool = False


@dataclass
class NRCellRecord:
    """5G NR-specific cell record."""
    timestamp: str = ""
    mcc: str = ""
    mnc: str = ""
    tac: int = 0
    nr_cell_id: int = 0
    pci: int = 0
    nr_arfcn: int = 0
    scs: int = 0
    bandwidth: str = ""
    ss_rsrp: int = 0
    ss_rsrq: int = 0
    ss_sinr: int = 0
    is_nsa: bool = False
    is_sa: bool = False
    csi_rsrp: int = 0
    csi_rsrq: int = 0
    csi_sinr: int = 0


@dataclass
class NeighborCell:
    """A detected neighbor cell."""
    technology: str = ""
    pci: int = 0
    arfcn: int = 0
    signal_dbm: int = 0
    mcc: str = ""
    mnc: str = ""
    cell_id: str = ""


@dataclass
class RadioForensicReport:
    """Complete radio forensic analysis report."""
    device_id: str = ""
    analysis_time: str = ""
    current_serving_cell: Optional[CellRecord] = None
    current_nr_cell: Optional[NRCellRecord] = None
    neighbor_cells: List[NeighborCell] = field(default_factory=list)
    cell_history: List[CellRecord] = field(default_factory=list)
    nr_cell_history: List[NRCellRecord] = field(default_factory=list)
    registration_changes: List[Dict] = field(default_factory=list)
    signal_timeline: List[Dict] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    raw_analysis: Dict[str, Any] = field(default_factory=dict)


class RadioForensicsAnalyzer:
    """
    Analyzes radio layer data for forensic artifacts including
    cell tower history, network transitions, and anomalies.
    """

    # LTE bands reference
    LTE_BANDS = {
        1: "2100 MHz (FDD)", 2: "1900 MHz (FDD)", 3: "1800 MHz (FDD)",
        4: "1700/2100 MHz (FDD)", 5: "850 MHz (FDD)", 7: "2600 MHz (FDD)",
        8: "900 MHz (FDD)", 12: "700 MHz (FDD)", 13: "700 MHz (FDD)",
        17: "700 MHz (FDD)", 20: "800 MHz (FDD)", 25: "1900 MHz (FDD)",
        26: "850 MHz (FDD)", 28: "700 MHz (FDD)", 38: "2600 MHz (TDD)",
        40: "2300 MHz (TDD)", 41: "2500 MHz (TDD)", 66: "1700/2100 MHz (FDD)",
        71: "600 MHz (FDD)",
    }

    # 5G NR bands reference
    NR_BANDS = {
        1: "2100 MHz (FDD)", 2: "1900 MHz (FDD)", 3: "1800 MHz (FDD)",
        5: "850 MHz (FDD)", 7: "2600 MHz (FDD)", 8: "900 MHz (FDD)",
        12: "700 MHz (FDD)", 20: "800 MHz (FDD)", 25: "1900 MHz (FDD)",
        28: "700 MHz (FDD)", 38: "2600 MHz (TDD)", 40: "2300 MHz (TDD)",
        41: "2500 MHz (TDD)", 66: "1700/2100 MHz (FDD)",
        71: "600 MHz (FDD)", 77: "3.3-4.2 GHz (TDD)", 78: "3.3-3.8 GHz (TDD)",
        79: "4.4-5.0 GHz (TDD)", 257: "26.5-29.5 GHz (TDD, mmWave)",
        258: "24.25-27.5 GHz (TDD, mmWave)", 260: "37-40 GHz (TDD, mmWave)",
        261: "27.5-28.35 GHz (TDD, mmWave)",
    }

    @staticmethod
    def parse_logcat_radio_events(logcat_output: str) -> List[Dict[str, Any]]:
        """
        Parse radio logcat output for RIL events, cell changes,
        and network state transitions.
        """
        events = []
        lines = logcat_output.strip().split("\n")
        
        for line in lines:
            event = {}
            
            # Parse standard logcat format: timestamp PID TID level TAG: message
            logcat_pattern = re.compile(
                r'(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+(.+?):\s*(.*)'
            )
            match = logcat_pattern.match(line)
            if match:
                event['timestamp'] = match.group(1)
                event['pid'] = match.group(2)
                event['tid'] = match.group(3)
                event['level'] = match.group(4)
                event['tag'] = match.group(5)
                event['message'] = match.group(6)
            else:
                event['raw'] = line
                event['timestamp'] = ""
                event['tag'] = "UNKNOWN"
                event['message'] = line
            
            # Classify the event
            tag = event.get('tag', '')
            msg = event.get('message', '')
            
            if 'RILJ' in tag or 'RIL' in tag:
                event['category'] = 'ril'
                # Detect specific RIL events
                if 'GET_CELL_INFO_LIST' in msg:
                    event['event_type'] = 'cell_info_request'
                elif 'UNSOL_RESPONSE' in msg:
                    event['event_type'] = 'unsolicited_response'
                    if 'CELL_INFO' in msg:
                        event['event_type'] = 'cell_info_update'
                    elif 'SIGNAL_STRENGTH' in msg:
                        event['event_type'] = 'signal_update'
                    elif 'VOICE_NETWORK_STATE' in msg:
                        event['event_type'] = 'network_state_change'
            elif 'CELL' in tag or 'CELL' in msg.upper():
                event['category'] = 'cell'
                if 'SERVING' in msg.upper():
                    event['event_type'] = 'serving_cell'
                elif 'NEIGHBOR' in msg.upper():
                    event['event_type'] = 'neighbor_cell'
                else:
                    event['event_type'] = 'cell_info'
            elif 'SIGNAL' in tag or 'SIGNAL' in msg.upper():
                event['category'] = 'signal'
                event['event_type'] = 'signal_measurement'
            elif 'NR' in tag or '5G' in tag or 'NR_' in tag:
                event['category'] = '5g_nr'
                event['event_type'] = 'nr_event'
            elif 'MODEM' in tag:
                event['category'] = 'modem'
                event['event_type'] = 'modem_event'
            elif 'BASEBAND' in tag:
                event['category'] = 'baseband'
                event['event_type'] = 'baseband_event'
            else:
                event['category'] = 'other'
                event['event_type'] = 'unknown'
            
            events.append(event)
        
        return events

    @staticmethod
    def extract_cell_history(events: List[Dict]) -> List[CellRecord]:
        """Extract cell tower history from parsed events."""
        cell_records = []
        seen_cells = set()
        
        for event in events:
            msg = event.get('message', '')
            
            # Try to parse cell identity information
            mcc_match = re.search(r'(?:mcc|MCC)[=:\s]*(\d{3})', msg)
            mnc_match = re.search(r'(?:mnc|MNC)[=:\s]*(\d{2,3})', msg)
            ci_match = re.search(r'(?:ci|cellId|getCid|CellId)[=:\s]*(\d+)', msg)
            lac_match = re.search(r'(?:lac|tac|LAC|TAC)[=:\s]*(\d+)', msg)
            pci_match = re.search(r'(?:pci|PCI|physCellId)[=:\s]*(\d{1,3})', msg)
            
            # Detect technology
            tech = "UNKNOWN"
            if re.search(r'LTE|lte', msg):
                tech = "LTE"
            elif re.search(r'NR|nrState|5G', msg, re.IGNORECASE):
                tech = "NR"
            elif re.search(r'WCDMA|UMTS', msg, re.IGNORECASE):
                tech = "WCDMA"
            elif re.search(r'GSM|GPRS', msg, re.IGNORECASE):
                tech = "GSM"
            
            if ci_match or pci_match:
                record = CellRecord(
                    timestamp=event.get('timestamp', ''),
                    mcc=mcc_match.group(1) if mcc_match else '',
                    mnc=mnc_match.group(1) if mnc_match else '',
                    lac_tac=int(lac_match.group(1)) if lac_match else 0,
                    cell_id=int(ci_match.group(1)) if ci_match else 0,
                    pci=int(pci_match.group(1)) if pci_match else 0,
                    technology=tech,
                )
                
                # Deduplicate
                key = (record.mcc, record.mnc, record.cell_id, record.pci)
                if key not in seen_cells and (record.cell_id or record.pci):
                    seen_cells.add(key)
                    cell_records.append(record)
        
        return cell_records

    @staticmethod
    def detect_anomalies(events: List[Dict], radio_state: Any) -> List[str]:
        """Detect potential forensic anomalies in radio behavior."""
        anomalies = []
        
        # Check for frequent IMSI detachment/attachment (tracking)
        attach_count = 0
        detach_count = 0
        for event in events:
            msg = event.get('message', '')
            if re.search(r'IMSI.*ATTACH|attach.*IMSI|GPRS.*ATTACH', msg, re.IGNORECASE):
                attach_count += 1
            if re.search(r'IMSI.*DETACH|detach.*IMSI|GPRS.*DETACH', msg, re.IGNORECASE):
                detach_count += 1
        
        if attach_count > 10:
            anomalies.append(f"High IMSI attach frequency: {attach_count} events (possible tracking or network instability)")
        if detach_count > 10:
            anomalies.append(f"High IMSI detach frequency: {detach_count} events (possible tracking or network rejection)")
        
        # Check for frequent cell reselections (mobility pattern analysis)
        reselection_count = sum(1 for e in events 
                               if re.search(r'RESEL|resel|CELL_RESELECTION|handover', 
                                           e.get('message', ''), re.IGNORECASE))
        if reselection_count > 20:
            anomalies.append(f"High cell reselection count: {reselection_count} (rapid mobility or coverage issues)")
        
        # Check for radio link failures
        rlf_count = sum(1 for e in events 
                       if re.search(r'RADIO_LINK_FAIL|RLF|radio link fail', 
                                   e.get('message', ''), re.IGNORECASE))
        if rlf_count > 5:
            anomalies.append(f"Multiple radio link failures detected: {rlf_count}")
        
        # Check for null cipher or weak encryption
        for event in events:
            msg = event.get('message', '')
            if re.search(r'cipher.*(?:null|none|0x0|EEA0|NEA0)', msg, re.IGNORECASE):
                anomalies.append("Weak/null cipher detected in radio connection (security risk)")
                break
        
        # Check for 2G fallback (potential downgrade attack)
        gsm_events = [e for e in events if re.search(r'GSM|GPRS|EDGE', e.get('message', ''), re.IGNORECASE)]
        if len(gsm_events) > 0:
            has_4g_5g = any(re.search(r'LTE|NR|5G', e.get('message', ''), re.IGNORECASE) for e in events)
            if has_4g_5g:
                anomalies.append(f"2G fallback detected ({len(gsm_events)} events) — possible downgrade from LTE/NR")
        
        # Check for IMSI catcher indicators
        imsi_catcher_indicators = 0
        for event in events:
            msg = event.get('message', '')
            # Unusual LAC/CID patterns
            if re.search(r'LAC.*0x0+[1-9a-fA-F]|CID.*0xFFFFFFFF', msg):
                imsi_catcher_indicators += 1
            # Absence of encryption
            if re.search(r'no.*cipher|unencrypted|NO_CIPHERING', msg, re.IGNORECASE):
                imsi_catcher_indicators += 1
        if imsi_catcher_indicators >= 3:
            anomalies.append("Potential IMSI catcher/stingray indicators detected")
        
        # Check for 5G NR-specific anomalies
        nr_events = [e for e in events if re.search(r'NR|5G_NR|nrState', e.get('message', ''), re.IGNORECASE)]
        bwp_switch_count = sum(1 for e in nr_events if re.search(r'BWP.*switch|bandwidth.*part', e.get('message', ''), re.IGNORECASE))
        if bwp_switch_count > 20:
            anomalies.append(f"High BWP switching frequency: {bwp_switch_count} (5G bandwidth part reconfiguration)")
        
        return anomalies

    @staticmethod
    def build_signal_timeline(events: List[Dict]) -> List[Dict]:
        """Build a timeline of signal strength measurements."""
        timeline = []
        
        for event in events:
            msg = event.get('message', '')
            
            # Extract signal measurements
            rsrp_match = re.search(r'(?:rsrp|RSRP)[=:\s]*(-?\d+)', msg)
            rsrq_match = re.search(r'(?:rsrq|RSRQ)[=:\s]*(-?\d+)', msg)
            rssi_match = re.search(r'(?:rssi|RSSI)[=:\s]*(-?\d+)', msg)
            sinr_match = re.search(r'(?:sinr|SINR)[=:\s]*(-?\d+\.?\d*)', msg)
            dbm_match = re.search(r'(-?\d{2,3})\s*dBm', msg)
            
            if any([rsrp_match, rsrq_match, rssi_match, sinr_match, dbm_match]):
                point = {
                    'timestamp': event.get('timestamp', ''),
                    'rsrp': int(rsrp_match.group(1)) if rsrp_match else None,
                    'rsrq': int(rsrq_match.group(1)) if rsrq_match else None,
                    'rssi': int(rssi_match.group(1)) if rssi_match else None,
                    'sinr': float(sinr_match.group(1)) if sinr_match else None,
                    'dbm': int(dbm_match.group(1)) if dbm_match else None,
                }
                timeline.append(point)
        
        return timeline

    @staticmethod
    def parse_neighbor_cells(telephony_dump: str) -> List[NeighborCell]:
        """Parse neighbor cell information from telephony registry dump."""
        neighbors = []
        
        # Look for neighbor cell sections
        # Pattern varies by Android version, look for cell info arrays
        cell_info_blocks = re.split(r'CellInfo\w*\[|cell-info|CellInfo', telephony_dump)
        
        for block in cell_info_blocks:
            nc = NeighborCell()
            
            # Technology
            if 'LteCell' in block or 'CellInfoLte' in block:
                nc.technology = 'LTE'
            elif 'NrCell' in block or 'CellInfoNr' in block:
                nc.technology = 'NR'
            elif 'WcdmaCell' in block or 'CellInfoWcdma' in block:
                nc.technology = 'WCDMA'
            elif 'GsmCell' in block or 'CellInfoGsm' in block:
                nc.technology = 'GSM'
            else:
                continue
            
            # PCI
            pci_match = re.search(r'(?:pci|physicalCellId)[=:\s]*(\d{1,4})', block)
            if pci_match:
                nc.pci = int(pci_match.group(1))
            
            # ARFCN
            arfcn_match = re.search(r'(?:arfcn|uarfcn|earfcn)[=:\s]*(\d+)', block)
            if arfcn_match:
                nc.arfcn = int(arfcn_match.group(1))
            
            # Signal
            rsrp_match = re.search(r'(?:rsrp)[=:\s]*(-?\d+)', block)
            if rsrp_match:
                nc.signal_dbm = int(rsrp_match.group(1))
            else:
                rssi_match = re.search(r'(?:rssi|signalStrength)[=:\s]*(-?\d+)', block)
                if rssi_match:
                    nc.signal_dbm = int(rssi_match.group(1))
            
            neighbors.append(nc)
        
        return neighbors

    def generate_forensic_report(self, device_id: str, events: List[Dict],
                                  radio_state: Any, telephony_dump: str,
                                  logcat_output: str) -> RadioForensicReport:
        """Generate a comprehensive forensic report from all collected data."""
        report = RadioForensicReport(
            device_id=device_id,
            analysis_time=datetime.now().isoformat(),
        )
        
        # Extract cell history
        report.cell_history = self.extract_cell_history(events)
        
        # Parse neighbor cells
        report.neighbor_cells = self.parse_neighbor_cells(telephony_dump)
        
        # Build signal timeline
        report.signal_timeline = self.build_signal_timeline(events)
        
        # Detect anomalies
        report.anomalies = self.detect_anomalies(events, radio_state)
        
        # Build current serving cell from radio state
        if radio_state:
            report.current_serving_cell = CellRecord(
                timestamp=datetime.now().isoformat(),
                mcc=radio_state.mcc,
                mnc=radio_state.mnc,
                lac_tac=int(radio_state.lac_tac, 16) if radio_state.lac_tac and all(c in '0123456789ABCDEFabcdef' for c in radio_state.lac_tac) else 0,
                cell_id=int(radio_state.cell_id, 16) if radio_state.cell_id and all(c in '0123456789ABCDEFabcdef' for c in radio_state.cell_id) else 0,
                pci=int(radio_state.pci) if radio_state.pci else 0,
                technology=radio_state.radio_technology,
                band=radio_state.band,
                arfcn=int(radio_state.arfcn) if radio_state.arfcn and radio_state.arfcn.isdigit() else 0,
                signal_dbm=radio_state.signal_dbm,
                signal_asu=radio_state.signal_asu,
                is_serving=True,
                is_registered=True,
            )
            
            if radio_state.is_sa or radio_state.is_nsa:
                report.current_nr_cell = NRCellRecord(
                    timestamp=datetime.now().isoformat(),
                    mcc=radio_state.mcc,
                    mnc=radio_state.mnc,
                    nr_arfcn=int(radio_state.nr_arfcn) if radio_state.nr_arfcn and radio_state.nr_arfcn.isdigit() else 0,
                    pci=int(radio_state.pci) if radio_state.pci else 0,
                    is_nsa=radio_state.is_nsa,
                    is_sa=radio_state.is_sa,
                )
        
        # Analyze registration changes
        for event in events:
            if event.get('event_type') in ('network_state_change', 'cell_info_update'):
                report.registration_changes.append({
                    'timestamp': event.get('timestamp', ''),
                    'message': event.get('message', ''),
                    'event_type': event.get('event_type', ''),
                })
        
        report.raw_analysis = {
            'total_events': len(events),
            'categories': {},
            'event_types': {},
        }
        
        for event in events:
            cat = event.get('category', 'other')
            etype = event.get('event_type', 'unknown')
            report.raw_analysis['categories'][cat] = report.raw_analysis['categories'].get(cat, 0) + 1
            report.raw_analysis['event_types'][etype] = report.raw_analysis['event_types'].get(etype, 0) + 1
        
        return report