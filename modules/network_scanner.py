"""
5G Network Boundary Forensics Scanner
======================================
Dedicated 5G NR (New Radio) network analysis module.
Handles NSA/SA mode detection, beam management analysis,
network slicing detection, and 5G-specific measurements.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import math


@dataclass
class NRCell:
    """5G NR cell information."""
    nr_arfcn: int = 0
    pci: int = 0
    mcc: str = ""
    mnc: str = ""
    tac: int = 0
    nci: int = 0  # NR Cell Identity (36 bits)
    gnb_id: str = ""
    cell_id: str = ""
    band: int = 0
    scs: int = 0  # Subcarrier Spacing in kHz
    bandwidth: int = 0  # In MHz
    ssb_frequency: float = 0.0  # SSB center frequency in MHz
    ss_rsrp: int = 0
    ss_rsrq: int = 0
    ss_sinr: int = 0
    csi_rsrp: int = 0
    csi_rsrq: int = 0
    csi_sinr: int = 0
    beam_index: int = 0
    is_current: bool = False
    connection_mode: str = ""  # NSA or SA
    duplex_mode: str = ""  # FDD or TDD
    frequency_range: str = ""  # FR1 or FR2 (mmWave)


@dataclass
class NRNetworkAnalysis:
    """Comprehensive 5G NR network analysis report."""
    serving_cell: Optional[NRCell] = None
    neighbor_nr_cells: List[NRCell] = field(default_factory=list)
    detected_bands: List[int] = field(default_factory=list)
    is_nsa_active: bool = False
    is_sa_active: bool = False
    endc_supported: bool = False
    carrier_aggregation: List[Dict] = field(default_factory=list)
    beam_measurements: List[Dict] = field(default_factory=list)
    network_slicing_indicators: List[str] = field(default_factory=list)
    mobility_history: List[Dict] = field(default_factory=list)
    throughput_estimation: Dict[str, Any] = field(default_factory=dict)
    analysis_notes: List[str] = field(default_factory=list)


class NRNetworkForensics:
    """
    Specialized 5G NR network forensic analyzer.
    """

    # NR-ARFCN to frequency mapping (simplified reference table)
    # NR-ARFCN range: 0-3279165 for FR1 (0-3000 MHz), 0-3279165 for FR2
    @staticmethod
    def nr_arfcn_to_frequency(nr_arfcn: int, band: int = 0) -> float:
        """
        Convert NR-ARFCN to approximate center frequency in MHz.
        Based on 3GPP TS 38.104.
        """
        if nr_arfcn == 0:
            return 0.0
        
        # FR1: 0 - 3000 MHz, NR-ARFCN 0 - 599999
        if nr_arfcn <= 599999:
            # Global frequency raster: F_REF = F_REF-Offs + ΔF_Global * (N_REF – N_REF-Offs)
            # Simplified for common bands
            if 600000 <= nr_arfcn <= 1999999:
                # n77/n78/n79 range (3.3-5.0 GHz)
                return 3000.0 + (nr_arfcn - 600000) * 0.015
            return nr_arfcn * 0.005  # ~5 kHz per ARFCN step (very rough)
        else:
            # FR2: 24250 - 52600 MHz
            return 24250.08 + (nr_arfcn - 2016667) * 0.06

    @staticmethod
    def frequency_to_band(freq_mhz: float) -> int:
        """Approximate NR band from frequency."""
        # Band definitions (simplified)
        bands = [
            (1, 2100, 2110, 2170), (2, 1900, 1930, 1990),
            (3, 1800, 1805, 1880), (5, 850, 869, 894),
            (7, 2600, 2620, 2690), (8, 900, 925, 960),
            (12, 700, 729, 746), (20, 800, 791, 821),
            (25, 1900, 1930, 1995), (28, 700, 758, 803),
            (38, 2600, 2570, 2620), (40, 2300, 2300, 2400),
            (41, 2500, 2496, 2690), (66, 1700, 2110, 2200),
            (71, 600, 617, 652), (77, 3700, 3300, 4200),
            (78, 3500, 3300, 3800), (79, 4700, 4400, 5000),
            (257, 28000, 26500, 29500), (258, 26000, 24250, 27500),
            (260, 39000, 37000, 40000), (261, 28000, 27500, 28350),
        ]
        
        for band_num, _, low, high in bands:
            if low <= freq_mhz <= high:
                return band_num
        
        if freq_mhz < 1000:
            return 71  # Low band
        elif freq_mhz < 2700:
            return 7  # Mid band
        elif freq_mhz < 5000:
            return 78  # C-band
        else:
            return 257  # mmWave

    @staticmethod
    def parse_nr_cell_info(telephony_dump: str) -> List[NRCell]:
        """Parse 5G NR cell information from telephony dump."""
        nr_cells = []
        
        # Find NR cell info blocks
        nr_blocks = re.split(r'(?:NrCellInfo|CellInfoNr|NR\s*Cell)', telephony_dump)
        
        for block in nr_blocks[1:]:  # Skip first split
            cell = NRCell()
            
            # NR-ARFCN
            nrarfcn_match = re.search(r'(?:nrarfcn|nrArfcn|NRARFCN)[=:\s]*(\d+)', block)
            if nrarfcn_match:
                cell.nr_arfcn = int(nrarfcn_match.group(1))
            
            # PCI
            pci_match = re.search(r'(?:pci|physicalCellId)[=:\s]*(\d{1,4})', block)
            if pci_match:
                cell.pci = int(pci_match.group(1))
            
            # TAC
            tac_match = re.search(r'(?:tac|trackingAreaCode)[=:\s]*(\d+)', block)
            if tac_match:
                cell.tac = int(tac_match.group(1))
            
            # NCI (NR Cell Identity)
            nci_match = re.search(r'(?:nci|nrCellId|cellIdentity)[=:\s]*(\d+)', block)
            if nci_match:
                nci = int(nci_match.group(1))
                cell.nci = nci
                # gNB ID is typically the first 22-32 bits of NCI
                cell.gnb_id = str(nci >> 4)  # Assuming 4-bit cell ID part
                cell.cell_id = str(nci & 0xF)
            
            # Band
            band_match = re.search(r'(?:band|nrBand|freqBand)[=:\s]*(\d+)', block)
            if band_match:
                cell.band = int(band_match.group(1))
            
            # SCS
            scs_match = re.search(r'(?:scs|subCarrierSpacing|numerology)[=:\s]*(\d+)', block)
            if scs_match:
                cell.scs = int(scs_match.group(1))
            
            # Bandwidth
            bw_match = re.search(r'(?:bandwidth|channelBW|carrierBandwidth)[=:\s]*(\d+)', block)
            if bw_match:
                bw = int(bw_match.group(1))
                cell.bandwidth = bw if bw < 400 else bw // 1000  # Convert kHz to MHz
            
            # SS-RSRP
            ss_rsrp_match = re.search(r'(?:ssRsrp|ss-rsrp|SS-RSRP)[=:\s]*(-?\d+)', block)
            if ss_rsrp_match:
                cell.ss_rsrp = int(ss_rsrp_match.group(1))
            
            # SS-RSRQ
            ss_rsrq_match = re.search(r'(?:ssRsrq|ss-rsrq|SS-RSRQ)[=:\s]*(-?\d+)', block)
            if ss_rsrq_match:
                cell.ss_rsrq = int(ss_rsrq_match.group(1))
            
            # SS-SINR
            ss_sinr_match = re.search(r'(?:ssSinr|ss-sinr|SS-SINR)[=:\s]*(-?\d+\.?\d*)', block)
            if ss_sinr_match:
                cell.ss_sinr = int(float(ss_sinr_match.group(1)))
            
            # CSI measurements
            csi_rsrp_match = re.search(r'(?:csiRsrp|csi-rsrp|CSI-RSRP)[=:\s]*(-?\d+)', block)
            if csi_rsrp_match:
                cell.csi_rsrp = int(csi_rsrp_match.group(1))
            
            csi_rsrq_match = re.search(r'(?:csiRsrq|csi-rsrq|CSI-RSRQ)[=:\s]*(-?\d+)', block)
            if csi_rsrq_match:
                cell.csi_rsrq = int(csi_rsrq_match.group(1))
            
            csi_sinr_match = re.search(r'(?:csiSinr|csi-sinr|CSI-SINR)[=:\s]*(-?\d+\.?\d*)', block)
            if csi_sinr_match:
                cell.csi_sinr = int(float(csi_sinr_match.group(1)))
            
            # Determine connection mode
            if re.search(r'nrState.*CONNECTED|NR_SA|sa.*mode', block, re.IGNORECASE):
                cell.connection_mode = "SA"
            elif re.search(r'(?:ENDC|NSA|nrDc|scg)', block, re.IGNORECASE):
                cell.connection_mode = "NSA"
            
            # Frequency range determination
            if cell.band >= 257 or cell.nr_arfcn > 2016667:
                cell.frequency_range = "FR2 (mmWave)"
            else:
                cell.frequency_range = "FR1 (sub-6 GHz)"
            
            # Determine if current/serving cell
            if re.search(r'(?:serving|registered|current|connected)', block, re.IGNORECASE):
                cell.is_current = True
            
            nr_cells.append(cell)
        
        return nr_cells

    @staticmethod
    def analyze_carrier_aggregation(telephony_dump: str, modem_logs: str) -> List[Dict]:
        """Analyze carrier aggregation configuration (5G NR CA and EN-DC)."""
        ca_combos = []
        
        # Look for CA config in telephony dump
        ca_patterns = re.findall(
            r'(?:ca-band|carrierAggregation|CA)[=:\s]*(\d+[A-Za-z]?(?:\+\d+[A-Za-z]?)*)',
            telephony_dump + " " + modem_logs
        )
        
        for combo in ca_patterns:
            bands = re.findall(r'(\d+)', combo)
            if len(bands) >= 2:
                ca_combos.append({
                    'combination': combo,
                    'bands': bands,
                    'num_carriers': len(bands),
                    'type': 'Intra-band' if all(b == bands[0] for b in bands) else 'Inter-band'
                })
        
        # Also look for EN-DC combinations (LTE anchor + NR)
        endc_patterns = re.findall(
            r'(?:endc|EN_DC)[=:\s]*(\d+[A-Za-z]?(?:_n?\d+[A-Za-z]?)*)',
            telephony_dump + " " + modem_logs, re.IGNORECASE
        )
        for combo in endc_patterns:
            parts = combo.split('_')
            ca_combos.append({
                'combination': f"EN-DC: {combo}",
                'bands': [p.lstrip('n') for p in parts if p],
                'num_carriers': len([p for p in parts if p]),
                'type': 'EN-DC (NSA)'
            })
        
        return ca_combos

    @staticmethod
    def detect_network_slicing(telephony_dump: str, modem_logs: str) -> List[str]:
        """Detect indicators of 5G network slicing."""
        indicators = []
        combined = telephony_dump + " " + modem_logs
        
        # NSSAI - Network Slice Selection Assistance Information
        # SST (Slice/Service Type) values:
        # 1 = eMBB, 2 = URLLC, 3 = MIoT, 4 = V2X
        sst_match = re.findall(r'(?:sst|SST|slice.*type)[=:\s]*(\d+)', combined, re.IGNORECASE)
        for sst in sst_match:
            sst_val = int(sst)
            if sst_val == 1:
                indicators.append("Slice SST=1: eMBB (Enhanced Mobile Broadband)")
            elif sst_val == 2:
                indicators.append("Slice SST=2: URLLC (Ultra-Reliable Low-Latency)")
            elif sst_val == 3:
                indicators.append("Slice SST=3: MIoT (Massive IoT)")
            elif sst_val == 4:
                indicators.append("Slice SST=4: V2X (Vehicle-to-Everything)")
        
        # SD (Slice Differentiator)
        sd_match = re.findall(r'(?:sd|slice.*differentiator|SD)[=:\s]*([0-9A-Fa-f]{6})', combined, re.IGNORECASE)
        for sd in sd_match:
            indicators.append(f"Slice SD: {sd.upper()}")
        
        # NSSAI sets
        nssai_match = re.findall(r'(?:nssai|NSSAI|allowedNssai|configuredNssai)[=:\[\s]*([^\]]+)', combined, re.IGNORECASE)
        for nssai in nssai_match:
            indicators.append(f"NSSAI detected: {nssai.strip()}")
        
        if not indicators:
            # Check for 5G core indicators
            if re.search(r'5GC|5G_CN|NGC', combined, re.IGNORECASE):
                indicators.append("5G Core (5GC) connectivity detected (network slicing ready)")
        
        return indicators

    def estimate_throughput(self, nr_cell: NRCell) -> Dict[str, Any]:
        """
        Estimate theoretical throughput based on 5G NR cell parameters.
        Based on 3GPP TS 38.306.
        """
        if not nr_cell.bandwidth or not nr_cell.scs:
            return {'estimated_dl_mbps': 0, 'estimated_ul_mbps': 0, 'note': 'Insufficient data'}
        
        # Calculate number of PRBs
        scs_to_prb = {
            15: {5: 25, 10: 52, 15: 79, 20: 106, 25: 133, 30: 160, 40: 216, 50: 270},
            30: {5: 11, 10: 24, 15: 38, 20: 51, 25: 65, 30: 78, 40: 106, 50: 133, 60: 162, 80: 217, 100: 273},
            60: {10: 11, 15: 18, 20: 24, 25: 31, 30: 38, 40: 51, 50: 65, 60: 79, 80: 107, 100: 135},
            120: {50: 32, 100: 66, 200: 132, 400: 264},
        }
        
        scs_map = scs_to_prb.get(nr_cell.scs, {})
        closest_bw = min(scs_map.keys(), key=lambda x: abs(x - nr_cell.bandwidth))
        num_prbs = scs_map.get(closest_bw, 0)
        
        if num_prbs == 0:
            return {'estimated_dl_mbps': 0, 'estimated_ul_mbps': 0, 'note': 'Could not map bandwidth to PRBs'}
        
        # Assume 256QAM, 4x4 MIMO (typical for 5G)
        spectral_efficiency = 7.4  # bits/s/Hz for 256QAM at good SINR
        num_layers = 4  # 4x4 MIMO
        overhead = 0.14  # 14% overhead
        
        # Subcarriers per PRB
        sc_per_prb = 12
        symbols_per_slot = 14  # 14 OFDM symbols per slot (normal CP)
        slots_per_second = 1000 * nr_cell.scs / 15  # Slots per second based on numerology
        
        # Data RE per PRB per slot
        data_re_per_prb = sc_per_prb * symbols_per_slot * (1 - overhead)
        
        # DL throughput
        dl_throughput = num_prbs * data_re_per_prb * spectral_efficiency * num_layers * slots_per_second / 1e6
        
        # UL throughput (assume 2 layers, 64QAM)
        ul_spectral_efficiency = 5.5
        ul_layers = 2
        ul_throughput = num_prbs * data_re_per_prb * ul_spectral_efficiency * ul_layers * slots_per_second / 1e6
        
        return {
            'estimated_dl_mbps': round(dl_throughput, 1),
            'estimated_ul_mbps': round(ul_throughput, 1),
            'num_prbs': num_prbs,
            'scs_khz': nr_cell.scs,
            'bandwidth_mhz': nr_cell.bandwidth,
            'num_layers_dl': num_layers,
            'modulation': '256QAM (DL) / 64QAM (UL)',
            'note': 'Theoretical maximum estimate'
        }

    def analyze_5g_network(self, telephony_dump: str, radio_dump: str,
                            modem_logs: str, radio_state: Any) -> NRNetworkAnalysis:
        """Perform comprehensive 5G NR network analysis."""
        analysis = NRNetworkAnalysis()
        
        # Parse NR cell info
        nr_cells = self.parse_nr_cell_info(telephony_dump + "\n" + radio_dump)
        
        # Identify serving cell
        serving_cells = [c for c in nr_cells if c.is_current]
        if serving_cells:
            analysis.serving_cell = serving_cells[0]
        elif nr_cells:
            analysis.serving_cell = nr_cells[0]
            analysis.serving_cell.is_current = True
        
        # Neighbor cells
        analysis.neighbor_nr_cells = [c for c in nr_cells if not c.is_current]
        
        # Detect bands
        analysis.detected_bands = list(set(c.band for c in nr_cells if c.band > 0))
        
        # NSA/SA detection
        analysis.is_nsa_active = radio_state.is_nsa if radio_state else False
        analysis.is_sa_active = radio_state.is_sa if radio_state else False
        
        if not analysis.is_nsa_active and not analysis.is_sa_active:
            # Check from dump
            if re.search(r'nrState.*CONNECTED|nrAvailable.*true|ENDC|NR_NSA', 
                        telephony_dump, re.IGNORECASE):
                analysis.is_nsa_active = True
            if re.search(r'NR_SA|5G_SA|nr.*standalone', 
                        telephony_dump, re.IGNORECASE):
                analysis.is_sa_active = True
        
        # EN-DC support
        analysis.endc_supported = bool(
            re.search(r'ENDC|endc.*supported|nr.*endc', 
                     telephony_dump + " " + radio_dump, re.IGNORECASE)
        )
        
        # Carrier aggregation analysis
        analysis.carrier_aggregation = self.analyze_carrier_aggregation(
            telephony_dump, modem_logs
        )
        
        # Network slicing detection
        analysis.network_slicing_indicators = self.detect_network_slicing(
            telephony_dump, modem_logs
        )
        
        # Throughput estimation for serving cell
        if analysis.serving_cell:
            analysis.throughput_estimation = self.estimate_throughput(analysis.serving_cell)
        
        # Analysis notes
        if analysis.is_sa_active:
            analysis.analysis_notes.append("5G Standalone (SA) mode active — direct 5GC connectivity")
        if analysis.is_nsa_active:
            analysis.analysis_notes.append("5G Non-Standalone (NSA) mode — anchored on LTE EPC")
        if analysis.carrier_aggregation:
            analysis.analysis_notes.append(
                f"Carrier aggregation active with {len(analysis.carrier_aggregation)} combination(s)"
            )
        if analysis.network_slicing_indicators:
            analysis.analysis_notes.append(
                f"Network slicing detected — {len(analysis.network_slicing_indicators)} indicator(s)"
            )
        if analysis.detected_bands:
            analysis.analysis_notes.append(f"NR bands detected: {analysis.detected_bands}")
        
        return analysis
