"""
Cell Tower Mapper Module
=========================
Maps detected cell towers and generates geolocation data.
Uses MCC/MNC/Cell ID for tower identification and
OpenCelliD-style mapping.
"""

import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import math


@dataclass
class TowerRecord:
    """A record of a detected cell tower."""
    mcc: str = ""
    mnc: str = ""
    lac: int = 0
    cell_id: int = 0
    enb_gnb_id: str = ""
    pci: int = 0
    technology: str = ""
    band: str = ""
    arfcn: int = 0
    signal_dbm: int = 0
    signal_quality: str = ""
    first_seen: str = ""
    last_seen: str = ""
    observation_count: int = 0
    is_serving: bool = False
    estimated_distance_m: float = 0.0
    location_hint: str = ""


@dataclass
class TowerMap:
    """Collection of all detected cell towers."""
    device_id: str = ""
    generated_at: str = ""
    towers: List[TowerRecord] = field(default_factory=list)
    total_towers: int = 0
    unique_cells: int = 0
    technologies_detected: List[str] = field(default_factory=list)
    coverage_area_km2: float = 0.0


class CellTowerMapper:
    """
    Maps and analyzes detected cell towers for forensic purposes.
    """

    # Signal quality mapping based on RSRP (dBm)
    @staticmethod
    def classify_signal_quality(rsrp_dbm: int) -> str:
        """Classify signal quality based on RSRP value."""
        if rsrp_dbm >= -80:
            return "Excellent"
        elif rsrp_dbm >= -90:
            return "Good"
        elif rsrp_dbm >= -100:
            return "Fair"
        elif rsrp_dbm >= -110:
            return "Poor"
        elif rsrp_dbm >= -120:
            return "Very Poor"
        else:
            return "No Signal"

    @staticmethod
    def estimate_distance(signal_dbm: int, technology: str, 
                           frequency_mhz: float = 1800) -> float:
        """
        Estimate distance to cell tower using free-space path loss.
        This is a rough approximation for forensic mapping.
        """
        if signal_dbm >= 0:
            return 0.0
        
        # Typical EIRP values
        if technology in ('NR', '5G NR (SA)', '5G NR (NSA)'):
            tx_power = 46  # dBm for 5G
        elif technology == 'LTE':
            tx_power = 43  # dBm for LTE
        elif technology in ('WCDMA', '3G (WCDMA/UMTS)'):
            tx_power = 43
        else:  # GSM
            tx_power = 43
        
        # Path loss
        path_loss = tx_power - abs(signal_dbm)
        
        # Free-space path loss: FSPL = 20*log10(d) + 20*log10(f) + 32.45
        # d = 10^((FSPL - 20*log10(f) - 32.45) / 20)
        try:
            log_f = 20 * math.log10(frequency_mhz)
            distance_km = 10 ** ((path_loss - log_f - 32.45) / 20)
            return distance_km * 1000  # Convert to meters
        except (ValueError, OverflowError):
            return 0.0

    @staticmethod
    def generate_tower_fingerprint(tower: TowerRecord) -> str:
        """Generate a unique fingerprint for a cell tower."""
        data = f"{tower.mcc}-{tower.mnc}-{tower.lac}-{tower.cell_id}-{tower.pci}-{tower.technology}"
        return hashlib.md5(data.encode()).hexdigest()[:16]

    def map_towers(self, device_id: str, cell_history: List[Any],
                    radio_state: Any, telephony_dump: str) -> TowerMap:
        """
        Build a comprehensive cell tower map from all collected data.
        """
        tower_map = TowerMap(
            device_id=device_id,
            generated_at=datetime.now().isoformat(),
        )
        
        seen_towers = {}  # fingerprint -> TowerRecord
        
        # Process cell history
        for cell in cell_history:
            tr = TowerRecord(
                mcc=getattr(cell, 'mcc', ''),
                mnc=getattr(cell, 'mnc', ''),
                lac=getattr(cell, 'lac_tac', 0),
                cell_id=getattr(cell, 'cell_id', 0),
                pci=getattr(cell, 'pci', 0),
                technology=getattr(cell, 'technology', ''),
                arfcn=getattr(cell, 'arfcn', 0),
                signal_dbm=getattr(cell, 'signal_dbm', 0),
                first_seen=getattr(cell, 'timestamp', ''),
                last_seen=getattr(cell, 'timestamp', ''),
                observation_count=1,
                is_serving=getattr(cell, 'is_serving', False),
            )
            
            tr.signal_quality = self.classify_signal_quality(tr.signal_dbm)
            
            # Estimate distance
            freq = 1800  # default
            if tr.arfcn:
                if tr.technology == 'NR':
                    freq = 3500 if tr.arfcn > 500000 else 2100
                elif tr.technology == 'LTE':
                    freq = 1800
            
            tr.estimated_distance_m = self.estimate_distance(
                tr.signal_dbm, tr.technology, freq
            )
            
            fingerprint = self.generate_tower_fingerprint(tr)
            
            if fingerprint in seen_towers:
                existing = seen_towers[fingerprint]
                existing.observation_count += 1
                existing.last_seen = tr.last_seen
                # Update signal if better
                if tr.signal_dbm > existing.signal_dbm:
                    existing.signal_dbm = tr.signal_dbm
                    existing.signal_quality = tr.signal_quality
            else:
                seen_towers[fingerprint] = tr
        
        # Add current serving cell
        if radio_state:
            tr = TowerRecord(
                mcc=radio_state.mcc,
                mnc=radio_state.mnc,
                lac=int(radio_state.lac_tac, 16) if radio_state.lac_tac and all(
                    c in '0123456789ABCDEFabcdef' for c in radio_state.lac_tac) else 0,
                cell_id=int(radio_state.cell_id, 16) if radio_state.cell_id and all(
                    c in '0123456789ABCDEFabcdef' for c in radio_state.cell_id) else 0,
                enb_gnb_id=radio_state.enb_gnb_id,
                pci=int(radio_state.pci) if radio_state.pci and radio_state.pci.isdigit() else 0,
                technology=radio_state.radio_technology,
                band=radio_state.band,
                arfcn=int(radio_state.arfcn) if radio_state.arfcn and radio_state.arfcn.isdigit() else 0,
                signal_dbm=radio_state.signal_dbm,
                is_serving=True,
                observation_count=1,
            )
            tr.signal_quality = self.classify_signal_quality(tr.signal_dbm)
            tr.first_seen = datetime.now().isoformat()
            tr.last_seen = tr.first_seen
            
            fingerprint = self.generate_tower_fingerprint(tr)
            if fingerprint not in seen_towers:
                seen_towers[fingerprint] = tr
            else:
                seen_towers[fingerprint].is_serving = True
        
        # Also extract from telephony dump for additional towers
        cell_pattern = re.finditer(
            r'CellInfo\w*\[.*?(?:mcc|MCC)[=:\s]*(\d{3}).*?(?:mnc|MNC)[=:\s]*(\d{2,3}).*?'
            r'(?:ci|cellId|CellId)[=:\s]*(\d+).*?(?:tac|lac|TAC|LAC)[=:\s]*(\d+)',
            telephony_dump
        )
        
        for match in cell_pattern:
            mcc, mnc, ci, lac = match.groups()
            
            tr = TowerRecord(
                mcc=mcc, mnc=mnc,
                cell_id=int(ci), lac=int(lac),
                technology='Unknown',
            )
            
            # Determine technology from context
            context = telephony_dump[match.start():match.end()+500]
            if 'Lte' in context or 'LTE' in context:
                tr.technology = 'LTE'
            elif 'Nr' in context or 'NR' in context:
                tr.technology = 'NR'
            elif 'Wcdma' in context or 'WCDMA' in context:
                tr.technology = 'WCDMA'
            elif 'Gsm' in context or 'GSM' in context:
                tr.technology = 'GSM'
            
            fingerprint = self.generate_tower_fingerprint(tr)
            if fingerprint not in seen_towers:
                tr.observation_count = 1
                seen_towers[fingerprint] = tr
        
        tower_map.towers = list(seen_towers.values())
        tower_map.total_towers = len(tower_map.towers)
        tower_map.unique_cells = len(set(
            (t.mcc, t.mnc, t.cell_id) for t in tower_map.towers
        ))
        
        # Detect technologies
        techs = set(t.technology for t in tower_map.towers if t.technology)
        tower_map.technologies_detected = list(techs)
        
        # Rough coverage area estimate
        distances = [t.estimated_distance_m for t in tower_map.towers if t.estimated_distance_m > 0]
        if distances:
            tower_map.coverage_area_km2 = math.pi * (max(distances) / 1000) ** 2
        return tower_map

    def generate_geojson(self, tower_map: TowerMap) -> Dict[str, Any]:
        """
        Generate a GeoJSON representation of detected towers.
        Note: Precise locations require OpenCelliD or similar database lookup.
        This provides the structure for visualization.
        """
        features = []
        
        for i, tower in enumerate(tower_map.towers):
            # Use placeholder coordinates based on tower data
            # In production, these would be resolved via a cell database
            feature = {
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    # Placeholder: use cell_id-based pseudo coordinates for visualization
                    "coordinates": [
                        float(tower.cell_id % 360 - 180),  # pseudo-lon
                        float((tower.mcc or "0").zfill(3)[:2] + 
                              (tower.mnc or "0").zfill(2))[:2].ljust(2, '0')[-2:]  # pseudo-lat placeholder
                    ]
                },
                "properties": {
                    "id": i,
                    "fingerprint": self.generate_tower_fingerprint(tower),
                    "mcc": tower.mcc,
                    "mnc": tower.mnc,
                    "lac": tower.lac,
                    "cell_id": tower.cell_id,
                    "pci": tower.pci,
                    "technology": tower.technology,
                    "band": tower.band,
                    "arfcn": tower.arfcn,
                    "signal_dbm": tower.signal_dbm,
                    "signal_quality": tower.signal_quality,
                    "estimated_distance_m": round(tower.estimated_distance_m, 1),
                    "is_serving": tower.is_serving,
                    "observation_count": tower.observation_count,
                }
            }
            features.append(feature)
        
        return {
            "type": "FeatureCollection",
            "features": features
        }
