"""
Mobile Cellular Baseband & 5G Network Boundary Forensics
========================================================
ADB Interface Module - Handles all Android Debug Bridge communication
for forensic data extraction from Android devices.
"""

import subprocess
import re
import os
import sys
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass


@dataclass
class DeviceInfo:
    """Represents a connected Android device."""
    serial: str
    model: str = ""
    manufacturer: str = ""
    android_version: str = ""
    sdk_version: str = ""
    baseband_version: str = ""
    build_fingerprint: str = ""
    security_patch: str = ""
    state: str = "unknown"


@dataclass
class RadioState:
    """Current radio/cellular state of the device."""
    radio_technology: str = ""
    network_type: str = ""
    data_state: str = ""
    voice_state: str = ""
    signal_dbm: int = 0
    signal_asu: int = 0
    signal_level: int = 0
    mcc: str = ""
    mnc: str = ""
    operator_name: str = ""
    lac_tac: str = ""
    cell_id: str = ""
    pci: str = ""
    band: str = ""
    channel: str = ""
    bandwidth: str = ""
    arfcn: str = ""
    nr_arfcn: str = ""
    scs: str = ""
    is_nsa: bool = False
    is_sa: bool = False
    enb_gnb_id: str = ""
    raw_dump: str = ""


class ADBInterface:
    """Interface for communicating with Android devices via ADB."""

    def __init__(self, adb_path: str = "adb"):
        self.adb = adb_path
        self._device_serial: Optional[str] = None
        self._last_error: str = ""

    def check_adb_available(self) -> bool:
        """Check if ADB is installed and accessible."""
        try:
            result = subprocess.run(
                [self.adb, "version"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            self._last_error = str(e)
            return False

    def list_devices(self) -> List[DeviceInfo]:
        """List all connected Android devices with details."""
        devices = []
        try:
            result = subprocess.run(
                [self.adb, "devices", "-l"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.strip()
            if not output:
                return devices
            
            lines = output.splitlines()
            if len(lines) <= 1:
                return devices
            
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                serial = parts[0]
                state = parts[1]
                device = DeviceInfo(serial=serial, state=state)
                
                # Parse device flags (-l mode)
                for part in parts[2:]:
                    if part.startswith("model:"):
                        device.model = part.split(":", 1)[1]
                    elif part.startswith("device:"):
                        pass  # device codename
                    elif part.startswith("product:"):
                        pass
                    elif part.startswith("transport_id:"):
                        pass
                
                # Fetch properties if device is online
                if state == "device":
                    self._device_serial = serial
                    try:
                        device.model = self._get_prop("ro.product.model") or device.model
                    except Exception:
                        pass
                    try:
                        device.manufacturer = self._get_prop("ro.product.manufacturer") or ""
                    except Exception:
                        pass
                    try:
                        device.android_version = self._get_prop("ro.build.version.release") or ""
                    except Exception:
                        pass
                    try:
                        device.baseband_version = self._get_prop("gsm.version.baseband") or ""
                    except Exception:
                        pass
                
                devices.append(device)
                self._device_serial = None
            
            self._last_error = ""
            return devices
        
        except subprocess.TimeoutExpired:
            self._last_error = "ADB command timed out"
            return []
        except OSError as e:
            self._last_error = f"OS error: {e}"
            return []
        except Exception as e:
            self._last_error = f"Unexpected: {e}"
            return []

    def get_last_error(self) -> str:
        return self._last_error

    def connect_wireless(self, ip_address: str, port: int = 5555) -> Tuple[bool, str]:
        """Connect to a device over TCP/IP (ADB over WiFi)."""
        try:
            target = f"{ip_address}:{port}"
            result = subprocess.run(
                [self.adb, "connect", target],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout + result.stderr
            success = "connected" in output.lower() or "already" in output.lower()
            return success, output.strip()
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, str(e)

    def disconnect_wireless(self, ip_address: str, port: int = 5555) -> str:
        """Disconnect a wireless ADB connection."""
        try:
            result = subprocess.run(
                [self.adb, "disconnect", f"{ip_address}:{port}"],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, OSError) as e:
            return str(e)

    def set_device(self, serial: str):
        """Set the target device serial for subsequent commands."""
        self._device_serial = serial

    def _adb_cmd(self, *args, use_shell: bool = False, timeout: int = 30) -> Tuple[int, str, str]:
        """Execute an ADB command with optional target device."""
        cmd = [self.adb]
        if self._device_serial:
            cmd.extend(["-s", self._device_serial])
        if use_shell:
            cmd.append("shell")
        cmd.extend(args)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except OSError as e:
            return -1, "", f"Command failed: {e}"

    def shell(self, command: str, timeout: int = 30) -> Tuple[int, str, str]:
        """Execute a shell command on the device."""
        return self._adb_cmd("shell", command, timeout=timeout)

    def _get_prop(self, prop_name: str) -> Optional[str]:
        """Get a system property from the device."""
        _, stdout, _ = self.shell(f"getprop {prop_name}", timeout=10)
        value = stdout.strip() if stdout else ""
        return value if value else None

    # =========================================================================
    # RADIO DATA COLLECTION
    # =========================================================================

    def get_radio_dump(self) -> str:
        rc, stdout, _ = self.shell("dumpsys telephony.registry 2>/dev/null", timeout=30)
        if rc == 0 and stdout and stdout.strip():
            return stdout
        rc, stdout, _ = self.shell("dumpsys radio 2>/dev/null", timeout=30)
        if rc == 0 and stdout and stdout.strip():
            return stdout
        all_parts = []
        for name, cmd in [
            ("connectivity", "dumpsys connectivity 2>/dev/null"),
            ("phone", "dumpsys phone 2>/dev/null"),
        ]:
            _, out, _ = self.shell(cmd, timeout=15)
            if out and out.strip():
                all_parts.append("=== " + name + " ===\n" + out)
        return "\n\n".join(all_parts) if all_parts else ""

    def get_telephony_dump(self) -> str:
        rc, stdout, _ = self.shell("dumpsys telephony.registry 2>/dev/null", timeout=30)
        if rc == 0 and stdout and stdout.strip():
            return stdout
        _, stdout, _ = self.shell("dumpsys phone 2>/dev/null", timeout=30)
        return stdout.strip()

    def get_phone_service_dump(self) -> str:
        _, stdout, _ = self.shell("dumpsys phone 2>/dev/null", timeout=30)
        return stdout

    def get_connectivity_dump(self) -> str:
        _, stdout, _ = self.shell("dumpsys connectivity 2>/dev/null", timeout=30)
        return stdout

    def get_service_list(self) -> str:
        _, stdout, _ = self.shell("service list 2>/dev/null", timeout=15)
        if not stdout or not stdout.strip():
            _, stdout, _ = self.shell("dumpsys -l 2>/dev/null", timeout=15)
        return stdout

    def get_baseband_logs(self, lines: int = 5000) -> str:
        for buf in ["radio", "main", "all"]:
            _, stdout, _ = self.shell(
                f"logcat -d -b {buf} -t '{lines}' 2>/dev/null", timeout=30
            )
            if stdout.strip():
                return stdout
        return ""

    def get_modem_logs(self, lines: int = 2000) -> str:
        for buf in ["radio", "all"]:
            _, stdout, _ = self.shell(
                f"logcat -d -b {buf} -t '{lines}' 2>/dev/null", timeout=30
            )
            if stdout.strip():
                return stdout
        return ""

    def get_sim_info(self) -> Dict[str, Any]:
        sim_data = {}
        _, telephony_dump, _ = self.shell("dumpsys telephony.registry 2>/dev/null", timeout=20)
        if not telephony_dump.strip():
            _, telephony_dump, _ = self.shell("dumpsys phone 2>/dev/null", timeout=20)
        
        iccid_match = re.findall(r"""iccid[=:\s]*['"]?(\d{10,22})['"]?""", telephony_dump, re.IGNORECASE)
        sim_data['iccids'] = list(set(iccid_match))
        
        imsi_match = re.findall(r"""imsi[=:\s]*['"]?(\d{10,16})['"]?""", telephony_dump, re.IGNORECASE)
        sim_data['imsis'] = list(set(imsi_match))
        
        _, operator_info, _ = self.shell(
            "dumpsys telephony.registry 2>/dev/null | grep -iE 'mcc|mnc|operator|carrier'",
            timeout=15
        )
        if not operator_info or not operator_info.strip():
            _, operator_info, _ = self.shell(
                "dumpsys phone 2>/dev/null | grep -iE 'mcc|mnc|operator|carrier'", timeout=15
            )
        sim_data['operator_raw'] = operator_info
        return sim_data

    def get_network_interfaces(self) -> str:
        _, stdout, _ = self.shell("ip addr show 2>/dev/null || ifconfig 2>/dev/null", timeout=10)
        return stdout

    def get_diag_ports(self) -> List[str]:
        diag_ports = []
        _, stdout, _ = self.shell(
            "ls /dev/diag 2>/dev/null; ls /dev/ttyUSB* 2>/dev/null; "
            "ls /dev/smd* 2>/dev/null; ls /dev/ttyHS* 2>/dev/null",
            timeout=10
        )
        for line in stdout.strip().splitlines():
            line = line.strip()
            if line:
                diag_ports.append(line)
        return diag_ports

    def check_root(self) -> bool:
        _, stdout, _ = self.shell("which su 2>/dev/null; id 2>/dev/null", timeout=5)
        return "root" in stdout.lower() or "/su" in stdout

    def get_radio_hal_version(self) -> str:
        _, stdout, _ = self.shell(
            "service check radio 2>/dev/null; lshal list 2>/dev/null | grep -i radio",
            timeout=10
        )
        return stdout.strip()


def parse_radio_state(dump: str) -> RadioState:
    """Parse radio dump output into a structured RadioState."""
    state = RadioState()
    state.raw_dump = dump[:5000]

    # Network Type Detection
    if re.search(r"NR|nrState.*CONNECTED|5G|NR_NSA|nrAvailable.*true", dump, re.IGNORECASE):
        if re.search(r"nrState.*CONNECTED|NRState.*CONNECTED|NR_SA", dump, re.IGNORECASE):
            state.is_sa = True
            state.network_type = "5G NR (SA)"
            state.radio_technology = "NR"
        else:
            state.is_nsa = True
            state.network_type = "5G NR (NSA)"
            state.radio_technology = "LTE/NR"
    elif re.search(r"LTE|lteState|dataRegState.*LTE", dump, re.IGNORECASE):
        state.network_type = "4G LTE"
        state.radio_technology = "LTE"
    elif re.search(r"WCDMA|UMTS|HSPA|HSUPA|HSDPA", dump, re.IGNORECASE):
        state.network_type = "3G (WCDMA/UMTS)"
        state.radio_technology = "WCDMA"
    elif re.search(r"GSM|GPRS|EDGE", dump, re.IGNORECASE):
        state.network_type = "2G (GSM/GPRS/EDGE)"
        state.radio_technology = "GSM"

    # Data/Voice State
    data_match = re.search(r"dataRegState[=:]\s*(\w+)", dump, re.IGNORECASE)
    if data_match:
        state.data_state = data_match.group(1)
    voice_match = re.search(r"voiceRegState[=:]\s*(\w+)", dump, re.IGNORECASE)
    if voice_match:
        state.voice_state = voice_match.group(1)

    # Signal Strength
    dbm_val = None
    ss_match = re.search(r"SignalStrength\s*[({](.*?)[)}]", dump, re.DOTALL)
    ss_text = ss_match.group(1) if ss_match else dump

    for pattern in [
        r"rsrp[=:\s]*(-?\d{2,3})",
        r"(-?\d{2,3})\s*dBm",
        r"rssi[=:\s]*(-?\d{2,3})",
        r"(?:mSignalStrength|signal)[=:\s]*(-?\d{2,3})",
    ]:
        m = re.search(pattern, ss_text, re.IGNORECASE)
        if m:
            dbm_val = int(m.group(1))
            break

    if dbm_val is None:
        gsm_m = re.search(r"gsmSignalStrength[=:\s]*(\d{1,2})", ss_text, re.IGNORECASE)
        if gsm_m:
            asu_val = int(gsm_m.group(1))
            if 0 <= asu_val <= 31:
                dbm_val = -113 + 2 * asu_val

    if dbm_val is not None:
        state.signal_dbm = dbm_val

    asu_match = re.search(r"asu[=:\s]*(\d+)", dump, re.IGNORECASE)
    if asu_match:
        state.signal_asu = int(asu_match.group(1))

    level_match = re.search(r"(?:level|mLevel)[=:\s]*(\d)", dump, re.IGNORECASE)
    if level_match:
        state.signal_level = int(level_match.group(1))

    # MCC/MNC
    mcc_match = re.search(r"""mcc[=:\s]*['"]?(\d{3})['"]?""", dump, re.IGNORECASE)
    if mcc_match:
        state.mcc = mcc_match.group(1)
    mnc_match = re.search(r"""mnc[=:\s]*['"]?(\d{2,3})['"]?""", dump, re.IGNORECASE)
    if mnc_match:
        state.mnc = mnc_match.group(1)

    # Operator
    operator_matches = re.findall(
        r"""(?:operatorAlpha(?:Long|Short)?|networkName|mNetworkName)[=:\s]*['"]?([^\s'",\]}]+)""",
        dump, re.IGNORECASE
    )
    for match in operator_matches:
        if match and not match.isdigit() and len(match) > 1:
            state.operator_name = match
            break

    # LAC/TAC
    lac_match = re.search(
        r"""(?:lac|tac|trackingAreaCode)[=:\s]*['"]?([0-9a-fA-F]{1,8})['"]?""", dump, re.IGNORECASE
    )
    if lac_match:
        state.lac_tac = lac_match.group(1).upper()

    # Cell ID
    ci_match = re.search(
        r"""(?:ci|cellIdentity|cellId|getCid)[=:\s]*['"]?([0-9a-fA-F]{1,16})['"]?""", dump, re.IGNORECASE
    )
    if ci_match:
        state.cell_id = ci_match.group(1).upper()

    # PCI
    pci_match = re.search(r"(?:pci|physicalCellId|physCellId)[=:\s]*(\d{1,4})", dump, re.IGNORECASE)
    if pci_match:
        try:
            pci_val = int(pci_match.group(1))
            if 0 <= pci_val <= 1007:
                state.pci = str(pci_val)
        except ValueError:
            pass

    # Band
    band_match = re.search(r"""(?:band|freqBand|bandIndicator|mBand)[=:\s]*['"]?(\d{1,3})['"]?""", dump, re.IGNORECASE)
    if band_match:
        state.band = band_match.group(1)

    # ARFCN
    arfcn_match = re.search(r"(?:arfcn|uarfcn|earfcn|channelNumber|mArfcn)[=:\s]*(\d+)", dump, re.IGNORECASE)
    if arfcn_match:
        state.arfcn = arfcn_match.group(1)
        state.channel = arfcn_match.group(1)

    # NR-ARFCN
    nr_arfcn_match = re.search(r"(?:nrArfcn|nrarfcn|nr_arfcn|NRARFCN|mNrArfcn)[=:\s]*(\d+)", dump, re.IGNORECASE)
    if nr_arfcn_match:
        state.nr_arfcn = nr_arfcn_match.group(1)

    # SCS
    scs_match = re.search(r"(?:scs|subCarrierSpacing|subcarrierSpacing|mScs)[=:\s]*(\d+)", dump, re.IGNORECASE)
    if scs_match:
        state.scs = scs_match.group(1) + " kHz"

    # Bandwidth
    bw_match = re.search(r"(?:bandwidth|channelBW|carrierBandwidth|mBandwidth)[=:\s]*(\d+)", dump, re.IGNORECASE)
    if bw_match:
        bw_val = int(bw_match.group(1))
        state.bandwidth = f"{bw_val} MHz" if bw_val <= 400 else f"{bw_val // 1000} MHz"

    # eNB/gNB ID
    enb_match = re.search(
        r"""(?:eNB[_\s-]?[iI]d|gnbId|gNB[_\s-]?[iI]d|mEnbId)[=:\s]*['"]?([0-9a-fA-F]{1,20})['"]?""",
        dump, re.IGNORECASE
    )
    if enb_match:
        state.enb_gnb_id = enb_match.group(1).upper()

    return state
