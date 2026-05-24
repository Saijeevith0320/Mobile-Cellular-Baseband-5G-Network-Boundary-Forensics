"""
Baseband Analyzer Module
=========================
Deep-dive analysis of the cellular baseband processor.
Extracts firmware versions, security state, modem capabilities,
and performs integrity checks on the baseband subsystem.
"""

import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class BasebandInfo:
    """Comprehensive baseband processor information."""
    firmware_version: str = ""
    baseband_processor: str = ""
    modem_model: str = ""
    chipset_vendor: str = ""
    security_patch_date: str = ""
    ril_version: str = ""
    hal_version: str = ""
    supported_technologies: List[str] = field(default_factory=list)
    supported_bands: List[str] = field(default_factory=list)
    modem_firmware_hash: str = ""
    modem_build_id: str = ""
    imei_range: str = ""
    is_engineering_build: bool = False
    carrier_config: str = ""
    volte_supported: bool = False
    vowifi_supported: bool = False
    nr_nsa_supported: bool = False
    nr_sa_supported: bool = False
    modem_asserts: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)


@dataclass 
class BasebandSecurityAudit:
    """Security audit results for the baseband processor."""
    cve_count: int = 0
    known_cves: List[str] = field(default_factory=list)
    patch_level_days_old: int = 0
    root_access_detected: bool = False
    bootloader_unlocked: bool = False
    selinux_status: str = ""
    dm_verity_status: str = ""
    encryption_status: str = ""
    dangerous_services: List[str] = field(default_factory=list)
    exposed_interfaces: List[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "Unknown"


class BasebandAnalyzer:
    """
    Analyzes the cellular baseband processor for forensic artifacts
    and security posture assessment.
    """

    # Known baseband chipset identifiers
    CHIPSET_SIGNATURES = {
        'mdm': 'Qualcomm MDM-series',
        'msm': 'Qualcomm Snapdragon (MSM)',
        'sd': 'Qualcomm Snapdragon',
        'sm': 'Qualcomm Snapdragon (SM)',
        'exynos': 'Samsung Exynos',
        'shannon': 'Samsung Shannon',
        'mt': 'MediaTek (MT-series)',
        'helio': 'MediaTek Helio',
        'dimensity': 'MediaTek Dimensity',
        'kirin': 'HiSilicon Kirin',
        'balong': 'HiSilicon Balong',
        't': 'Unisoc/Tangula',
        'unisoc': 'Unisoc',
        'bcm': 'Broadcom',
    }

    # Known baseband CVE patterns to look for in firmware versions
    KNOWN_CVE_VERSIONS = {
        'Qualcomm': [
            ('CVE-2024-21458', r'(?:LA|AU)_\d+\.\d+\.\d+\.\d+'),
            ('CVE-2024-20673', r'MDM\d+.*(?:V\d+\.\d+)'),
            ('CVE-2024-0044', r'(?:BOOT|TZ)\.(?:X|A)\.\d+\.\d+'),
            ('CVE-2023-28577', r'HLOS\.\d+\.\d+'),
            ('CVE-2023-33042', r'MDM.*(?:2\.\d+\.\d+)'),
        ],
        'Samsung': [
            ('CVE-2024-20017', r'Shannon.*(?:5G|5123)'),
            ('CVE-2023-26074', r'S(?:5E|6E)\d+'),
        ],
        'MediaTek': [
            ('CVE-2024-20088', r'MTK.*R(?:2[12]|3[01])'),
            ('CVE-2023-32837', r'MT\d{4}'),
        ],
    }

    @staticmethod
    def identify_chipset(device_props: Dict[str, str], build_prop: str) -> Tuple[str, str, str]:
        """
        Identify the baseband chipset vendor, model, and processor
        from device properties.
        """
        vendor = "Unknown"
        processor = "Unknown"
        model = "Unknown"
        
        # Combine all sources
        all_text = build_prop + " " + " ".join(f"{k}={v}" for k, v in device_props.items())
        all_lower = all_text.lower()
        
        # Check for Qualcomm
        if any(x in all_lower for x in ['qualcomm', 'snapdragon', 'msm', 'mdm', 'qcom']):
            vendor = "Qualcomm"
            # Find specific model
            msm_match = re.search(r'(?:msm|mdm|sd|sm|qcm)(\d{3,4}[a-z]?)', all_lower)
            if msm_match:
                processor = msm_match.group(0).upper()
                model = processor
        
        # Check for Samsung Exynos/Shannon
        elif any(x in all_lower for x in ['exynos', 'shannon', 'samsung']):
            vendor = "Samsung"
            exy_match = re.search(r'(?:exynos|shannon)[\s-]*(\d{3,5}[a-z]?)', all_lower)
            if exy_match:
                processor = exy_match.group(0).upper()
                model = processor
        
        # Check for MediaTek
        elif any(x in all_lower for x in ['mediatek', 'mtk', 'helio', 'dimensity']):
            vendor = "MediaTek"
            mt_match = re.search(r'(?:mt|dimensity|helio)[\s-]*(\d{3,5}[a-z]?)', all_lower)
            if mt_match:
                processor = mt_match.group(0).upper()
                model = processor
        
        # Check for HiSilicon
        elif any(x in all_lower for x in ['hisilicon', 'kirin', 'balong']):
            vendor = "HiSilicon"
            kirin_match = re.search(r'(?:kirin|balong)[\s-]*(\d{3,5}[a-z]?)', all_lower)
            if kirin_match:
                processor = kirin_match.group(0).upper()
                model = processor
        
        # Check for Unisoc
        elif any(x in all_lower for x in ['unisoc', 'spreadtrum', 'sc983', 'sc9863', 't606', 't610', 't612', 't616', 't618', 't700', 't740', 't760', 't770', 't820']):
            vendor = "Unisoc"
        
        # Check for Intel (older devices)
        elif any(x in all_lower for x in ['intel', 'xmm', 'sofia']):
            vendor = "Intel"
        
        return vendor, processor, model

    def analyze_baseband(self, device_props: Dict[str, str], 
                          build_prop: str, radio_hal: str,
                          modem_logs: str, device_info: Any) -> BasebandInfo:
        """
        Perform comprehensive baseband analysis.
        """
        info = BasebandInfo()
        
        # Baseband firmware version
        info.firmware_version = device_props.get('gsm.version.baseband', 'Unknown')
        if not info.firmware_version or info.firmware_version == 'Unknown':
            info.firmware_version = device_props.get('ro.boot.baseband', 'Unknown')
        if not info.firmware_version or info.firmware_version == 'Unknown':
            info.firmware_version = device_props.get('ro.baseband', 'Unknown')
        
        # Identify chipset
        vendor, processor, model = self.identify_chipset(device_props, build_prop)
        info.chipset_vendor = vendor
        info.baseband_processor = processor
        info.modem_model = model
        
        # Security patch date
        info.security_patch_date = device_props.get('ro.build.version.security_patch', 'Unknown')
        
        # RIL version
        info.ril_version = device_props.get('ro.ril.version', 'Unknown')
        if info.ril_version == 'Unknown':
            info.ril_version = device_props.get('gsm.version.ril-impl', 'Unknown')
        
        # HAL version
        hal_match = re.search(r'(?:android\.hardware\.radio|IRadio)\s*@\s*(\d+\.\d+)', radio_hal)
        if hal_match:
            info.hal_version = hal_match.group(1)
        
        # Modem build ID
        info.modem_build_id = device_props.get('ro.bootimage.build.fingerprint', '')
        if not info.modem_build_id:
            info.modem_build_id = device_props.get('ro.modem.build.id', '')
        
        # Engineering build detection
        eng_indicators = ['eng', 'engineering', 'debug', 'test-keys', 'development']
        fingerprint = device_props.get('ro.build.fingerprint', '').lower()
        build_type = device_props.get('ro.build.type', '').lower()
        if any(ind in fingerprint for ind in eng_indicators) or build_type == 'eng':
            info.is_engineering_build = True
        
        # Detect supported technologies from modem logs
        for tech in ['NR', 'LTE', 'WCDMA', 'TD-SCDMA', 'GSM', 'CDMA', 'EVDO']:
            pattern = re.compile(rf'\b{tech}\b', re.IGNORECASE)
            if pattern.search(modem_logs) or pattern.search(build_prop):
                if tech not in info.supported_technologies:
                    info.supported_technologies.append(tech)
        
        # Check for VoLTE/VoWiFi
        info.volte_supported = bool(
            re.search(r'(?:volte|ims.*enabled|persist\.radio\.volte)', 
                     build_prop.lower(), re.IGNORECASE)
        )
        info.vowifi_supported = bool(
            re.search(r'(?:vowifi|wifi.*calling|persist\.radio\.vowifi)', 
                     build_prop.lower(), re.IGNORECASE)
        )
        
        # Check 5G capabilities
        info.nr_nsa_supported = bool(
            re.search(r'(?:nr|5g.*nsa|ENDC|nr_nsa|nr\.mode.*nsa)', 
                     build_prop.lower(), re.IGNORECASE)
        )
        info.nr_sa_supported = bool(
            re.search(r'(?:nr.*sa|5g.*sa|nr_sa|nr\.mode.*standalone)', 
                     build_prop.lower(), re.IGNORECASE)
        )
        
        # Extract IMEI range pattern
        imei_match = re.search(r'(?:imei|IMEI)[=:\s]*(\d{6,8})\d+', build_prop)
        if imei_match:
            info.imei_range = imei_match.group(1) + "XXXX"
        
        # Carrier config
        info.carrier_config = device_props.get('ro.carrier', 'Unknown')
        if info.carrier_config == 'Unknown':
            info.carrier_config = device_props.get('ro.com.google.clientidbase', 'Unknown')
        
        # Look for modem asserts/crashes
        assert_pattern = re.findall(
            r'(?:modem.*(?:crash|assert|fatal|error|panic|reset|subsys))[^.]*\.', 
            modem_logs, re.IGNORECASE
        )
        info.modem_asserts = assert_pattern[:20]  # Limit to 20
        
        # Security issues detection
        if info.is_engineering_build:
            info.security_issues.append("Engineering/debug build — reduced security hardening")
        
        if 'test-keys' in fingerprint:
            info.security_issues.append("Signed with test keys — not production signed")
        
        if vendor == 'Unknown' and info.firmware_version == 'Unknown':
            info.security_issues.append("Unable to identify baseband — potential hidden/fake baseband")
        
        return info

    def audit_security(self, device_props: Dict[str, str],
                        build_prop: str, service_list: str,
                        baseband_info: BasebandInfo,
                        is_rooted: bool) -> BasebandSecurityAudit:
        """
        Perform security audit of the baseband subsystem.
        """
        audit = BasebandSecurityAudit()
        
        # Root detection
        audit.root_access_detected = is_rooted
        
        # Bootloader status
        bl_status = device_props.get('ro.boot.verifiedbootstate', 'green')
        audit.bootloader_unlocked = bl_status.lower() in ('orange', 'yellow', 'unlocked', '')
        
        # SELinux
        audit.selinux_status = device_props.get('ro.build.selinux', 'Unknown')
        selinux_enforcing = device_props.get('ro.boot.selinux', 'permissive')
        if selinux_enforcing == 'permissive':
            audit.selinux_status += " (Permissive — security risk)"
        
        # DM-Verity
        audit.dm_verity_status = device_props.get('ro.boot.veritymode', 'Unknown')
        
        # Encryption
        audit.encryption_status = device_props.get('ro.crypto.state', 'Unknown')
        
        # Dangerous services
        dangerous_patterns = [
            r'diag_mdlog', r'qmi', r'netmgr', r'qmuxd', r'qrtr', 
            r'port-bridge', r'rmt_storage', r'tftp_server', r'dun',
            r'mobile_log_d', r'oemhook', r'gsiff',
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, service_list, re.IGNORECASE):
                audit.dangerous_services.append(pattern)
        
        # Exposed interfaces
        exposed_patterns = [
            r'/dev/diag', r'/dev/ttyUSB', r'/dev/smd', r'/dev/qmi',
            r'/dev/rmnet', r'/dev/rmnet_mhi',
        ]
        for pattern in exposed_patterns:
            if re.search(pattern, service_list, re.IGNORECASE):
                audit.exposed_interfaces.append(pattern)
        
        # Calculate patch age
        try:
            patch_date = datetime.strptime(baseband_info.security_patch_date, '%Y-%m-%d')
            days_old = (datetime.now() - patch_date).days
            audit.patch_level_days_old = days_old
        except (ValueError, TypeError):
            audit.patch_level_days_old = -1
        
        # Risk scoring
        risk_score = 0
        
        if audit.root_access_detected:
            risk_score += 25
        if audit.bootloader_unlocked:
            risk_score += 20
        if 'permissive' in audit.selinux_status.lower():
            risk_score += 30
        if audit.dm_verity_status.lower() in ('disabled', 'logging'):
            risk_score += 15
        if audit.encryption_status.lower() != 'encrypted':
            risk_score += 15
        if audit.patch_level_days_old > 180:
            risk_score += 15
        elif audit.patch_level_days_old > 90:
            risk_score += 10
        if baseband_info.is_engineering_build:
            risk_score += 20
        if audit.dangerous_services:
            risk_score += min(len(audit.dangerous_services) * 5, 20)
        if audit.exposed_interfaces:
            risk_score += min(len(audit.exposed_interfaces) * 5, 15)
        if baseband_info.security_issues:
            risk_score += min(len(baseband_info.security_issues) * 5, 15)
        
        audit.risk_score = min(risk_score, 100)
        
        if audit.risk_score >= 70:
            audit.risk_level = "CRITICAL"
        elif audit.risk_score >= 50:
            audit.risk_level = "HIGH"
        elif audit.risk_score >= 30:
            audit.risk_level = "MEDIUM"
        elif audit.risk_score >= 10:
            audit.risk_level = "LOW"
        else:
            audit.risk_level = "MINIMAL"
        
        return audit

    def generate_baseband_fingerprint(self, baseband_info: BasebandInfo,
                                       security_audit: BasebandSecurityAudit) -> str:
        """
        Generate a unique fingerprint of the baseband configuration
        for forensic comparison purposes.
        """
        fingerprint_data = (
            f"{baseband_info.chipset_vendor}|"
            f"{baseband_info.firmware_version}|"
            f"{baseband_info.security_patch_date}|"
            f"{baseband_info.ril_version}|"
            f"{baseband_info.hal_version}|"
            f"{baseband_info.modem_model}|"
            f"{security_audit.selinux_status}|"
            f"{security_audit.bootloader_unlocked}|"
        )
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:40]
