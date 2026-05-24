"""
SIM/USIM Forensics Module
==========================
Forensic analysis of SIM/USIM/eSIM card artifacts.
Extracts identifiers, operator data, and security state.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SIMInfo:
    """Structured SIM card information."""
    iccid: str = ""
    imsi: str = ""
    mcc: str = ""
    mnc: str = ""
    msin: str = ""
    operator_name: str = ""
    operator_country: str = ""
    sim_state: str = ""
    sim_type: str = ""  # SIM, USIM, eSIM, CSIM, ISIM
    phone_number: str = ""
    gid1: str = ""
    gid2: str = ""
    spn: str = ""  # Service Provider Name
    msisdn: str = ""
    authentication_state: str = ""
    is_roaming: bool = False
    home_mcc: str = ""
    home_mnc: str = ""
    imei: str = ""
    imei_sv: str = ""
    pin_retries_left: int = -1
    puk_retries_left: int = -1
    card_issuer: str = ""
    profile_class: str = ""
    ef_dir_files: List[str] = field(default_factory=list)
    atr: str = ""  # Answer to Reset (if available)


class SIMForensics:
    """
    Performs forensic analysis of SIM/USIM artifacts.
    """

    # MCC to Country mapping
    MCC_COUNTRY = {
        "001": "Test Network",
        "202": "Greece", "204": "Netherlands", "206": "Belgium",
        "208": "France", "212": "Monaco", "213": "Andorra",
        "214": "Spain", "216": "Hungary", "218": "Bosnia & Herzegovina",
        "219": "Croatia", "220": "Serbia", "222": "Italy",
        "225": "Vatican City", "226": "Romania", "228": "Switzerland",
        "230": "Czech Republic", "231": "Slovakia", "232": "Austria",
        "234": "United Kingdom", "235": "United Kingdom", "238": "Denmark",
        "240": "Sweden", "242": "Norway", "244": "Finland",
        "246": "Lithuania", "247": "Latvia", "248": "Estonia",
        "250": "Russia", "255": "Ukraine", "257": "Belarus",
        "259": "Moldova", "260": "Poland", "262": "Germany",
        "266": "Gibraltar", "268": "Portugal", "270": "Luxembourg",
        "272": "Ireland", "274": "Iceland", "276": "Albania",
        "278": "Malta", "280": "Cyprus", "282": "Georgia",
        "283": "Armenia", "284": "Bulgaria", "286": "Turkey",
        "288": "Faroe Islands", "290": "Greenland", "292": "San Marino",
        "293": "Slovenia", "294": "Macedonia", "295": "Liechtenstein",
        "297": "Montenegro", "302": "Canada", "308": "Saint Pierre & Miquelon",
        "310": "United States", "311": "United States", "312": "United States",
        "313": "United States", "314": "United States", "315": "United States",
        "316": "United States", "330": "Puerto Rico", "332": "US Virgin Islands",
        "334": "Mexico", "338": "Jamaica", "340": "French Guiana",
        "342": "Barbados", "344": "Antigua & Barbuda", "346": "Cayman Islands",
        "348": "British Virgin Islands", "350": "Bermuda", "352": "Grenada",
        "354": "Montserrat", "356": "Saint Kitts & Nevis", "358": "Saint Lucia",
        "360": "Saint Vincent & Grenadines", "362": "Netherlands Antilles",
        "363": "Aruba", "364": "Bahamas", "365": "Anguilla",
        "366": "Dominica", "368": "Cuba", "370": "Dominican Republic",
        "372": "Haiti", "374": "Trinidad & Tobago", "376": "Turks & Caicos",
        "400": "Azerbaijan", "401": "Kazakhstan", "402": "Bhutan",
        "404": "India", "405": "India", "406": "India",
        "410": "Pakistan", "412": "Afghanistan", "413": "Sri Lanka",
        "414": "Myanmar", "415": "Lebanon", "416": "Jordan",
        "417": "Syria", "418": "Iraq", "419": "Kuwait",
        "420": "Saudi Arabia", "421": "Yemen", "422": "Oman",
        "424": "UAE", "425": "Israel", "426": "Bahrain",
        "427": "Qatar", "428": "Mongolia", "429": "Nepal",
        "430": "UAE (Abu Dhabi)", "431": "UAE (Dubai)", "432": "Iran",
        "434": "Uzbekistan", "436": "Tajikistan", "437": "Kyrgyzstan",
        "438": "Turkmenistan", "440": "Japan", "441": "Japan",
        "450": "South Korea", "452": "Vietnam", "454": "Hong Kong",
        "455": "Macau", "456": "Cambodia", "457": "Laos",
        "460": "China", "461": "China", "466": "Taiwan",
        "467": "North Korea", "470": "Bangladesh", "472": "Maldives",
        "502": "Malaysia", "505": "Australia", "510": "Indonesia",
        "514": "Timor-Leste", "515": "Philippines", "520": "Thailand",
        "525": "Singapore", "528": "Brunei", "530": "New Zealand",
        "535": "Guam", "536": "Nauru", "537": "Papua New Guinea",
        "539": "Tonga", "540": "Solomon Islands", "541": "Vanuatu",
        "542": "Fiji", "543": "Wallis & Futuna", "544": "American Samoa",
        "545": "Kiribati", "546": "New Caledonia", "547": "French Polynesia",
        "548": "Cook Islands", "549": "Samoa", "550": "Micronesia",
        "551": "Marshall Islands", "552": "Palau", "553": "Tuvalu",
        "602": "Egypt", "603": "Algeria", "604": "Morocco",
        "605": "Tunisia", "606": "Libya", "607": "Gambia",
        "608": "Senegal", "609": "Mauritania", "610": "Mali",
        "611": "Guinea", "612": "Ivory Coast", "613": "Burkina Faso",
        "614": "Niger", "615": "Togo", "616": "Benin",
        "617": "Mauritius", "618": "Liberia", "619": "Sierra Leone",
        "620": "Ghana", "621": "Nigeria", "622": "Chad",
        "623": "Central African Republic", "624": "Cameroon", "625": "Cape Verde",
        "626": "São Tomé & Príncipe", "627": "Equatorial Guinea", "628": "Gabon",
        "629": "Congo (Brazzaville)", "630": "Congo (Kinshasa)", "631": "Angola",
        "632": "Guinea-Bissau", "633": "Seychelles", "634": "Sudan",
        "635": "Rwanda", "636": "Ethiopia", "637": "Somalia",
        "638": "Djibouti", "639": "Kenya", "640": "Tanzania",
        "641": "Uganda", "642": "Burundi", "643": "Mozambique",
        "645": "Zambia", "646": "Madagascar", "647": "Réunion",
        "648": "Zimbabwe", "649": "Namibia", "650": "Malawi",
        "651": "Lesotho", "652": "Botswana", "653": "Swaziland",
        "654": "Comoros", "655": "South Africa", "657": "Eritrea",
        "658": "Saint Helena", "659": "South Sudan",
        "702": "Belize", "704": "Guatemala", "706": "El Salvador",
        "708": "Honduras", "710": "Nicaragua", "712": "Costa Rica",
        "714": "Panama", "716": "Peru", "722": "Argentina",
        "724": "Brazil", "730": "Chile", "732": "Colombia",
        "734": "Venezuela", "736": "Bolivia", "738": "Guyana",
        "740": "Ecuador", "742": "French Guiana", "744": "Paraguay",
        "746": "Suriname", "748": "Uruguay",
        "901": "International (Satellite)", "902": "Global Mobile Satellite",
    }

    # Major ICCID issuer identification (first 2-3 digits)
    ICCID_ISSUERS = {
        "89": "Telecommunications",
        "8986": "China Mobile", "89860": "China Mobile",
        "898601": "China Unicom", "898602": "China Unicom",
        "898603": "China Telecom",
        "8901": "AT&T (USA)", "8914": "T-Mobile (USA)",
        "89148": "Verizon (USA)", "8930": "Sprint (USA)",
        "8944": "Vodafone (UK)", "8941": "EE (UK)", 
        "8942": "O2 (UK)", "8940": "Three (UK)",
        "8991": "Airtel (India)", "8999": "Jio (India)",
        "8995": "Vodafone Idea (India)", "8998": "BSNL (India)",
        "8922": "NTT Docomo (Japan)", "8920": "SoftBank (Japan)",
        "8921": "KDDI (Japan)",
        "8950": "SK Telecom (Korea)", "8952": "KT (Korea)",
        "8955": "LG U+ (Korea)",
        "8949": "Telenor", "8947": "Telia",
        "8934": "Telefonica / Movistar",
        "8962": "MTN Group", "8965": "Vodacom",
        "8970": "Etisalat",
    }

    @staticmethod
    def parse_iccid(iccid: str) -> Dict[str, str]:
        """
        Parse ICCID to extract issuer, country, and other details.
        ICCID format: MM CC II NN NNNNNNNNNN C
        MM = Major Industry Identifier (always 89 for telecom)
        CC = Country Code (2-3 digits)
        II = Issuer Identifier (1-4 digits)
        NN...N = Individual account number
        C = Luhn check digit
        """
        result = {
            'raw': iccid,
            'major_industry': '',
            'country_code': '',
            'issuer_code': '',
            'account_number': '',
            'check_digit': '',
            'issuer_name': '',
        }
        
        if len(iccid) < 6:
            return result
        
        result['major_industry'] = iccid[:2]
        result['check_digit'] = iccid[-1] if len(iccid) > 0 else ''
        
        # Try to identify issuer from prefix
        for prefix_len in [6, 5, 4, 3]:
            prefix = iccid[:prefix_len]
            if prefix in SIMForensics.ICCID_ISSUERS:
                result['issuer_name'] = SIMForensics.ICCID_ISSUERS[prefix]
                result['issuer_code'] = prefix
                break
        
        # If no specific issuer found, use telecom identifier
        if not result['issuer_name'] and iccid.startswith("89"):
            result['issuer_name'] = "Telecom (Generic)"
        
        # Country code is typically digits 3-4 or 3-5
        cc2 = iccid[2:4]
        cc3 = iccid[2:5]
        
        result['country_code'] = cc2
        result['account_number'] = iccid[4:-1] if len(iccid) > 5 else iccid[4:]
        
        return result

    @staticmethod
    def parse_imsi(imsi: str) -> Dict[str, str]:
        """
        Parse IMSI into MCC, MNC, and MSIN.
        IMSI format: MCC (3 digits) + MNC (2-3 digits) + MSIN (9-10 digits)
        """
        result = {
            'raw': imsi,
            'mcc': '',
            'mnc': '',
            'msin': '',
            'country': '',
        }
        
        if len(imsi) < 5:
            return result
        
        result['mcc'] = imsi[:3]
        
        # Look up country
        result['country'] = SIMForensics.MCC_COUNTRY.get(
            result['mcc'], 'Unknown'
        )
        
        # MNC is typically 2 or 3 digits
        # Try 3-digit MNC first
        if len(imsi) >= 6:
            mnc3 = imsi[3:6]
            result['mnc'] = mnc3
            result['msin'] = imsi[6:] if len(imsi) > 6 else ''
        else:
            result['mnc'] = imsi[3:5]
            result['msin'] = imsi[5:] if len(imsi) > 5 else ''
        
        return result

    def analyze_sim(self, sim_data: Dict[str, Any], 
                     telephony_dump: str, build_prop: str,
                     device_serial: str) -> List[SIMInfo]:
        """
        Perform comprehensive SIM card forensic analysis.
        Returns a list of SIMInfo objects (one per detected SIM slot).
        """
        sims = []
        
        iccids = sim_data.get('iccids', [])
        imsis = sim_data.get('imsis', [])
        operator_raw = sim_data.get('operator_raw', '')
        
        # If no data, try to extract from telephony dump directly
        if not iccids:
            iccid_matches = re.findall(r'iccid[=:\s]*[\'\"]?(\d{10,22})[\'\"]?', 
                                       telephony_dump, re.IGNORECASE)
            iccids = list(set(iccid_matches))
        
        if not imsis:
            imsi_matches = re.findall(r'imsi[=:\s]*[\'\"]?(\d{10,16})[\'\"]?', 
                                      telephony_dump, re.IGNORECASE)
            imsis = list(set(imsi_matches))
        
        # Process each ICCID/IMSI pair
        for i, iccid in enumerate(iccids):
            sim = SIMInfo()
            sim.iccid = iccid
            
            # Parse ICCID
            iccid_info = self.parse_iccid(iccid)
            if iccid_info.get('issuer_name'):
                sim.card_issuer = iccid_info['issuer_name']
            
            # Match IMSI if available
            if i < len(imsis):
                sim.imsi = imsis[i]
                imsi_info = self.parse_imsi(imsis[i])
                sim.mcc = imsi_info['mcc']
                sim.mnc = imsi_info['mnc']
                sim.msin = imsi_info['msin']
                sim.operator_country = imsi_info['country']
            elif imsis:
                sim.imsi = imsis[0]
                imsi_info = self.parse_imsi(imsis[0])
                sim.mcc = imsi_info['mcc']
                sim.mnc = imsi_info['mnc']
                sim.msin = imsi_info['msin']
                sim.operator_country = imsi_info['country']
            
            # Extract operator name from raw dump
            op_matches = re.findall(
                r'(?:operatorAlphaLong|operatorAlpha|networkName)[=:\s]*[\'\"]?([^\"\']+?)[\'\"]?[\s,\]]', 
                operator_raw, re.IGNORECASE
            )
            if op_matches:
                sim.operator_name = op_matches[0].strip()
            
            # SIM state
            state_match = re.search(r'(?:simState|getSimState)[=:\s]*[\'\"]?(\w+)[\'\"]?', 
                                    telephony_dump, re.IGNORECASE)
            if state_match:
                sim.sim_state = state_match.group(1)
            
            # Detect eSIM
            if re.search(r'(?:euicc|esim|eUICC|embedded.*sim)', 
                        telephony_dump, re.IGNORECASE):
                sim.sim_type = "eSIM"
            elif re.search(r'USIM|usim', telephony_dump):
                sim.sim_type = "USIM"
            else:
                sim.sim_type = "SIM"
            
            # Phone number/MSISDN
            msisdn_match = re.search(
                r'(?:msisdn|phoneNumber|line1Number|getLine1Number)[=:\s]*[\'\"]?(\+?\d{7,15})[\'\"]?',
                telephony_dump, re.IGNORECASE
            )
            if msisdn_match:
                sim.msisdn = msisdn_match.group(1)
            
            # GID1/GID2
            gid1_match = re.search(r'gid1[=:\s]*[\'\"]?([0-9A-Fa-f]+)[\'\"]?', 
                                   telephony_dump, re.IGNORECASE)
            if gid1_match:
                sim.gid1 = gid1_match.group(1)
            
            gid2_match = re.search(r'gid2[=:\s]*[\'\"]?([0-9A-Fa-f]+)[\'\"]?', 
                                   telephony_dump, re.IGNORECASE)
            if gid2_match:
                sim.gid2 = gid2_match.group(1)
            
            # SPN
            spn_match = re.search(r'(?:spn|serviceProviderName)[=:\s]*[\'\"]?([^\"\']+?)[\'\"]?', 
                                  telephony_dump, re.IGNORECASE)
            if spn_match:
                sim.spn = spn_match.group(1).strip()
            
            # IMEI
            imei_match = re.search(r'(?:imei|deviceId|getDeviceId)[=:\s]*[\'\"]?(\d{14,16})[\'\"]?', 
                                   telephony_dump, re.IGNORECASE)
            if imei_match:
                sim.imei = imei_match.group(1)
            
            # PIN/PUK retries
            pin_match = re.search(r'pinRetry[=:\s]*(\d+)', telephony_dump, re.IGNORECASE)
            if pin_match:
                sim.pin_retries_left = int(pin_match.group(1))
            
            puk_match = re.search(r'pukRetry[=:\s]*(\d+)', telephony_dump, re.IGNORECASE)
            if puk_match:
                sim.puk_retries_left = int(puk_match.group(1))
            
            # Roaming detection
            home_mcc_match = re.search(r'(?:homeMcc|simMcc)[=:\s]*[\'\"]?(\d{3})[\'\"]?', 
                                       telephony_dump, re.IGNORECASE)
            if home_mcc_match:
                sim.home_mcc = home_mcc_match.group(1)
                if sim.home_mcc != sim.mcc and sim.mcc:
                    sim.is_roaming = True
            
            # Authentication state
            auth_match = re.search(r'(?:auth|authentication)[=:\s]*(\w+)', 
                                   telephony_dump, re.IGNORECASE)
            if auth_match:
                sim.authentication_state = auth_match.group(1)
            
            sims.append(sim)
        
        # If we got IMSI without ICCID, still create an entry
        if not sims and imsis:
            sim = SIMInfo()
            sim.imsi = imsis[0]
            imsi_info = self.parse_imsi(imsis[0])
            sim.mcc = imsi_info['mcc']
            sim.mnc = imsi_info['mnc']
            sim.msin = imsi_info['msin']
            sim.operator_country = imsi_info['country']
            sims.append(sim)
        
        # If no SIM data at all, create empty entry
        if not sims:
            sims.append(SIMInfo(sim_state="No SIM detected"))
        
        return sims