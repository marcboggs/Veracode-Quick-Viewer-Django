from datetime import datetime, timedelta
from collections import Counter
import xml.etree.ElementTree as ET # Needed for generate_compliance_data
import logging

logger = logging.getLogger(__name__)

def parse_date(date_str):
    """
    Safely parses a date string in YYYY-MM-DD format.
    Returns a datetime object or None if parsing fails.
    """
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        try: # Try with Z timezone info
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            logger.warning(f"Could not parse date string: {date_str}")
            return None

def generate_summary_data(flaws, sca_components):
    """
    Generates summary data from flaws and SCA components.
    Args:
        flaws (list): A list of static flaw dictionaries.
        sca_components (list): A list of SCA component dictionaries.
    Returns:
        dict: A dictionary containing summary information.
    """
    if flaws is None: flaws = []
    if sca_components is None: sca_components = []

    summary = {}

    static_open = [f for f in flaws if f.get('Status', '').lower() in ("open", "new", "reopen")]
    summary['total_static_open'] = len(static_open)

    summary['severity_breakdown'] = Counter(f.get('Severity') for f in static_open)
    summary['cwe_breakdown'] = Counter(f.get('CWE') for f in static_open)
    summary['category_breakdown'] = Counter(f.get('Category') for f in static_open)

    summary['total_sca_components'] = len(sca_components)
    summary['sca_vendor_breakdown'] = Counter(c.get('Vendor') for c in sca_components if c.get('Vendor'))

    # Helper for formatting bar charts in templates if needed, or do it in template
    # def bar_data(count, total, width=20):
    #     proportion = count / total if total else 0
    #     bars = int(proportion * width)
    #     return {'bars': bars, 'empty_bars': width - bars, 'count': count, 'proportion_percent': f"{proportion:.0%}"}
    # summary['severity_bars'] = {
    #    sev: bar_data(count, summary['total_static_open']) for sev, count in summary['severity_breakdown'].items()
    # }
    return summary

def generate_compliance_data(flaws, raw_xml_string, sca_components):
    """
    Generates compliance data based on flaws, SCA components, and report generation date.
    Args:
        flaws (list): A list of static flaw dictionaries.
        raw_xml_string (str): The raw XML report as a string.
        sca_components (list): A list of SCA component dictionaries.
    Returns:
        dict: A dictionary containing compliance status and reasons.
    """
    if flaws is None: flaws = []
    if sca_components is None: sca_components = []

    compliance_info = {
        'generation_date_valid': False,
        'generation_date': None,
        'scan_within_30_days': False,
        'no_expired_findings': True,
        'expired_finding_reasons': [],
        'no_open_high_critical': True,
        'high_critical_reasons': [],
        'no_high_critical_sca_vulns': True,
        'high_critical_sca_reasons': [],
        'messages': []
    }

    generation_date_dt = None
    try:
        if isinstance(raw_xml_string, str):
            raw_xml_bytes = raw_xml_string.encode("utf-8")
        else:
            raw_xml_bytes = raw_xml_string # Assuming it's bytes

        root = ET.fromstring(raw_xml_bytes)
        # Try to get generation_date from various possible attributes
        possible_date_attrs = ['generation_date', 'report_date', 'last_completed_date']
        gen_date_str = None
        for attr in possible_date_attrs:
            gen_date_str = root.get(attr)
            if gen_date_str:
                break

        generation_date_dt = parse_date(gen_date_str)
        compliance_info['generation_date'] = gen_date_str # Store the string version

        if generation_date_dt:
            compliance_info['generation_date_valid'] = True
            if generation_date_dt >= datetime.utcnow() - timedelta(days=30):
                compliance_info['scan_within_30_days'] = True
                compliance_info['messages'].append(f"✅ Last scan on {generation_date_dt.date()} (within 30 days)")
            else:
                compliance_info['messages'].append(f"❌ Last scan was on {generation_date_dt.date()} (>30 days ago)")
        else:
            compliance_info['messages'].append("❌ Missing or invalid generation_date in XML.")

    except ET.ParseError as e:
        logger.error(f"Failed to parse XML for compliance generation_date: {e}")
        compliance_info['messages'].append("❌ Error parsing report XML for scan date.")
    except Exception as e:
        logger.error(f"Unexpected error getting generation_date for compliance: {e}")
        compliance_info['messages'].append("❌ Unexpected error processing report scan date.")


    now = datetime.utcnow()
    for flaw in flaws:
        status = flaw.get('Status', '').lower()
        severity = flaw.get('Severity') # Assuming severity is string like "5", "4"
        grace_period_str = flaw.get('grace_period_expires', '')
        grace_period_dt = parse_date(grace_period_str)

        if status in ("open", "new", "reopen"):
            if severity in ("5", "4"): # Veracode severity: 5=Very High, 4=High
                compliance_info['no_open_high_critical'] = False
                compliance_info['high_critical_reasons'].append(f"Finding {flaw.get('ID')} (Severity {severity})")

            if grace_period_dt and grace_period_dt < now:
                compliance_info['no_expired_findings'] = False
                compliance_info['expired_finding_reasons'].append(f"Finding {flaw.get('ID')} expired on {grace_period_dt.date()}")

    if compliance_info['no_expired_findings']:
        compliance_info['messages'].append("✅ No expired open findings.")
    else:
        compliance_info['messages'].append("\n❌ There are open findings with expired grace periods:")
        compliance_info['messages'].extend([f"  - {reason}" for reason in compliance_info['expired_finding_reasons']])

    if compliance_info['no_open_high_critical']:
        compliance_info['messages'].append("✅ No open severity 4 or 5 findings.")
    else:
        compliance_info['messages'].append("\n❌ Open findings with severity 4 or 5 exist:")
        compliance_info['messages'].extend([f"  - {reason}" for reason in compliance_info['high_critical_reasons']])

    # SCA Compliance Checks
    high_critical_severities_text = ["HIGH", "CRITICAL"]
    high_critical_severities_numeric = ["4", "5"]

    for component in sca_components:
        component_id = component.get('component_id', 'Unknown Component') # Or 'name', 'ref', etc.
        version = component.get('version', '')
        component_display = f"{component_id}:{version}" if version else component_id

        vulnerabilities = component.get('vulnerabilities', [])
        if not isinstance(vulnerabilities, list): # Ensure vulnerabilities is iterable
            logger.warning(f"Vulnerabilities for component {component_display} is not a list, skipping.")
            continue

        for vuln in vulnerabilities:
            severity = str(vuln.get('severity', '')).upper() # Convert to string and uppercase
            cve = vuln.get('cve', {}).get('cve_id', 'N/A')
            cvss_score = vuln.get('cvss_score', 'N/A') # Or severity from Veracode's perspective

            is_high_critical = False
            if severity in high_critical_severities_text:
                is_high_critical = True
            elif severity in high_critical_severities_numeric: # Check numeric strings like "4", "5"
                is_high_critical = True

            if is_high_critical:
                compliance_info['no_high_critical_sca_vulns'] = False
                reason = f"Component '{component_display}' has {str(vuln.get('severity', '')).upper()} vulnerability '{cve}' (Severity: {cvss_score})"
                compliance_info['high_critical_sca_reasons'].append(reason)

    if compliance_info['no_high_critical_sca_vulns']:
        compliance_info['messages'].append("✅ No SCA components with High or Critical severity vulnerabilities found.")
    else:
        compliance_info['messages'].append("\n❌ SCA components with High or Critical severity vulnerabilities found:")
        compliance_info['messages'].extend([f"  - {reason}" for reason in compliance_info['high_critical_sca_reasons']])

    return compliance_info
