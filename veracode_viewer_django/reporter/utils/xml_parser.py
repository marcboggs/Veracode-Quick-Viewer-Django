import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)

# Namespaces for Veracode detailed report XML
NS = {'v': 'https://www.veracode.com/schema/reports/export/1.0'}

def parse_detailed_report_xml(xml_data_string):
    """
    Parses the detailed report XML string from Veracode.
    Args:
        xml_data_string (str): The XML data as a string.
    Returns:
        tuple: A tuple containing two lists: (flaws, sca_components)
               Returns ([], []) if parsing fails or no data.
    """
    try:
        # Ensure that xml_data_string is bytes for ET.fromstring
        if isinstance(xml_data_string, str):
            xml_data_bytes = xml_data_string.encode("utf-8")
        else:
            xml_data_bytes = xml_data_string # Assuming it might already be bytes

        root = ET.fromstring(xml_data_bytes)
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML: {e}. Input (first 500 chars): {xml_data_string[:500]}")
        return [], []
    except Exception as e: # Catch other potential errors during initial parsing (e.g. if not string or bytes)
        logger.error(f"An unexpected error occurred during XML parsing setup: {e}")
        return [], []

    flaws, sca_components = [], []

    # Extract static flaws
    for severity in root.findall('.//v:severity', NS):
        severity_level = severity.get('level', 'Unknown')
        for category in severity.findall('v:category', NS):
            category_name = category.get('categoryname', 'Unknown')
            for cwe in category.findall('v:cwe', NS):
                cwe_id = cwe.get('cweid', 'N/A')
                cwe_name = cwe.get('cwename', 'Unknown')
                static_flaws_element = cwe.find('v:staticflaws', NS)
                if static_flaws_element is not None:
                    for flaw in static_flaws_element.findall('v:flaw', NS):
                        flaws.append({
                            'ID': flaw.get('issueid', ''),
                            'Severity': severity_level,
                            'CWE': f"{cwe_id} - {cwe_name}", # Combining CWE ID and name as in original
                            'Category': category_name,
                            'File': flaw.get('sourcefile', ''),
                            'Line': flaw.get('line', ''),
                            'Function': flaw.get('functionprototype', ''),
                            'Status': flaw.get('remediation_status', ''),
                            'Module': flaw.get('module', ''),
                            'Description': flaw.get('description', ''), # As in original script
                            'grace_period_expires': flaw.get('grace_period_expires', '') # As in original
                        })

    # Extract SCA components
    # Original script path: './/v:software_composition_analysis/v:component'
    sca_results_element = root.find('v:software_composition_analysis', NS)
    if sca_results_element is not None:
        for comp in sca_results_element.findall('v:component', NS):
            sca_components.append({
                'Component': comp.get('component_name', ''),
                'Version': comp.get('version', ''),
                'CPE': comp.get('cpe', ''), # Common Platform Enumeration
                'Vendor': comp.get('vendor', ''),
                'Description': comp.get('description', ''), # Or 'library' as per some schemas
                # Add other relevant SCA fields if needed, e.g., licenses, vulnerabilities
                'Licenses': [{'name': lic.get('name'), 'url': lic.get('license_url')} for lic in comp.findall('.//v:license', NS)],
                'Vulnerabilities': [{'cveid': vuln.get('cveid'), 'severity': vuln.get('severity')} for vuln in comp.findall('.//v:vulnerability', NS)]
            })

    # Add extraction for policy compliance and report metadata if needed
    # For example:
    # report_format_version = root.get('report_format_version')
    # app_name = root.get('app_name')
    # policy_name = root.get('policy_name')
    # policy_compliance_status = root.get('policy_compliance_status')
    # etc.

    return flaws, sca_components
