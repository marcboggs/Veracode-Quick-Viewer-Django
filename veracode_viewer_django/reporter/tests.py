from django.test import TestCase
from veracode_viewer_django.reporter.utils.report_utils import generate_compliance_data
from datetime import datetime, timedelta

class TestGenerateComplianceDataSCA(TestCase):
    def setUp(self):
        # Generate a date string for "today" for consistent XML generation_date
        self.today_date_str = datetime.utcnow().strftime("%Y-%m-%d")
        self.raw_xml_minimal = f'<detailedreport report_format_version="1.0" generation_date="{self.today_date_str}T10:00:00Z"></detailedreport>'
        self.flaws_empty = []

    def test_sca_no_components(self):
        """Test with no SCA components."""
        sca_components = []
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertTrue(result['no_high_critical_sca_vulns'])
        self.assertEqual(len(result['high_critical_sca_reasons']), 0)
        self.assertIn("✅ No SCA components with High or Critical severity vulnerabilities found.", result['messages'])

    def test_sca_no_vulnerabilities(self):
        """Test with SCA components that have no vulnerabilities listed."""
        sca_components = [
            {'component_id': 'TestLib1', 'version': '1.0', 'vulnerabilities': []},
            {'component_id': 'TestLib2', 'version': '2.1', 'vulnerabilities': []}
        ]
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertTrue(result['no_high_critical_sca_vulns'])
        self.assertEqual(len(result['high_critical_sca_reasons']), 0)
        self.assertIn("✅ No SCA components with High or Critical severity vulnerabilities found.", result['messages'])

    def test_sca_low_severity_vulnerabilities(self):
        """Test with SCA components having only low or medium severity vulnerabilities."""
        sca_components = [
            {'component_id': 'TestLibLow', 'version': '1.0', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-001'}, 'severity': 'Low', 'cvss_score': '3.0'},
                {'cve': {'cve_id': 'CVE-2023-002'}, 'severity': '2', 'cvss_score': '2.5'} # Medium by numeric
            ]},
            {'component_id': 'TestLibMed', 'version': '1.1', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-003'}, 'severity': 'Medium', 'cvss_score': '6.0'},
                {'cve': {'cve_id': 'CVE-2023-004'}, 'severity': '3', 'cvss_score': '5.5'} # Medium by numeric
            ]}
        ]
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertTrue(result['no_high_critical_sca_vulns'])
        self.assertEqual(len(result['high_critical_sca_reasons']), 0)
        self.assertIn("✅ No SCA components with High or Critical severity vulnerabilities found.", result['messages'])

    def test_sca_high_severity_vulnerability_numeric(self):
        """Test one component with a numeric '4' (High) severity vulnerability."""
        sca_components = [
            {'component_id': 'TestLibHighNum', 'version': '1.0', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-101'}, 'severity': '4', 'cvss_score': '7.5'}
            ]}
        ]
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertFalse(result['no_high_critical_sca_vulns'])
        self.assertEqual(len(result['high_critical_sca_reasons']), 1)
        self.assertIn("Component 'TestLibHighNum:1.0' has 4 vulnerability 'CVE-2023-101' (Severity: 7.5)", result['high_critical_sca_reasons'][0])
        self.assertTrue(any("❌ SCA components with High or Critical severity vulnerabilities found:" in msg for msg in result['messages']))
        self.assertTrue(any("TestLibHighNum:1.0" in msg for msg in result['messages']))


    def test_sca_critical_severity_vulnerability_numeric(self):
        """Test one component with a numeric '5' (Critical/Very High) severity vulnerability."""
        sca_components = [
            {'component_id': 'TestLibCritNum', 'version': '2.0', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-102'}, 'severity': '5', 'cvss_score': '9.8'}
            ]}
        ]
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertFalse(result['no_high_critical_sca_vulns'])
        self.assertEqual(len(result['high_critical_sca_reasons']), 1)
        self.assertIn("Component 'TestLibCritNum:2.0' has 5 vulnerability 'CVE-2023-102' (Severity: 9.8)", result['high_critical_sca_reasons'][0])
        self.assertTrue(any("❌ SCA components with High or Critical severity vulnerabilities found:" in msg for msg in result['messages']))

    def test_sca_high_severity_vulnerability_text(self):
        """Test one component with a text 'High' (case-insensitive) severity vulnerability."""
        sca_components = [
            {'component_id': 'TestLibHighText', 'version': '3.0', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-103'}, 'severity': 'high', 'cvss_score': '8.0'} # Lowercase 'high'
            ]}
        ]
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertFalse(result['no_high_critical_sca_vulns'])
        self.assertEqual(len(result['high_critical_sca_reasons']), 1)
        self.assertIn("Component 'TestLibHighText:3.0' has HIGH vulnerability 'CVE-2023-103' (Severity: 8.0)", result['high_critical_sca_reasons'][0])
        self.assertTrue(any("❌ SCA components with High or Critical severity vulnerabilities found:" in msg for msg in result['messages']))

    def test_sca_critical_severity_vulnerability_text(self):
        """Test one component with a text 'Critical' (case-insensitive) severity vulnerability."""
        sca_components = [
            {'component_id': 'TestLibCritText', 'version': '4.0', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-104'}, 'severity': 'CRITICAL', 'cvss_score': '10.0'} # Uppercase
            ]}
        ]
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertFalse(result['no_high_critical_sca_vulns'])
        self.assertEqual(len(result['high_critical_sca_reasons']), 1)
        self.assertIn("Component 'TestLibCritText:4.0' has CRITICAL vulnerability 'CVE-2023-104' (Severity: 10.0)", result['high_critical_sca_reasons'][0])
        self.assertTrue(any("❌ SCA components with High or Critical severity vulnerabilities found:" in msg for msg in result['messages']))

    def test_sca_multiple_critical_vulnerabilities(self):
        """Test with multiple components having High or Critical vulnerabilities."""
        sca_components = [
            {'component_id': 'MultiLib1', 'version': '1.0', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-201'}, 'severity': 'Critical', 'cvss_score': '9.5'}
            ]},
            {'component_id': 'MultiLib2', 'version': '1.1', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-202'}, 'severity': 'Low', 'cvss_score': '3.0'}
            ]},
            {'component_id': 'MultiLib3', 'version': '1.2', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-203'}, 'severity': '4', 'cvss_score': '7.0'},
                {'cve': {'cve_id': 'CVE-2023-204'}, 'severity': 'HIGH', 'cvss_score': '7.8'}
            ]}
        ]
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertFalse(result['no_high_critical_sca_vulns'])
        self.assertEqual(len(result['high_critical_sca_reasons']), 3) # 1 from MultiLib1, 2 from MultiLib3

        reasons_str = " ".join(result['high_critical_sca_reasons'])
        self.assertIn("MultiLib1:1.0", reasons_str)
        self.assertIn("CVE-2023-201", reasons_str)
        self.assertIn("CRITICAL", reasons_str)

        self.assertIn("MultiLib3:1.2", reasons_str)
        self.assertIn("CVE-2023-203", reasons_str)
        self.assertIn("4", reasons_str) # Severity for CVE-2023-203
        self.assertIn("CVE-2023-204", reasons_str)
        self.assertIn("HIGH", reasons_str) # Severity for CVE-2023-204

        self.assertTrue(any("❌ SCA components with High or Critical severity vulnerabilities found:" in msg for msg in result['messages']))
        # Check that all specific reasons are also in the main messages list
        for reason in result['high_critical_sca_reasons']:
             self.assertTrue(any(reason in detailed_msg for detailed_msg in result['messages']))

    def test_sca_component_details_in_reason(self):
        """Check component_id, version are correctly reported. Test with missing version."""
        sca_components = [
            {'component_id': 'CompWithVer', 'version': '1.2.3', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-301'}, 'severity': 'High', 'cvss_score': '7.7'}
            ]},
            {'component_id': 'CompNoVer', 'vulnerabilities': [ # No version key
                {'cve': {'cve_id': 'CVE-2023-302'}, 'severity': '5', 'cvss_score': '9.1'}
            ]}
        ]
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertFalse(result['no_high_critical_sca_vulns'])
        self.assertEqual(len(result['high_critical_sca_reasons']), 2)

        reasons_str = " ".join(result['high_critical_sca_reasons'])
        self.assertIn("Component 'CompWithVer:1.2.3' has HIGH vulnerability 'CVE-2023-301'", reasons_str)
        self.assertIn("Component 'CompNoVer' has 5 vulnerability 'CVE-2023-302'", reasons_str) # Note: No colon if version is missing

    def test_sca_vulnerability_details_in_reason(self):
        """Check CVE and severity are correctly reported. Test with missing CVE."""
        sca_components = [
            {'component_id': 'LibCVE', 'version': '1.0', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-001'}, 'severity': 'Critical', 'cvss_score': '9.0'}
            ]},
            {'component_id': 'LibNoCVE', 'version': '2.0', 'vulnerabilities': [ # No cve.cve_id
                {'severity': 'High', 'cvss_score': '8.0'} # 'cve' key might be missing or cve_id missing
            ]},
            {'component_id': 'LibEmptyCVEStruct', 'version': '3.0', 'vulnerabilities': [
                {'cve': {}, 'severity': '4', 'cvss_score': '7.0'} # 'cve' key present but empty
            ]}
        ]
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertFalse(result['no_high_critical_sca_vulns'])
        self.assertEqual(len(result['high_critical_sca_reasons']), 3)

        reasons_str = " ".join(result['high_critical_sca_reasons'])
        self.assertIn("'LibCVE:1.0' has CRITICAL vulnerability 'CVE-001'", reasons_str)
        self.assertIn("'LibNoCVE:2.0' has HIGH vulnerability 'N/A'", reasons_str)
        self.assertIn("'LibEmptyCVEStruct:3.0' has 4 vulnerability 'N/A'", reasons_str)

    def test_sca_vulnerabilities_not_a_list(self):
        """Test robustness if 'vulnerabilities' key is not a list (e.g., None or string)."""
        sca_components = [
            {'component_id': 'BadVulnFormat1', 'version': '1.0', 'vulnerabilities': None},
            {'component_id': 'BadVulnFormat2', 'version': '2.0', 'vulnerabilities': "this should be a list"},
            {'component_id': 'GoodLib', 'version': '3.0', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-GOOD-001'}, 'severity': 'Low', 'cvss_score': '1.0'}
            ]}
        ]
        # Expect no errors, and the good library to be processed normally.
        # The bad ones should be skipped.
        result = generate_compliance_data(self.flaws_empty, sca_components, self.raw_xml_minimal)
        self.assertTrue(result['no_high_critical_sca_vulns']) # Because only Low was found
        self.assertEqual(len(result['high_critical_sca_reasons']), 0)
        self.assertIn("✅ No SCA components with High or Critical severity vulnerabilities found.", result['messages'])

    # It might be good to also test interaction with static flaws,
    # but the subtask is focused on SCA.
    # For now, ensure static flaw messages are still present if static flaws exist.
    def test_sca_with_static_high_flaw(self):
        """Test that SCA checks don't interfere with static flaw messages."""
        flaws_with_high = [
            {'ID': '123', 'Severity': '5', 'Status': 'open', 'grace_period_expires': (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d")}
        ]
        sca_components = [
            {'component_id': 'TestLibLow', 'version': '1.0', 'vulnerabilities': [
                {'cve': {'cve_id': 'CVE-2023-001'}, 'severity': 'Low', 'cvss_score': '3.0'}
            ]}
        ]
        result = generate_compliance_data(flaws_with_high, sca_components, self.raw_xml_minimal)

        # SCA part
        self.assertTrue(result['no_high_critical_sca_vulns'])
        self.assertIn("✅ No SCA components with High or Critical severity vulnerabilities found.", result['messages'])

        # Static part
        self.assertFalse(result['no_open_high_critical']) # Static high flaw
        self.assertIn("❌ Open findings with severity 4 or 5 exist:", "\n".join(result['messages']))
        self.assertIn("Finding 123 (Severity 5)", "\n".join(result['messages']))

```
