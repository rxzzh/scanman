import unittest
from scanman.core import Prime
from scanman.model import Vulnerability

class TestFilterAffections(unittest.TestCase):
    def setUp(self):
        """Set up a Prime instance with sample data for testing."""
        self.prime = Prime()
        self.prime.vulnerabilities = [
            Vulnerability(name="Vuln A", severity="high", description="High severity vulnerability", solution="Solution A"),
            Vulnerability(name="Vuln B", severity="middle", description="Medium severity vulnerability", solution="Solution B"),
            Vulnerability(name="Vuln C", severity="low", description="Low severity with IP 192.168.1.1", solution="Solution C"),
            Vulnerability(name="Vuln D", severity="high", description="Another high severity vulnerability", solution="Solution D"),
        ]
        self.prime.affections = {
            "Vuln A": ["192.168.1.1", "192.168.1.2"],
            "Vuln B": ["192.168.1.3"],
            "Vuln C": ["192.168.1.1"],
            "Vuln D": ["10.0.0.1"],
        }

    def test_filter_by_severity_high(self):
        """Test filtering for high severity vulnerabilities."""
        rules = {
            "rules": [{"field": "severity", "operator": "equal", "value": "high"}]
        }
        self.prime.filter_affections(rules)
        
        self.assertEqual(len(self.prime.affections), 2)
        self.assertIn("Vuln A", self.prime.affections)
        self.assertIn("Vuln D", self.prime.affections)
        self.assertEqual(len(self.prime.vulnerabilities), 2)

    def test_filter_by_ip_and_severity(self):
        """Test filtering with a combination of IP and severity."""
        rules = {
            "logical_operator": "AND",
            "rules": [
                {"field": "severity", "operator": "equal", "value": "high"},
                {"field": "ip", "operator": "equal", "value": "192.168.1.1"},
            ]
        }
        self.prime.filter_affections(rules)
        
        self.assertEqual(len(self.prime.affections), 1)
        self.assertIn("Vuln A", self.prime.affections)
        self.assertEqual(self.prime.affections["Vuln A"], ["192.168.1.1"])
        self.assertEqual(len(self.prime.vulnerabilities), 1)
        self.assertEqual(self.prime.vulnerabilities[0].name, "Vuln A")

    def test_filter_with_or_operator(self):
        """Test filtering using the OR logical operator."""
        rules = {
            "logical_operator": "OR",
            "rules": [
                {"field": "severity", "operator": "equal", "value": "low"},
                {"field": "name", "operator": "equal", "value": "Vuln B"},
            ]
        }
        self.prime.filter_affections(rules)
        
        self.assertEqual(len(self.prime.affections), 2)
        self.assertIn("Vuln B", self.prime.affections)
        self.assertIn("Vuln C", self.prime.affections)

    def test_filter_with_not_operator(self):
        """Test filtering using the NOT logical operator."""
        rules = {
            "logical_operator": "NOT",
            "rules": [
                {"field": "severity", "operator": "equal", "value": "high"}
            ]
        }
        self.prime.filter_affections(rules)
        
        self.assertEqual(len(self.prime.affections), 2)
        self.assertNotIn("Vuln A", self.prime.affections)
        self.assertNotIn("Vuln D", self.prime.affections)

    def test_filter_no_matches(self):
        """Test a filter that should result in no matches."""
        rules = {
            "rules": [{"field": "name", "operator": "equal", "value": "NonExistentVuln"}]
        }
        self.prime.filter_affections(rules)
        
        self.assertEqual(len(self.prime.affections), 0)
        self.assertEqual(len(self.prime.vulnerabilities), 0)

    def test_filter_ip_in_list(self):
        """Test filtering with the 'in' operator for IP addresses."""
        rules = {
            "rules": [{"field": "ip", "operator": "in", "value": ["192.168.1.1", "10.0.0.1"]}]
        }
        self.prime.filter_affections(rules)

        self.assertEqual(len(self.prime.affections), 3)
        self.assertEqual(self.prime.affections["Vuln A"], ["192.168.1.1"])
        self.assertEqual(self.prime.affections["Vuln C"], ["192.168.1.1"])
        self.assertEqual(self.prime.affections["Vuln D"], ["10.0.0.1"])

    def test_filter_oracle_mysql_high_middle_severity(self):
        """Test removing Oracle/MySQL vulns with high or middle severity."""
        # Add specific data for this test case
        self.prime.vulnerabilities.extend([
            Vulnerability(name="Oracle DB Auth Bypass", severity="high", description="desc", solution="sol"),
            Vulnerability(name="MySQL Remote Code Execution", severity="middle", description="desc", solution="sol"),
            Vulnerability(name="Oracle DB Info Leak", severity="low", description="desc", solution="sol"),
            Vulnerability(name="Apache Struts Exploit", severity="high", description="desc", solution="sol"),
        ])
        self.prime.affections["Oracle DB Auth Bypass"] = ["10.0.0.2"]
        self.prime.affections["MySQL Remote Code Execution"] = ["10.0.0.3"]
        self.prime.affections["Oracle DB Info Leak"] = ["10.0.0.4"]
        self.prime.affections["Apache Struts Exploit"] = ["10.0.0.5"]
        
        rules = {
            "logical_operator": "NOT",
            "rules": [
                {
                    "logical_operator": "AND",
                    "rules": [
                        {
                            "logical_operator": "OR",
                            "rules": [
                                {"field": "name", "operator": "contains", "value": "Oracle"},
                                {"field": "name", "operator": "contains", "value": "MySQL"},
                            ],
                        },
                        {
                            "field": "severity",
                            "operator": "in",
                            "value": ["high", "middle"],
                        },
                    ],
                }
            ],
        }
        
        self.prime.filter_affections(rules)

        # Should be removed
        self.assertNotIn("Oracle DB Auth Bypass", self.prime.affections)
        self.assertNotIn("MySQL Remote Code Execution", self.prime.affections)

        # Should remain
        self.assertIn("Vuln A", self.prime.affections)
        self.assertIn("Vuln B", self.prime.affections)
        self.assertIn("Vuln C", self.prime.affections)
        self.assertIn("Vuln D", self.prime.affections)
        self.assertIn("Oracle DB Info Leak", self.prime.affections) # Low severity
        self.assertIn("Apache Struts Exploit", self.prime.affections) # Different name

        remaining_vuln_names = [v.name for v in self.prime.vulnerabilities]
        self.assertNotIn("Oracle DB Auth Bypass", remaining_vuln_names)
        self.assertNotIn("MySQL Remote Code Execution", remaining_vuln_names)
        self.assertIn("Oracle DB Info Leak", remaining_vuln_names)
        self.assertIn("Apache Struts Exploit", remaining_vuln_names)


if __name__ == '__main__':
    unittest.main()
