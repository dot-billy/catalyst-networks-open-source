import unittest

from tools import port_diff_intake


class PortDiffIntakeTests(unittest.TestCase):
    def test_classifies_customer_only_paths(self):
        rows = port_diff_intake.parse_name_status(
            "M\tlicensing/views.py\n"
            "A\tsaas_entitlements/models.py\n"
            "M\tsupport/templates/support/ticket.html\n"
        )

        self.assertEqual([row.classification for row in rows], [
            'port:customer-only',
            'port:customer-only',
            'port:customer-only',
        ])

    def test_classifies_shared_watch_paths(self):
        rows = port_diff_intake.parse_name_status(
            "M\tsso/views.py\n"
            "M\tnodes/web_views.py\n"
            "M\ttemplates/organizations/detail.html\n"
        )

        self.assertEqual([row.classification for row in rows], [
            'port:shared',
            'port:shared',
            'port:shared',
        ])

    def test_handles_renamed_files_using_new_path(self):
        rows = port_diff_intake.parse_name_status(
            "R100\ttemplates/old.html\ttemplates/new.html\n"
        )

        self.assertEqual(rows[0].path, 'templates/new.html')
        self.assertEqual(rows[0].classification, 'port:shared')


if __name__ == '__main__':
    unittest.main()
