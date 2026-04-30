from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from reNgine.whois_service import NetlasWhoisProvider, RdapWhoisProvider, WhoisService, mask_sensitive_value


class NetlasWhoisProviderTests(SimpleTestCase):
    @patch('reNgine.whois_service.get_netlas_key', return_value=None)
    def test_missing_api_key(self, _):
        result = NetlasWhoisProvider().query('example.com')
        self.assertEqual(result.category, 'config_error')

    @patch('reNgine.whois_service.get_netlas_key', return_value='secret123')
    @patch('reNgine.whois_service.requests.get')
    def test_auth_error(self, mock_get, _):
        mock_get.return_value = Mock(status_code=401, headers={})
        result = NetlasWhoisProvider().query('example.com')
        self.assertEqual(result.category, 'auth_error')

    @patch('reNgine.whois_service.get_netlas_key', return_value='secret123')
    @patch('reNgine.whois_service.requests.get')
    def test_valid_whois_payload(self, mock_get, _):
        resp = Mock(status_code=200, headers={})
        resp.json.return_value = {'whois': {'created_date': '2020-01-01'}, 'dns': {}}
        mock_get.return_value = resp
        result = NetlasWhoisProvider().query('example.com')
        self.assertEqual(result.status, 'ok')


class RdapWhoisProviderTests(SimpleTestCase):
    @patch('reNgine.whois_service.requests.get')
    def test_rdap_not_available(self, mock_get):
        boot = Mock(status_code=200)
        boot.raise_for_status.return_value = None
        boot.json.return_value = {'services': [[['com'], ['https://rdap.verisign.com/com/v1']]]}
        mock_get.return_value = boot
        result = RdapWhoisProvider().query('domain.invalidtld')
        self.assertEqual(result.category, 'rdap_not_available')


class WhoisServiceTests(SimpleTestCase):
    def test_netlas_fail_rdap_ok(self):
        netlas = Mock()
        rdap = Mock()
        netlas.query.return_value = Mock(status='failed', category='config_error', provider='netlas', message='x', data={}, raw_keys=[], used_fallback=False)
        rdap.query.return_value = Mock(status='ok', category='ok', provider='rdap', message='ok', data={'whois': {}}, raw_keys=[], used_fallback=False)
        result = WhoisService(netlas, rdap).query('example.com')
        self.assertTrue(result.used_fallback)
        self.assertEqual(result.provider, 'rdap')


class LoggingSafetyTests(SimpleTestCase):
    def test_mask_sensitive_value(self):
        self.assertEqual(mask_sensitive_value('abcd1234'), 'ab****34')
