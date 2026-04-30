from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from reNgine.whois_service import NetlasWhoisProvider, RdapWhoisProvider, WhoisService, mask_sensitive_value
from reNgine.tasks import query_whois


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
        self.assertEqual(len(result.provider_attempts), 2)

    def test_netlas_fail_rdap_fail_sets_provider_none(self):
        netlas = Mock()
        rdap = Mock()
        netlas.query.return_value = Mock(status='failed', category='timeout', provider='netlas', message='timeout', data={}, raw_keys=[], used_fallback=False)
        rdap.query.return_value = Mock(status='failed', category='rdap_not_found', provider='rdap', message='not found', data={}, raw_keys=[], used_fallback=False)
        result = WhoisService(netlas, rdap).query('example.com')
        self.assertEqual(result.provider, 'none')
        self.assertEqual(len(result.provider_attempts), 2)


class QueryWhoisFlowTests(SimpleTestCase):
    @patch('reNgine.tasks.release_whois_lock')
    @patch('reNgine.tasks.save_domain_info_to_db')
    @patch('reNgine.tasks.format_whois_response', return_value={})
    @patch('reNgine.tasks.parse_whois_data')
    @patch('reNgine.tasks.reverse_whois', return_value=[])
    @patch('reNgine.tasks.fetch_related_tlds_and_domains', return_value=([], []))
    @patch('reNgine.tasks.get_domain_historical_ip_address', return_value=[])
    @patch('reNgine.tasks.get_domain_info_from_db', return_value=None)
    @patch('reNgine.tasks.WhoisService')
    def test_query_whois_uses_service_once_and_no_legacy_whois_task(self, mock_service, *_):
        service = Mock()
        service.query.return_value = Mock(status='ok', category='ok', message='ok', provider='netlas', used_fallback=False, provider_attempts=[], data={'related_domains': []})
        mock_service.return_value = service
        query_whois('example.com', force_reload_whois=True)
        service.query.assert_called_once_with('example.com')

    @patch('reNgine.tasks.release_whois_lock')
    @patch('reNgine.tasks.save_domain_info_to_db', return_value=Mock(id=1))
    @patch('reNgine.tasks.format_whois_response', return_value={})
    @patch('reNgine.tasks.parse_whois_data')
    @patch('reNgine.tasks.reverse_whois', return_value=[])
    @patch('reNgine.tasks.fetch_related_tlds_and_domains', return_value=([], []))
    @patch('reNgine.tasks.get_domain_historical_ip_address', return_value=[])
    @patch('reNgine.tasks.get_domain_info_from_db')
    @patch('reNgine.tasks.WhoisService')
    def test_reload_fail_keeps_existing_data_and_saves_diagnostic(self, mock_service, mock_get_db, *_):
        existing = Mock()
        mock_get_db.side_effect = [None, existing]
        service = Mock()
        service.query.return_value = Mock(status='failed', category='empty_response', message='x', provider='none', used_fallback=True, provider_attempts=[], data={})
        mock_service.return_value = service
        response = query_whois('example.com', force_reload_whois=True)
        self.assertIn('whois_status', response)
        self.assertEqual(response['whois_status']['provider'], 'none')


class LoggingSafetyTests(SimpleTestCase):
    def test_mask_sensitive_value(self):
        self.assertEqual(mask_sensitive_value('abcd1234'), 'ab****34')
