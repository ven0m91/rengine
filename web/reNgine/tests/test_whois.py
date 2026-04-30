from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from reNgine.tasks import classify_whois_status, fetch_rdap_data


class WhoisHelperTests(SimpleTestCase):
    def test_classify_success(self):
        status = classify_whois_status({'status': True, 'data': {'whois': {}}}, 'example.com')
        self.assertTrue(status['status'])
        self.assertEqual(status['category'], 'ok')

    def test_classify_rate_limit(self):
        status = classify_whois_status({'status': False, 'message': 'Request limit exceeded'}, 'nic.cl')
        self.assertFalse(status['status'])
        self.assertEqual(status['category'], 'rate_limit')

    def test_classify_timeout(self):
        status = classify_whois_status({'status': False, 'message': 'connection timeout'}, 'google.com')
        self.assertEqual(status['category'], 'timeout')

    @patch('reNgine.tasks.requests.get')
    def test_rdap_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'events': [
                {'eventAction': 'registration', 'eventDate': '2020-01-01T00:00:00Z'},
                {'eventAction': 'expiration', 'eventDate': '2030-01-01T00:00:00Z'},
                {'eventAction': 'last changed', 'eventDate': '2024-01-01T00:00:00Z'},
            ],
            'status': ['active'],
            'nameservers': [{'ldhName': 'ns1.example.com'}],
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        response = fetch_rdap_data('example.com')
        self.assertTrue(response['status'])
        self.assertIn('whois', response['data'])

    @patch('reNgine.tasks.requests.get')
    def test_rdap_not_found(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        response = fetch_rdap_data('un-dominio-inexistente-test-123456.cl')
        self.assertFalse(response['status'])
        self.assertIn('not found', response['message'].lower())
