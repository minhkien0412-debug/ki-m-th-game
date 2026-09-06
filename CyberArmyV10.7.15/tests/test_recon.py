"""Tests for crt.sh passive recon parsing and failure surfacing."""

import unittest
from unittest.mock import Mock

import requests

from units.external_intel_client import ExternalIntelClient


class FakeResp:
    def __init__(self, status_code=200, text='', payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError('no json')
        return self._payload


class TestCrtShClient(unittest.TestCase):
    def setUp(self):
        self.client = ExternalIntelClient(retries=0)
        self.addCleanup(self.client.close)

    def test_parses_unique_names_and_drops_wildcards(self):
        payload = [
            {'name_value': 'a.playstation.net\n*.playstation.net'},
            {'name_value': 'b.playstation.net'},
            {'name_value': 'a.playstation.net'},  # duplicate
        ]
        self.client.session.get = Mock(return_value=FakeResp(200, '[...]', payload))
        result = self.client.query_crtsh('playstation.net')
        names = sorted(r['subdomain'] for r in result)
        self.assertEqual(names, ['a.playstation.net', 'b.playstation.net'])
        # the query is passed via params so % is encoded correctly
        _, kwargs = self.client.session.get.call_args
        self.assertEqual(kwargs['params']['q'], '%.playstation.net')

    def test_non_200_returns_empty(self):
        self.client.session.get = Mock(return_value=FakeResp(503, 'busy'))
        self.assertEqual(self.client.query_crtsh('playstation.net'), [])

    def test_request_error_returns_empty(self):
        self.client.session.get = Mock(
            side_effect=requests.exceptions.ConnectionError('no route')
        )
        self.assertEqual(self.client.query_crtsh('playstation.net'), [])

    def test_retries_then_succeeds(self):
        payload = [{'name_value': 'x.playstation.net'}]
        self.client.retries = 1
        self.client.session.get = Mock(side_effect=[
            FakeResp(502, 'bad gateway'),
            FakeResp(200, '[...]', payload),
        ])
        # avoid real backoff sleep
        import units.external_intel_client as m
        original_sleep = m.time.sleep
        m.time.sleep = lambda *_: None
        try:
            result = self.client.query_crtsh('playstation.net')
        finally:
            m.time.sleep = original_sleep
        self.assertEqual([r['subdomain'] for r in result], ['x.playstation.net'])
        self.assertEqual(self.client.session.get.call_count, 2)


if __name__ == '__main__':
    unittest.main()
