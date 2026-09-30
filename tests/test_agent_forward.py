# Copyright (c) 2026 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License v2.0, Version 2.0, or any later version of
#    the GNU General Public License.
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later

"""Unit tests for restricted SSH agent forwarding"""

import asyncio

import asyncssh

from asyncssh.forward import SSHForwarder, SSHRestrictedAgentForwarder
from asyncssh.packet import Byte, SSHPacket, String, UInt32

from .util import AsyncTestCase, asynctest


REQUEST_IDENTITIES = 11
SIGN_REQUEST = 13
REMOVE_ALL_IDENTITIES = 19

FAILURE = 5
IDENTITIES_ANSWER = 12
SIGN_RESPONSE = 14

ALLOWED_KEY = b'allowed-public-key'
OTHER_KEY = b'other-public-key'
ALLOWED_BLOB = String(b'ssh-fake') + String(ALLOWED_KEY)
OTHER_BLOB = String(b'ssh-fake') + String(OTHER_KEY)


def frame(payload: bytes) -> bytes:
    """Encode an SSH agent frame"""

    return UInt32(len(payload)) + payload


def identity_request() -> bytes:
    """Build an identity listing request"""

    return frame(Byte(REQUEST_IDENTITIES))


def sign_request(key: bytes, data: bytes = b'data') -> bytes:
    """Build a signature request"""

    return frame(Byte(SIGN_REQUEST) + String(key) + String(data) + UInt32(0))


class FakeTransport(asyncio.Transport):
    """Transport which records writes and close state"""

    def __init__(self):
        super().__init__()

        self.written = b''
        self.eof_written = False
        self.closed = False
        self.paused = False

    def write(self, data: bytes) -> None:
        """Record data written by a forwarding protocol"""

        self.written += data

    def write_eof(self) -> None:
        """Record delivery of EOF"""

        self.eof_written = True

    def can_write_eof(self) -> bool:
        """Report EOF support"""

        return True

    def close(self) -> None:
        """Record connection close"""

        self.closed = True

    def pause_reading(self) -> None:
        """Pause local protocol reads"""

        self.paused = True

    def resume_reading(self) -> None:
        """Resume local protocol reads"""

        self.paused = False

    def get_extra_info(self, name, default=None):
        """Return no socket information"""

        return default


class _TestRestrictedAgentForwarder(AsyncTestCase):
    """Unit tests for the restricted SSH agent forwarder"""

    def setUp(self):
        self.remote_transport = FakeTransport()
        self.agent_transport = FakeTransport()

        self.forwarder = SSHRestrictedAgentForwarder([ALLOWED_BLOB])
        self.agent_forwarder = SSHForwarder(self.forwarder)

        self.forwarder.connection_made(self.remote_transport)
        self.agent_forwarder.connection_made(self.agent_transport)

    def _agent_response(self, payload: bytes):
        """Deliver a complete response from the fake local agent"""

        self.agent_forwarder.data_received(frame(payload))

    def _identity_answer(self, *keys: bytes) -> bytes:
        """Build an identity answer from the fake local agent"""

        payload = Byte(IDENTITIES_ANSWER) + UInt32(len(keys))

        for index, key in enumerate(keys):
            payload += String(ALLOWED_BLOB if key == ALLOWED_KEY else
                              OTHER_BLOB) + String(f'key-{index}'.encode())

        return frame(payload)

    @asynctest
    async def test_client_option_defaults(self):
        """Restricted forwarding identities are session-scoped options"""

        unrestricted = asyncssh.SSHClientConnectionOptions(
            agent_path='agent', known_hosts=(), agent_forwarding=True)
        self.assertIsNone(unrestricted.agent_forward_identities)

        restricted = asyncssh.SSHClientConnectionOptions(
            agent_path='agent', known_hosts=(), agent_forwarding=True,
            agent_forward_identities=[ALLOWED_BLOB])
        self.assertEqual(restricted.agent_forward_identities,
                         [ALLOWED_BLOB])

        no_identities = asyncssh.SSHClientConnectionOptions(
            agent_path='agent', known_hosts=(), agent_forwarding=True,
            agent_forward_identities=[])
        self.assertEqual(no_identities.agent_forward_identities, [])

    @asynctest
    async def test_identity_filtering_and_allowed_signature(self):
        """Allowed key is listed and can sign; other keys are hidden"""

        request = identity_request()
        self.forwarder.data_received(request[:2])
        self.assertEqual(self.agent_transport.written, b'')
        self.forwarder.data_received(request[2:])
        self.assertEqual(self.agent_transport.written, request)

        response = self._identity_answer(ALLOWED_KEY, OTHER_KEY)
        self.agent_forwarder.data_received(response[:5])
        self.assertEqual(self.remote_transport.written, b'')
        self.agent_forwarder.data_received(response[5:])

        response = self.remote_transport.written
        packet = SSHPacket(response[4:])
        self.assertEqual(packet.get_byte(), IDENTITIES_ANSWER)
        self.assertEqual(packet.get_uint32(), 1)
        self.assertEqual(packet.get_string(), ALLOWED_BLOB)
        comment = packet.get_string()
        self.assertEqual(comment, b'key-0')
        packet.check_end()
        self.assertIn(ALLOWED_KEY, response)
        self.assertNotIn(OTHER_KEY, response)

        self.remote_transport.written = b''
        self.forwarder.data_received(sign_request(OTHER_BLOB))
        self.assertEqual(self.remote_transport.written,
                         frame(Byte(FAILURE)))
        self.assertEqual(self.agent_transport.written, request)

        self.remote_transport.written = b''
        allowed_request = sign_request(ALLOWED_BLOB, b'challenge')
        self.forwarder.data_received(allowed_request)
        self.assertEqual(self.agent_transport.written,
                         request + allowed_request)

        self._agent_response(Byte(SIGN_RESPONSE) + String(b'fake-signature'))
        response = self.remote_transport.written
        self.assertEqual(response[4], SIGN_RESPONSE)
        self.assertIn(b'fake-signature', response)

    @asynctest
    async def test_coalesced_requests_are_individually_filtered(self):
        """Merged request frames cannot hide a request from filtering"""

        allowed = sign_request(ALLOWED_BLOB)
        denied = sign_request(OTHER_BLOB)
        self.forwarder.data_received(allowed + denied)

        self.assertEqual(self.agent_transport.written, allowed)
        self._agent_response(Byte(SIGN_RESPONSE) + String(b'fake-signature'))

        self.assertEqual(self.agent_transport.written, allowed)
        self.assertEqual(self.remote_transport.written[-5:],
                         frame(Byte(FAILURE)))

    @asynctest
    async def test_unknown_operation_denied(self):
        """Unknown SSH agent operations receive a local failure"""

        self.forwarder.data_received(frame(Byte(REMOVE_ALL_IDENTITIES)))

        self.assertEqual(self.remote_transport.written,
                         frame(Byte(FAILURE)))
        self.assertEqual(self.agent_transport.written, b'')
        self.assertFalse(self.remote_transport.closed)

    @asynctest
    async def test_malformed_length_closes_channel(self):
        """A malformed message length closes both sides"""

        self.forwarder.data_received(UInt32(0)[:2])
        self.assertFalse(self.remote_transport.closed)
        self.forwarder.data_received(UInt32(0)[2:])

        self.assertTrue(self.remote_transport.closed)
        self.assertTrue(self.agent_transport.closed)

    @asynctest
    async def test_oversized_length_closes_channel(self):
        """An oversized declared length is rejected once complete"""

        oversized = UInt32(256 * 1024 + 1)
        self.forwarder.data_received(oversized[:2])
        self.forwarder.data_received(oversized[2:] + b'x')

        self.assertEqual(self.agent_transport.written, b'')
        self.assertTrue(self.remote_transport.closed)
        self.assertTrue(self.agent_transport.closed)

    @asynctest
    async def test_malformed_request_closes_channel(self):
        """A malformed known request closes rather than being forwarded"""

        self.forwarder.data_received(frame(Byte(SIGN_REQUEST)))

        self.assertEqual(self.agent_transport.written, b'')
        self.assertTrue(self.remote_transport.closed)
        self.assertTrue(self.agent_transport.closed)

    @asynctest
    async def test_unsolicited_or_coalesced_response_closes_channel(self):
        """Extra upstream frames cannot be smuggled through the proxy"""

        self.forwarder.data_received(identity_request())
        response = self._identity_answer(ALLOWED_KEY)
        self.agent_forwarder.data_received(response + response)

        self.assertEqual(self.remote_transport.written, b'')
        self.assertTrue(self.remote_transport.closed)
        self.assertTrue(self.agent_transport.closed)

    @asynctest
    async def test_upstream_disconnect_completes_request(self):
        """Upstream disconnection while a request is pending closes"""

        self.forwarder.data_received(identity_request())
        self.agent_forwarder.connection_lost(None)

        self.assertTrue(self.remote_transport.closed)
        self.assertTrue(self.agent_transport.closed)

    @asynctest
    async def test_session_close_completes_pending_request(self):
        """SSH session close terminates a request still pending upstream"""

        self.forwarder.data_received(identity_request())
        self.forwarder.connection_lost(None)

        self.assertTrue(self.remote_transport.closed)
        self.assertTrue(self.agent_transport.closed)
