# Copyright (c) 2016-2025 by Ron Frederick <ronf@timeheart.net> and others.
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
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Unit tests for AsyncSSH ssh-agent client"""

import asyncio
import functools
import os
from pathlib import Path
import signal
import subprocess
import unittest

import asyncssh

from asyncssh.agent import SSH_AGENT_SUCCESS, SSH_AGENT_FAILURE
from asyncssh.agent import SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE
from asyncssh.agent import SSH_AGENTC_REQUEST_IDENTITIES
from asyncssh.agent import SSH_AGENTC_SIGN_REQUEST, SSH_AGENTC_ADD_IDENTITY
from asyncssh.agent import SSH_AGENTC_REMOVE_ALL_IDENTITIES
from asyncssh.crypto import ed25519_available
from asyncssh.packet import Byte, String, UInt32, SSHPacket

from .sk_stub import sk_available, patch_sk
from .util import AsyncTestCase, asynctest, get_test_key, run, try_remove


def agent_test(func):
    """Decorator for running SSH agent tests"""

    @asynctest
    @functools.wraps(func)
    async def agent_wrapper(self):
        """Run a test after connecting to an SSH agent"""

        async with asyncssh.connect_agent() as agent:
            await agent.remove_all()
            await func(self, agent)

    return agent_wrapper


class _Agent:
    """Mock SSH agent for testing error cases"""

    def __init__(self, response):
        self._response = b'' if response is None else String(response)
        self._path = None
        self._server = None

    async def start(self, path):
        """Start a new mock SSH agent"""

        self._path = path

        # pylint doesn't think start_unix_server exists
        # pylint: disable=no-member
        self._server = \
            await asyncio.start_unix_server(self.process_request, path)

    async def process_request(self, reader, writer):
        """Process a request sent to the mock SSH agent"""

        await reader.readexactly(4)
        writer.write(self._response)
        writer.close()

    async def stop(self):
        """Shut down the mock SSH agent"""

        self._server.close()
        await self._server.wait_closed()

        try_remove(self._path)


class _TestAgent(AsyncTestCase):
    """Unit tests for AsyncSSH API"""

    _agent_pid = None
    _public_keys = {}

    @staticmethod
    def set_askpass(status):
        """Set return status for ssh-askpass"""

        with open('ssh-askpass', 'w') as f:
            f.write(f'#!/bin/sh\nexit {status}\n')
            os.chmod('ssh-askpass', 0o755)

    # Pylint doesn't like mixed case method names, but this was chosen to
    # match the convention used in the unittest module.

    # pylint: disable=invalid-name

    @classmethod
    async def asyncSetUpClass(cls):
        """Set up keys and an SSH server for the tests to use"""

        os.environ['DISPLAY'] = ' '
        os.environ['HOME'] = '.'
        os.environ['SSH_ASKPASS'] = os.path.join(os.getcwd(), 'ssh-askpass')

        try:
            output = run('ssh-agent -a agent 2>/dev/null')
        except subprocess.CalledProcessError: # pragma: no cover
            return

        cls._agent_pid = int(output.splitlines()[2].split()[3][:-1])
        os.environ['SSH_AUTH_SOCK'] = 'agent'

    @classmethod
    async def asyncTearDownClass(cls):
        """Shut down agents"""

        if cls._agent_pid: # pragma: no branch
            os.kill(cls._agent_pid, signal.SIGTERM)

    def setUp(self):
        """Skip unit tests if we couldn't start an agent"""

        if not self._agent_pid: # pragma: no cover
            self.skipTest('ssh-agent not available')

    # pylint: enable=invalid-name

    @agent_test
    async def test_connection(self, agent):
        """Test opening a connection to the agent"""

        self.assertIsNotNone(agent)

    @asynctest
    async def test_connection_failed(self):
        """Test failure in opening a connection to the agent"""

        with self.assertRaises(OSError):
            await asyncssh.connect_agent('xxx')

    @asynctest
    async def test_no_auth_sock(self):
        """Test failure when no auth sock is set"""

        del os.environ['SSH_AUTH_SOCK']

        with self.assertRaises(OSError):
            await asyncssh.connect_agent()

        os.environ['SSH_AUTH_SOCK'] = 'agent'

    @agent_test
    async def test_get_keys(self, agent):
        """Test getting keys from the agent"""

        keys = await agent.get_keys()
        self.assertEqual(len(keys), len(self._public_keys))

    @agent_test
    async def test_sign(self, agent):
        """Test signing a block of data using the agent"""

        algs = ['ssh-rsa', 'ecdsa-sha2-nistp256']

        if ed25519_available: # pragma: no branch
            algs.append('ssh-ed25519')

        for alg_name in algs:
            key = get_test_key(alg_name)
            pubkey = key.convert_to_public()
            cert = key.generate_user_certificate(key, 'name')

            await agent.add_keys([(key, cert)])
            agent_keys = await agent.get_keys()

            for agent_key in agent_keys:
                agent_key.set_sig_algorithm(agent_key.sig_algorithms[0])
                sig = await agent_key.sign_async(b'test')
                self.assertTrue(pubkey.verify(b'test', sig))

            await agent.remove_keys(agent_keys)

    @agent_test
    async def test_set_certificate(self, agent):
        """Test setting certificate on an existing keypair"""

        key = get_test_key('ssh-rsa')
        cert = key.generate_user_certificate(key, 'name')

        key2 = get_test_key('ssh-rsa', 1)
        cert2 = key.generate_user_certificate(key2, 'name')

        await agent.add_keys([key])
        agent_key = (await agent.get_keys())[0]

        agent_key.set_certificate(cert)
        self.assertEqual(agent_key.public_data, cert.public_data)

        with self.assertRaises(ValueError):
            asyncssh.load_keypairs([(agent_key, cert2)])

        agent_key = (await agent.get_keys())[0]
        agent_key = asyncssh.load_keypairs([(agent_key, cert)])[0]
        self.assertEqual(agent_key.public_data, cert.public_data)

        with self.assertRaises(ValueError):
            asyncssh.load_keypairs([(agent_key, cert2)])

    @agent_test
    async def test_reconnect(self, agent):
        """Test reconnecting to the agent after closing it"""

        key = get_test_key('ecdsa-sha2-nistp256')
        pubkey = key.convert_to_public()

        async with agent:
            await agent.add_keys([key])
            agent_keys = await agent.get_keys()

        for agent_key in agent_keys:
            sig = await agent_key.sign_async(b'test')
            self.assertTrue(pubkey.verify(b'test', sig))

    @agent_test
    async def test_add_remove_keys(self, agent):
        """Test adding and removing keys"""

        await agent.add_keys()
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

        key = get_test_key('ssh-rsa')
        await agent.add_keys([key])
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 1)

        await agent.remove_keys(agent_keys)
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

        await agent.add_keys([key])
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 1)

        await agent_keys[0].remove()
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

        await agent.add_keys([key], lifetime=1)
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 1)
        await asyncio.sleep(2)

        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

    @agent_test
    async def test_add_nonlocal(self, agent):
        """Test failure when adding a non-local key to an agent"""

        key = get_test_key('ssh-rsa')

        async with agent:
            await agent.add_keys([key])
            agent_keys = await agent.get_keys()

            with self.assertRaises(asyncssh.KeyImportError):
                await agent.add_keys(agent_keys)

    @agent_test
    async def test_add_keys_failure(self, agent):
        """Test failure adding keys to the agent"""

        os.mkdir('.ssh', 0o700)
        key = get_test_key('ssh-rsa')
        key.write_private_key(Path('.ssh', 'id_rsa'))

        try:
            mock_agent = _Agent(Byte(SSH_AGENT_FAILURE))
            await mock_agent.start('mock_agent')

            async with asyncssh.connect_agent('mock_agent') as agent:
                async with agent:
                    await agent.add_keys()

                async with agent:
                    with self.assertRaises(ValueError):
                        await agent.add_keys([key])
        finally:
            await mock_agent.stop()
            os.remove(os.path.join('.ssh', 'id_rsa'))
            os.rmdir('.ssh')

    @unittest.skipUnless(sk_available, 'security key support not available')
    @patch_sk([2])
    @asynctest
    async def test_add_sk_keys(self):
        """Test adding U2F security keys"""

        key = get_test_key('sk-ecdsa-sha2-nistp256@openssh.com')
        cert = key.generate_user_certificate(key, 'test')

        mock_agent = _Agent(Byte(SSH_AGENT_SUCCESS))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            for keypair in asyncssh.load_keypairs([key, (key, cert)]):
                async with agent:
                    self.assertIsNone(await agent.add_keys([keypair]))

            with self.assertRaises(asyncssh.KeyExportError):
                await agent.add_keys([key.convert_to_public()])

        await mock_agent.stop()

    @unittest.skipUnless(sk_available, 'security key support not available')
    @patch_sk([2])
    @asynctest
    async def test_get_sk_keys(self):
        """Test getting U2F security keys"""

        key = get_test_key('sk-ecdsa-sha2-nistp256@openssh.com')
        cert = key.generate_user_certificate(key, 'test')

        mock_agent = _Agent(Byte(SSH_AGENT_IDENTITIES_ANSWER) + UInt32(2) +
                            String(key.public_data) + String('') +
                            String(cert.public_data) + String(''))

        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            await agent.get_keys()

        await mock_agent.stop()

    @asynctest
    async def test_add_remove_smartcard_keys(self):
        """Test adding and removing smart card keys"""

        mock_agent = _Agent(Byte(SSH_AGENT_SUCCESS))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            result = await agent.add_smartcard_keys('provider')
            self.assertIsNone(result)

        await mock_agent.stop()

        mock_agent = _Agent(Byte(SSH_AGENT_SUCCESS))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            result = await agent.remove_smartcard_keys('provider')
            self.assertIsNone(result)

        await mock_agent.stop()

    @agent_test
    async def test_confirm(self, agent):
        """Test confirmation of key"""

        key = get_test_key('ecdsa-sha2-nistp256')
        pubkey = key.convert_to_public()

        await agent.add_keys([key], confirm=True)
        agent_keys = await agent.get_keys()

        self.set_askpass(1)

        for agent_key in agent_keys:
            with self.assertRaises(ValueError):
                sig = await agent_key.sign_async(b'test')

        self.set_askpass(0)

        for agent_key in agent_keys:
            sig = await agent_key.sign_async(b'test')
            self.assertTrue(pubkey.verify(b'test', sig))

    @agent_test
    async def test_lock(self, agent):
        """Test lock and unlock"""

        key = get_test_key('ecdsa-sha2-nistp256')
        pubkey = key.convert_to_public()

        await agent.add_keys([key])
        agent_keys = await agent.get_keys()

        await agent.lock('passphrase')

        for agent_key in agent_keys:
            with self.assertRaises(ValueError):
                await agent_key.sign_async(b'test')

        await agent.unlock('passphrase')

        for agent_key in agent_keys:
            sig = await agent_key.sign_async(b'test')
            self.assertTrue(pubkey.verify(b'test', sig))

    @asynctest
    async def test_query_extensions(self):
        """Test query of supported extensions"""

        mock_agent = _Agent(Byte(SSH_AGENT_SUCCESS) + String('xxx'))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            extensions = await agent.query_extensions()
            self.assertEqual(extensions, ['xxx'])

        await mock_agent.stop()

        mock_agent = _Agent(Byte(SSH_AGENT_SUCCESS) + String(b'\xff'))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            with self.assertRaises(ValueError):
                await agent.query_extensions()

        await mock_agent.stop()

        mock_agent = _Agent(Byte(SSH_AGENT_FAILURE))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            extensions = await agent.query_extensions()
            self.assertEqual(extensions, [])

        await mock_agent.stop()

        mock_agent = _Agent(b'\xff')
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            with self.assertRaises(ValueError):
                await agent.query_extensions()

        await mock_agent.stop()

    @agent_test
    async def test_unknown_key(self, agent):
        """Test failure when signing with an unknown key"""

        key = get_test_key('ssh-rsa')

        with self.assertRaises(ValueError):
            await agent.sign(key.public_data, b'test')

    @agent_test
    async def test_double_close(self, agent):
        """Test calling close more than once on the agent"""

        self.assertIsNotNone(agent)
        agent.close()

    @asynctest
    async def test_errors(self):
        """Test getting error responses from SSH agent"""

        key = get_test_key('ssh-rsa')
        keypair = asyncssh.load_keypairs(key)[0]

        for response in (None, b'', Byte(SSH_AGENT_FAILURE), b'\xff'):
            mock_agent = _Agent(response)
            await mock_agent.start('mock_agent')

            async with asyncssh.connect_agent('mock_agent') as agent:
                for request in (agent.get_keys(),
                                agent.sign(b'xxx', b'test'),
                                agent.add_keys([key]),
                                agent.add_smartcard_keys('xxx'),
                                agent.remove_keys([keypair]),
                                agent.remove_smartcard_keys('xxx'),
                                agent.remove_all(),
                                agent.lock('passphrase'),
                                agent.unlock('passphrase')):
                    async with agent:
                        with self.assertRaises(ValueError):
                            await request

            await mock_agent.stop()


class _FakeAgentConnection:
    """In-memory connection to a fake SSH agent"""

    def __init__(self, agent):
        self._agent = agent
        self._send_buf = b''
        self._recv_buf = b''
        self._recv_eof = False
        self._recv_event = asyncio.Event()
        self._closed = False
        self._processing = False

    async def readexactly(self, n):
        """Read exactly n bytes of response data from the agent"""

        while len(self._recv_buf) < n:
            if self._recv_eof:
                raise asyncio.IncompleteReadError(self._recv_buf, n)

            self._recv_event.clear()
            await self._recv_event.wait()

        result, self._recv_buf = self._recv_buf[:n], self._recv_buf[n:]

        return result

    def write(self, data):
        """Write request data to the agent"""

        if self._closed:
            return

        self._send_buf += data

        if not self._processing:
            self._processing = True
            asyncio.ensure_future(self._process_requests())

    def close(self):
        """Close the connection to the agent"""

        self._closed = True
        self._recv_eof = True
        self._recv_event.set()

    async def wait_closed(self):
        """Wait for the connection to the agent to close"""

    def feed_eof(self):
        """Feed end of file to the reader"""

        self._recv_eof = True
        self._recv_event.set()

    async def _process_requests(self):
        """Process complete request frames written to the agent"""

        try:
            while len(self._send_buf) >= 4:
                length = int.from_bytes(self._send_buf[:4], 'big')

                if len(self._send_buf) < 4 + length:
                    break

                payload = self._send_buf[4:4+length]
                self._send_buf = self._send_buf[4+length:]

                response = await self._agent.handle_request(payload)

                if response is None:
                    self.feed_eof()
                    break

                self._recv_buf += UInt32(len(response)) + response
                self._recv_event.set()
        finally:
            self._processing = False


class _FakeAgent:
    """Fake SSH agent speaking the SSH agent protocol in memory"""

    def __init__(self, keys):
        self._keys = keys
        self.sign_requests = []
        self.disconnect_on_sign = False
        self.sign_event = None

    async def open_agent_connection(self):
        """Open an in-memory connection to the fake SSH agent"""

        conn = _FakeAgentConnection(self)

        return conn, conn

    async def handle_request(self, payload):
        """Handle a request sent to the fake SSH agent"""

        msgtype = payload[0]

        if msgtype == SSH_AGENTC_REQUEST_IDENTITIES:
            response = Byte(SSH_AGENT_IDENTITIES_ANSWER) + \
                       UInt32(len(self._keys))

            for key_blob, comment in self._keys:
                response += String(key_blob) + String(comment)

            return response

        if msgtype == SSH_AGENTC_SIGN_REQUEST:
            packet = SSHPacket(payload[1:])
            key_blob = packet.get_string()
            data = packet.get_string()
            flags = packet.get_uint32()

            self.sign_requests.append((key_blob, data, flags))

            if self.disconnect_on_sign:
                return None

            if self.sign_event:
                await self.sign_event.wait()

            if key_blob not in [blob for blob, _ in self._keys]:
                return Byte(SSH_AGENT_FAILURE)

            sig = String(b'ssh-fake') + String(b'sig:' + data)

            return Byte(SSH_AGENT_SIGN_RESPONSE) + String(sig)

        return Byte(SSH_AGENT_FAILURE)


class _FakeChannelTransport:
    """Fake channel transport capturing data written by a filter"""

    def __init__(self):
        self.data = b''
        self.closed = False

    def write(self, data):
        """Write data to the transport"""

        self.data += data

    def close(self):
        """Close the transport"""

        self.closed = True


class _FailingChannelTransport(_FakeChannelTransport):
    """Fake channel transport which fails on write"""

    def __init__(self, exc):
        super().__init__()
        self._exc = exc

    def write(self, data):
        """Raise an error on write"""

        # pylint: disable=unused-argument

        raise self._exc


class _TestAgentForwardingFilter(AsyncTestCase):
    """Unit tests for SSH agent forwarding filter"""

    def setUp(self):
        """Set up keys for the tests to use"""

        super().setUp()

        self.allowed_key = get_test_key('ssh-rsa')
        self.other_key = get_test_key('ssh-rsa', 1)

        self.keys = [(self.allowed_key.public_data, b'allowed'),
                     (self.other_key.public_data, b'other')]

    async def _start_filter(self, agent, allowed_identities):
        """Start a forwarding filter connected to a fake SSH agent"""

        agent_filter = asyncssh.SSHAgentForwardingFilter(
            agent, allowed_identities)
        await agent_filter.connect()

        transport = _FakeChannelTransport()
        agent_filter.connection_made(transport)

        return agent_filter, transport

    async def _wait_response(self, transport, start):
        """Wait for a response frame and return its type and payload"""

        resplen = None

        for _ in range(1000):
            await asyncio.sleep(0.001)

            if len(transport.data) >= start + 4:
                resplen = int.from_bytes(transport.data[start:start+4], 'big')

                if len(transport.data) >= start + 4 + resplen:
                    break
        else:
            self.fail('Timed out waiting for SSH agent response')

        resp = SSHPacket(transport.data[start+4:start+4+resplen])

        return resp.get_byte(), resp, start + 4 + resplen

    async def _send_request(self, agent_filter, transport, payload):
        """Send a request frame and return the response type and payload"""

        start = len(transport.data)
        agent_filter.data_received(UInt32(len(payload)) + payload)

        resptype, resp, _ = await self._wait_response(transport, start)

        return resptype, resp

    @staticmethod
    def _sign_request(key_blob, data=b'data', flags=0):
        """Build an SSH agent sign request payload"""

        return Byte(SSH_AGENTC_SIGN_REQUEST) + String(key_blob) + \
               String(data) + UInt32(flags)

    @asynctest
    async def test_allowed_key_can_sign(self):
        """Test that an allowed key can sign through the filter"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        resptype, resp = await self._send_request(
            agent_filter, transport,
            self._sign_request(self.allowed_key.public_data))

        self.assertEqual(resptype, SSH_AGENT_SIGN_RESPONSE)
        self.assertEqual(resp.get_string(),
                         String(b'ssh-fake') + String(b'sig:data'))
        resp.check_end()

        self.assertEqual(agent.sign_requests,
                         [(self.allowed_key.public_data, b'data', 0)])

        agent_filter.close()

    @asynctest
    async def test_other_key_not_visible(self):
        """Test that non-allowed keys are neither visible nor usable"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        resptype, resp = await self._send_request(
            agent_filter, transport, Byte(SSH_AGENTC_REQUEST_IDENTITIES))

        self.assertEqual(resptype, SSH_AGENT_IDENTITIES_ANSWER)
        self.assertEqual(resp.get_uint32(), 1)
        self.assertEqual(resp.get_string(), self.allowed_key.public_data)
        self.assertEqual(resp.get_string(), b'allowed')
        resp.check_end()

        resptype, _ = await self._send_request(
            agent_filter, transport,
            self._sign_request(self.other_key.public_data))

        self.assertEqual(resptype, SSH_AGENT_FAILURE)
        self.assertEqual(agent.sign_requests, [])

        agent_filter.close()

    @asynctest
    async def test_empty_allowed_identities(self):
        """Test that an empty allowed list hides and denies all keys"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(agent, [])

        resptype, resp = await self._send_request(
            agent_filter, transport, Byte(SSH_AGENTC_REQUEST_IDENTITIES))

        self.assertEqual(resptype, SSH_AGENT_IDENTITIES_ANSWER)
        self.assertEqual(resp.get_uint32(), 0)
        resp.check_end()

        resptype, _ = await self._send_request(
            agent_filter, transport,
            self._sign_request(self.allowed_key.public_data))

        self.assertEqual(resptype, SSH_AGENT_FAILURE)
        self.assertEqual(agent.sign_requests, [])

        agent_filter.close()

    @asynctest
    async def test_unknown_operation_denied(self):
        """Test that unknown agent operations are denied by default"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        for msgtype in (SSH_AGENTC_ADD_IDENTITY,
                        SSH_AGENTC_REMOVE_ALL_IDENTITIES, 0xff):
            resptype, _ = await self._send_request(
                agent_filter, transport, Byte(msgtype))

            self.assertEqual(resptype, SSH_AGENT_FAILURE)

        agent_filter.close()

    @asynctest
    async def test_fragmented_frame(self):
        """Test that fragmented frames can't bypass the filter"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        payload = self._sign_request(self.other_key.public_data)
        frame = UInt32(len(payload)) + payload

        for i in range(0, len(frame), 3):
            agent_filter.data_received(frame[i:i+3])
            await asyncio.sleep(0)

        resptype, _, _ = await self._wait_response(transport, 0)

        self.assertEqual(resptype, SSH_AGENT_FAILURE)
        self.assertEqual(agent.sign_requests, [])

        agent_filter.close()

    @asynctest
    async def test_merged_frames(self):
        """Test that coalesced frames are filtered individually"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        payload1 = Byte(SSH_AGENTC_REQUEST_IDENTITIES)
        payload2 = self._sign_request(self.other_key.public_data)
        payload3 = self._sign_request(self.allowed_key.public_data)

        agent_filter.data_received(UInt32(len(payload1)) + payload1 +
                                   UInt32(len(payload2)) + payload2 +
                                   UInt32(len(payload3)) + payload3)

        resptype, resp, offset = await self._wait_response(transport, 0)
        self.assertEqual(resptype, SSH_AGENT_IDENTITIES_ANSWER)
        self.assertEqual(resp.get_uint32(), 1)

        resptype, _, offset = await self._wait_response(transport, offset)
        self.assertEqual(resptype, SSH_AGENT_FAILURE)

        resptype, _, _ = await self._wait_response(transport, offset)
        self.assertEqual(resptype, SSH_AGENT_SIGN_RESPONSE)

        self.assertEqual(agent.sign_requests,
                         [(self.allowed_key.public_data, b'data', 0)])

        agent_filter.close()

    @asynctest
    async def test_malformed_frame_length(self):
        """Test that malformed frame lengths close the channel"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        for framelen in (0, 0x7fffffff):
            agent_filter.data_received(UInt32(framelen))
            await asyncio.sleep(0.1)

            self.assertTrue(transport.closed)

            agent_filter.data_received(b'xxx')

            agent_filter.close()

            if framelen == 0:
                agent_filter, transport = await self._start_filter(
                    agent, [self.allowed_key.public_data])

    @asynctest
    async def test_malformed_sign_request(self):
        """Test that malformed sign requests are denied"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        for payload in (Byte(SSH_AGENTC_SIGN_REQUEST),
                        Byte(SSH_AGENTC_SIGN_REQUEST) + b'\xff',
                        Byte(SSH_AGENTC_SIGN_REQUEST) +
                        String(self.allowed_key.public_data),
                        Byte(SSH_AGENTC_REQUEST_IDENTITIES) + b'extra'):
            resptype, _ = await self._send_request(agent_filter, transport,
                                                   payload)

            self.assertEqual(resptype, SSH_AGENT_FAILURE)

        self.assertEqual(agent.sign_requests, [])

        agent_filter.close()

    @asynctest
    async def test_upstream_disconnect(self):
        """Test that upstream disconnect fails the request and closes"""

        agent = _FakeAgent(self.keys)
        agent.disconnect_on_sign = True

        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        resptype, _ = await self._send_request(
            agent_filter, transport,
            self._sign_request(self.allowed_key.public_data))

        self.assertEqual(resptype, SSH_AGENT_FAILURE)
        self.assertTrue(transport.closed)

        agent_filter.close()

    @asynctest
    async def test_close_cancels_pending_requests(self):
        """Test that closing the filter cancels outstanding requests"""

        agent = _FakeAgent(self.keys)
        agent.sign_event = asyncio.Event()

        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        payload = self._sign_request(self.allowed_key.public_data)
        agent_filter.data_received(UInt32(len(payload)) + payload)

        await asyncio.sleep(0.1)

        agent_filter.close()
        agent_filter.close()

        self.assertTrue(transport.closed)
        self.assertFalse(agent_filter._tasks)
        self.assertEqual(transport.data, b'')

        agent.sign_event.set()

    @asynctest
    async def test_eof(self):
        """Test that end of file from the remote end closes the filter"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        self.assertFalse(agent_filter.eof_received())
        self.assertTrue(transport.closed)

        agent_filter.close()

    @asynctest
    async def test_eof_with_pending_request(self):
        """Test that end of file waits for outstanding requests"""

        agent = _FakeAgent(self.keys)
        agent.sign_event = asyncio.Event()

        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        payload = self._sign_request(self.allowed_key.public_data)
        agent_filter.data_received(UInt32(len(payload)) + payload)

        await asyncio.sleep(0.1)

        self.assertFalse(agent_filter.eof_received())
        self.assertFalse(transport.closed)

        agent.sign_event.set()

        resptype, _, _ = await self._wait_response(transport, 0)
        self.assertEqual(resptype, SSH_AGENT_SIGN_RESPONSE)

        for _ in range(100):
            await asyncio.sleep(0.01)

            if transport.closed:
                break

        self.assertTrue(transport.closed)

    @asynctest
    async def test_connection_lost(self):
        """Test that a channel close shuts down the filter"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        agent_filter.connection_lost(None)

        self.assertTrue(transport.closed)

        agent_filter.close()

    @asynctest
    async def test_write_error(self):
        """Test that a channel write error closes the filter"""

        agent = _FakeAgent(self.keys)
        agent_filter, _ = await self._start_filter(
            agent, [self.allowed_key.public_data])

        transport = _FailingChannelTransport(BrokenPipeError())
        agent_filter.connection_made(transport)

        payload = Byte(SSH_AGENTC_REQUEST_IDENTITIES)
        agent_filter.data_received(UInt32(len(payload)) + payload)

        await asyncio.sleep(0.1)

        self.assertTrue(transport.closed)

    @asynctest
    async def test_unexpected_task_error(self):
        """Test that an unexpected request error closes the filter"""

        agent = _FakeAgent(self.keys)
        agent_filter, _ = await self._start_filter(
            agent, [self.allowed_key.public_data])

        transport = _FailingChannelTransport(ValueError())
        agent_filter.connection_made(transport)

        payload = Byte(SSH_AGENTC_REQUEST_IDENTITIES)
        agent_filter.data_received(UInt32(len(payload)) + payload)

        await asyncio.sleep(0.1)

        self.assertTrue(transport.closed)

    @asynctest
    async def test_process_frame_after_close(self):
        """Test that frames received after close are ignored"""

        agent = _FakeAgent(self.keys)
        agent_filter, transport = await self._start_filter(
            agent, [self.allowed_key.public_data])

        agent_filter.close()

        await agent_filter._process_frame(Byte(SSH_AGENTC_REQUEST_IDENTITIES))

        self.assertEqual(transport.data, b'')

    @asynctest
    async def test_connection_failed(self):
        """Test failure to connect to the SSH agent"""

        agent_filter = asyncssh.SSHAgentForwardingFilter(
            'fake_agent', [self.allowed_key.public_data])

        with self.assertRaises(OSError):
            await agent_filter.connect()
