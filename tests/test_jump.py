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
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later

"""Unit tests for multi-hop SSH jump chains"""

import asyncio
from functools import partial
import os

import asyncssh
from asyncssh import SSHJumpError, SSHJumpHop, connect_jump

from .util import AsyncTestCase, asynctest, get_test_key


class _JumpServer(asyncssh.SSHServer):
    """SSH test server requiring hop-specific password authentication"""

    instances = []

    def __init__(self, username, password):
        self._expected_username = username
        self._expected_password = password
        self.conn = None
        self.auths = []

        _JumpServer.instances.append(self)

    def connection_made(self, conn):
        """Record the server-side connection"""

        self.conn = conn

    def begin_auth(self, username):
        """Require authentication for all users"""

        return True

    def password_auth_supported(self):
        """Enable password authentication"""

        return True

    def validate_password(self, username, password):
        """Validate hop-specific username and password"""

        self.auths.append(username)

        return (username == self._expected_username and
                password == self._expected_password)

    def connection_requested(self, dest_host, dest_port,
                             orig_host, orig_port):
        """Allow direct TCP/IP forwarding to the next hop"""

        return True


class _TestJumpChain(AsyncTestCase):
    """Unit tests for connect_jump using three local SSH servers"""

    servers = []
    ports = []

    @classmethod
    async def asyncSetUpClass(cls):
        """Start three SSH servers, each with its own host key"""

        for i in range(3):
            skey = get_test_key('ssh-rsa', key_id=20+i)
            skey.write_private_key(f'skey{i}')
            os.chmod(f'skey{i}', 0o600)

            server = await asyncssh.listen(
                '127.0.0.1', 0,
                server_factory=partial(_JumpServer, f'user{i}', f'pw{i}'),
                server_host_keys=[f'skey{i}'])

            cls.servers.append(server)
            cls.ports.append(server.get_port())

            with open(f'kh{i}', 'w') as known_hosts:
                known_hosts.write(f'[127.0.0.1]:{server.get_port()} ')
                known_hosts.write(skey.export_public_key().decode())

        # A known_hosts file for hop 2 (index 1) containing a different
        # host key, simulating a changed host key on that hop
        changed_key = get_test_key('ssh-rsa', key_id=30)

        with open('kh1_changed', 'w') as known_hosts:
            known_hosts.write(f'[127.0.0.1]:{cls.ports[1]} ')
            known_hosts.write(changed_key.export_public_key().decode())

    @classmethod
    async def asyncTearDownClass(cls):
        """Shut down the SSH servers"""

        for server in cls.servers:
            server.close()
            await server.wait_closed()

    def setUp(self):
        """Reset the list of server-side connections"""

        _JumpServer.instances.clear()

    def hop(self, index, **kwargs):
        """Return a hop description for one of the test servers"""

        hop_kwargs = dict(port=self.ports[index], username=f'user{index}',
                          password=f'pw{index}', known_hosts=f'kh{index}',
                          client_keys=[], agent_path=None)
        hop_kwargs.update(kwargs)

        return SSHJumpHop('127.0.0.1', **hop_kwargs)

    async def open_hop(self, index):
        """Open a caller-owned connection to one of the test servers"""

        return await asyncssh.connect(
            '127.0.0.1', self.ports[index], username=f'user{index}',
            password=f'pw{index}', known_hosts=f'kh{index}',
            client_keys=[], agent_path=None)

    @asynctest
    async def test_jump_chain(self):
        """Test connecting through a three-hop jump chain"""

        async with connect_jump([self.hop(0), self.hop(1),
                                 self.hop(2)]) as conn:
            self.assertEqual(conn.get_extra_info('username'), 'user2')

        # Each hop must have authenticated independently with its own
        # hop-specific username
        self.assertEqual([inst.auths for inst in _JumpServer.instances],
                         [['user0'], ['user1'], ['user2']])

        # Closing the target connection closes the connections created
        # for the intermediate hops
        for inst in _JumpServer.instances:
            await asyncio.wait_for(inst.conn.wait_closed(), 10)

    @asynctest
    async def test_jump_chain_host_key_changed(self):
        """Test failure when the second hop's host key has changed"""

        hops = [self.hop(0), self.hop(1, known_hosts='kh1_changed'),
                self.hop(2)]

        with self.assertRaises(SSHJumpError) as cm:
            await connect_jump(hops)

        exc = cm.exception
        self.assertEqual(exc.hop_index, 1)
        self.assertIn('hop 1', str(exc))
        self.assertNotIn('PRIVATE KEY', str(exc))

        # The connection created for the first hop must be released
        await asyncio.wait_for(_JumpServer.instances[0].conn.wait_closed(), 10)

    @asynctest
    async def test_jump_chain_existing_connection(self):
        """Test ownership handling with a caller-provided connection"""

        caller_conn = await self.open_hop(0)

        try:
            conn = await connect_jump([caller_conn, self.hop(1),
                                       self.hop(2)])

            conn.close()
            await conn.wait_closed()

            # The intermediate connection created by connect_jump is
            # closed when the target connection closes
            await asyncio.wait_for(_JumpServer.instances[1].conn.wait_closed(),
                                   10)

            # The caller-provided connection remains open
            self.assertFalse(caller_conn.is_closed())
            self.assertFalse(_JumpServer.instances[0].conn.is_closed())
        finally:
            caller_conn.close()
            await caller_conn.wait_closed()

    @asynctest
    async def test_jump_chain_failure_preserves_existing(self):
        """Test that failure doesn't close caller-provided connections"""

        caller_conn = await self.open_hop(0)

        try:
            with self.assertRaises(SSHJumpError) as cm:
                await connect_jump([caller_conn,
                                    self.hop(1, known_hosts='kh1_changed')])

            self.assertEqual(cm.exception.hop_index, 1)
            self.assertFalse(caller_conn.is_closed())
        finally:
            caller_conn.close()
            await caller_conn.wait_closed()

    @asynctest
    async def test_jump_chain_no_hops(self):
        """Test that an empty hop list is rejected"""

        with self.assertRaises(ValueError):
            await connect_jump([])

    def test_jump_error_sanitizes_private_key(self):
        """Test that jump errors never contain private key material"""

        key_data = ('-----BEGIN OPENSSH PRIVATE KEY-----\n'
                    'secret-key-material\n'
                    '-----END OPENSSH PRIVATE KEY-----')

        exc = SSHJumpError(2, 'example.com', 2222,
                           f'Authentication failed: {key_data}')

        self.assertEqual(exc.hop_index, 2)
        self.assertIn('hop 2', str(exc))
        self.assertNotIn('secret-key-material', str(exc))
        self.assertNotIn('PRIVATE KEY', str(exc))

    def test_hop_settings_are_independent(self):
        """Test that hop settings are never inherited by other hops"""

        hop1 = SSHJumpHop('host1', known_hosts='kh1', agent_forwarding=True)
        hop2 = SSHJumpHop('host2')

        kwargs1 = hop1._connect_kwargs() # pylint: disable=protected-access
        kwargs2 = hop2._connect_kwargs() # pylint: disable=protected-access

        self.assertEqual(kwargs1['known_hosts'], 'kh1')
        self.assertEqual(kwargs2['known_hosts'], ())
        self.assertTrue(kwargs1['agent_forwarding'])
        self.assertFalse(kwargs2['agent_forwarding'])
