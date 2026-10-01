"""Unit tests for structured multi-hop SSH connection chains"""

import asyncio
import errno

import asyncssh

from .util import AsyncTestCase, asynctest, get_test_key


class _MemoryPipe:
    """A bidirectional in-memory connection between two protocols

       This acts as a transport-level connection between a client and
       a local SSH service without requiring any real sockets, so the
       tests can run in environments where socket operations are
       restricted.

    """

    def __init__(self, loop):
        self._loop = loop
        self._protocols = [None, None]
        self._transports = [None, None]
        self._ready = asyncio.Event()
        self._closed = False
        self.ends = (_MemoryEnd(self, 0), _MemoryEnd(self, 1))

    def attach(self, side, transport, protocol):
        """Attach a protocol to one end of the pipe"""

        self._transports[side] = transport
        self._protocols[side] = protocol

        if all(self._protocols):
            # Signal readiness before delivering connection_made, so
            # that the caller of create_connection() regains control
            # and finishes wiring up the protocols before any data
            # can be delivered to them, matching the behavior of a
            # real transport
            self._loop.call_soon(self._ready.set)

            for i in (0, 1):
                self._loop.call_soon(self._protocols[i].connection_made,
                                     self._transports[i])

    async def wait_ready(self):
        """Wait for both ends to be attached and started"""

        await self._ready.wait()

    def write(self, side, data):
        """Deliver data to the protocol on the other end of the pipe"""

        peer = self._protocols[1 - side]

        if peer is not None and not self._closed:
            self._loop.call_soon(peer.data_received, data)

    def close(self):
        """Deliver connection loss to the protocols on both ends"""

        if not self._closed:
            self._closed = True

            for protocol in self._protocols:
                if protocol is not None:
                    self._loop.call_soon(protocol.connection_lost, None)


class _MemoryEnd:
    """A token for one end of a memory pipe, used in place of a socket"""

    def __init__(self, pipe, side):
        self.pipe = pipe
        self.side = side


class _MemoryTransport(asyncio.Transport):
    """An asyncio transport which carries data over a memory pipe"""

    def __init__(self, pipe, side):
        super().__init__()

        self._pipe = pipe
        self._side = side
        self._closing = False

    def write(self, data):
        """Write data to the pipe"""

        if not self._closing:
            self._pipe.write(self._side, data)

    def close(self):
        """Close the pipe"""

        if not self._closing:
            self._closing = True
            self._pipe.close()

    def abort(self):
        """Abruptly close the pipe"""

        self.close()

    def is_closing(self):
        """Return whether the pipe is closing"""

        return self._closing

    def write_eof(self):
        """Ignore end-of-file writes"""

    def can_write_eof(self):
        """Return that end-of-file writes are not supported"""

        return False

    def pause_reading(self):
        """Ignore read pauses"""

    def resume_reading(self):
        """Ignore read resumes"""


class _LocalNetwork:
    """An in-process network connecting clients to local SSH services

       This replaces the event loop's create_connection() so that
       connections to registered (host, port) pairs are carried over
       memory pipes to SSH services running in this process, avoiding
       the need for real socket operations.

       A periodic waker task is also started to work around
       restricted environments where writing to the event loop's
       self-pipe is blocked, stranding callbacks queued from other
       threads (such as executor completions) until the loop happens
       to wake up for another reason.

    """

    def __init__(self, loop):
        self._loop = loop
        self._services = {}
        self._tasks = []

        self._real_create_connection = loop.create_connection
        loop.create_connection = self._create_connection

        self._waker = loop.create_task(self._wake_loop())

    def close(self):
        """Restore the event loop's original create_connection()"""

        self._waker.cancel()

        self._loop.create_connection = self._real_create_connection

    async def _wake_loop(self):
        """Periodically wake the loop to process stranded callbacks"""

        while True:
            await asyncio.sleep(0.01)

    def add_service(self, host, port, **server_kwargs):
        """Register an SSH service at a host and port"""

        self._services[(host, port)] = server_kwargs

    async def _run_service(self, server_end, server_kwargs):
        """Run an SSH service on one end of a memory pipe"""

        try:
            await asyncssh.run_server(server_end, **server_kwargs)
        except Exception: # pragma: no cover
            pass

    async def _create_connection(self, protocol_factory, host=None, port=None,
                                 **kwargs):
        """Connect to a registered SSH service over a memory pipe"""

        sock = kwargs.get('sock')

        if isinstance(sock, _MemoryEnd):
            protocol = protocol_factory()
            transport = _MemoryTransport(sock.pipe, sock.side)
            sock.pipe.attach(sock.side, transport, protocol)
            return transport, protocol

        try:
            server_kwargs = self._services[(host, port)]
        except KeyError:
            raise OSError(errno.ECONNREFUSED,
                          'Connection refused') from None

        pipe = _MemoryPipe(self._loop)

        self._tasks.append(asyncio.ensure_future(
            self._run_service(pipe.ends[1], server_kwargs)))

        protocol = protocol_factory()
        transport = _MemoryTransport(pipe, 0)
        pipe.attach(0, transport, protocol)

        # Wait for the service on the other end of the pipe to be
        # attached and for both ends to be started, mirroring how
        # asyncio's create_connection() only returns after the
        # connection is fully established
        await pipe.wait_ready()

        return transport, protocol

    async def wait(self):
        """Wait for all spawned SSH services to finish"""

        if self._tasks:
            await asyncio.wait(self._tasks, timeout=5)


class _HopSession(asyncssh.SSHServerSession):
    """A session which echoes back the requested command"""

    def __init__(self):
        self._chan = None
        self._command = None

    def connection_made(self, chan):
        """Handle session open"""

        self._chan = chan

    def exec_requested(self, command):
        """Handle command execution"""

        self._command = command

        return True

    def session_started(self):
        """Handle session start"""

        self._chan.write(f'executed:{self._command}')
        self._chan.exit(0)
        self._chan.close()


class _HopServer(asyncssh.SSHServer):
    """SSH server for a single hop, recording its connections"""

    def __init__(self, username, client_key):
        self._username = username
        self._client_key = client_key

        self.conn = None
        self.close_event = asyncio.Event()

    def connection_made(self, conn):
        """Record the new connection"""

        self.conn = conn

    def connection_lost(self, exc):
        """Record the connection closing"""

        self.close_event.set()

    def begin_auth(self, username):
        """Require public key authentication"""

        return True

    def public_key_auth_supported(self):
        """Return that public key authentication is supported"""

        return True

    def validate_public_key(self, username, key):
        """Validate the hop-specific username and client key"""

        trusted_key = self._client_key.export_public_key()

        return (username == self._username and
                key.export_public_key() == trusted_key)

    def connection_requested(self, dest_host, dest_port,
                             orig_host, orig_port):
        """Allow direct TCP/IP forwarding through this hop"""

        # pylint: disable=unused-argument

        return True

    def session_requested(self):
        """Handle a request to create a new session"""

        return _HopSession()


class _Hop:
    """A local SSH service acting as a single hop"""

    def __init__(self, network, username, host_key, client_key, port):
        self.username = username
        self.host_key = host_key
        self.client_key = client_key
        self.host = '127.0.0.1'
        self.port = port
        self.servers = []

        def server_factory():
            """Create a server instance and record it"""

            server = _HopServer(username, client_key)
            self.servers.append(server)
            return server

        network.add_service(self.host, self.port,
                            server_factory=server_factory,
                            server_host_keys=[host_key], gss_host=None)

    @property
    def known_hosts(self):
        """Return known_hosts data matching this hop's host key"""

        return (f'[{self.host}]:{self.port} '.encode() +
                self.host_key.export_public_key())

    def config(self, **kwargs):
        """Return an SSHChainHop for connecting to this hop"""

        kwargs.setdefault('username', self.username)
        kwargs.setdefault('client_keys', [self.client_key])
        kwargs.setdefault('known_hosts', self.known_hosts)

        return asyncssh.SSHChainHop(self.host, self.port, **kwargs)

    async def connect(self, **kwargs):
        """Open a direct connection to this hop"""

        return await asyncssh.connect(
            self.host, self.port, username=self.username,
            client_keys=[self.client_key], known_hosts=self.known_hosts,
            **kwargs)


class TestConnectChain(AsyncTestCase):
    """Unit tests for asyncssh.connect_chain"""

    async def asyncSetUp(self):
        self.network = _LocalNetwork(self.loop)

        self.hops = []

        for i in range(3):
            self.hops.append(_Hop(self.network, f'user{i}',
                                  get_test_key('ssh-rsa', 10 + i),
                                  get_test_key('ssh-rsa', 20 + i),
                                  9001 + i))

    async def asyncTearDown(self):
        self.network.close()
        await self.network.wait()

    @asynctest
    async def test_connect_chain(self):
        """Test connecting to a target through a chain of hops"""

        conn = await asyncssh.connect_chain([hop.config()
                                             for hop in self.hops])

        try:
            result = await conn.run('hello')
            self.assertEqual(result.stdout, 'executed:hello')

            # Each hop authenticated with its own username and key, and
            # the final connection is verified against the target's key
            for i, hop in enumerate(self.hops):
                self.assertEqual(len(hop.servers), 1)
                server_conn = hop.servers[0].conn
                self.assertEqual(server_conn.get_extra_info('username'),
                                 f'user{i}')

            self.assertEqual(conn.get_server_host_key().export_public_key(),
                             self.hops[2].host_key.export_public_key())
        finally:
            conn.close()
            await conn.wait_closed()

        # Closing the target connection releases the whole chain
        for hop in self.hops:
            await asyncio.wait_for(hop.servers[0].close_event.wait(), 5)

    @asynctest
    async def test_second_hop_host_key_changed(self):
        """Test a host key change at the second hop failing the chain"""

        changed_key = get_test_key('ssh-rsa', 30)
        changed_known_hosts = (
            f'[{self.hops[1].host}]:{self.hops[1].port} '.encode() +
            changed_key.export_public_key())

        hops = [self.hops[0].config(),
                self.hops[1].config(known_hosts=changed_known_hosts),
                self.hops[2].config()]

        with self.assertRaises(asyncssh.SSHChainError) as cm:
            await asyncssh.connect_chain(hops)

        self.assertEqual(cm.exception.hop_index, 1)
        self.assertIn('Hop 1', str(cm.exception))
        self.assertNotIn('PRIVATE KEY', str(cm.exception))

        # The first hop connection created by the call was released
        self.assertEqual(len(self.hops[0].servers), 1)
        await asyncio.wait_for(self.hops[0].servers[0].close_event.wait(), 5)

        # The target was never contacted
        self.assertEqual(len(self.hops[2].servers), 0)

    @asynctest
    async def test_existing_connection_retained_on_close(self):
        """Test caller-provided connections surviving target close"""

        existing = await self.hops[0].connect()

        conn = await asyncssh.connect_chain(
            [existing, self.hops[1].config(), self.hops[2].config()])

        result = await conn.run('hello')
        self.assertEqual(result.stdout, 'executed:hello')

        conn.close()
        await conn.wait_closed()

        # The intermediate connection created by connect_chain was
        # closed along with the target connection
        await asyncio.wait_for(self.hops[1].servers[0].close_event.wait(), 5)
        await asyncio.wait_for(self.hops[2].servers[0].close_event.wait(), 5)

        # The caller-provided connection remains open and usable
        self.assertFalse(existing.is_closed())

        result = await existing.run('hello')
        self.assertEqual(result.stdout, 'executed:hello')

        existing.close()
        await existing.wait_closed()

    @asynctest
    async def test_existing_connection_retained_on_failure(self):
        """Test caller-provided connections surviving a chain failure"""

        existing = await self.hops[0].connect()

        changed_key = get_test_key('ssh-rsa', 30)
        changed_known_hosts = (
            f'[{self.hops[1].host}]:{self.hops[1].port} '.encode() +
            changed_key.export_public_key())

        hops = [existing,
                self.hops[1].config(known_hosts=changed_known_hosts),
                self.hops[2].config()]

        with self.assertRaises(asyncssh.SSHChainError) as cm:
            await asyncssh.connect_chain(hops)

        self.assertEqual(cm.exception.hop_index, 1)

        # The caller-provided connection remains open and usable
        self.assertFalse(existing.is_closed())

        result = await existing.run('hello')
        self.assertEqual(result.stdout, 'executed:hello')

        existing.close()
        await existing.wait_closed()

    @asynctest
    async def test_error_excludes_private_key_info(self):
        """Test chain errors not leaking private key information"""

        hops = [self.hops[0].config(),
                self.hops[1].config(client_keys=[get_test_key('ssh-rsa', 31)],
                                    passphrase='secret'),
                self.hops[2].config()]

        with self.assertRaises(asyncssh.SSHChainError) as cm:
            await asyncssh.connect_chain(hops)

        self.assertEqual(cm.exception.hop_index, 1)
        self.assertNotIn('secret', str(cm.exception))
        self.assertNotIn('PRIVATE KEY', str(cm.exception))

        # The first hop connection created by the call was released
        await asyncio.wait_for(self.hops[0].servers[0].close_event.wait(), 5)

    @asynctest
    async def test_hop_repr_excludes_private_key_info(self):
        """Test hop repr not leaking private key information"""

        hop = asyncssh.SSHChainHop('host', username='user',
                                   client_keys=['key'], passphrase='secret')

        self.assertNotIn('secret', repr(hop))
        self.assertNotIn('key', repr(hop))

    @asynctest
    async def test_invalid_chain(self):
        """Test invalid chain arguments being rejected"""

        with self.assertRaises(ValueError):
            await asyncssh.connect_chain([])

        existing = await self.hops[0].connect()

        try:
            with self.assertRaises(ValueError):
                await asyncssh.connect_chain([existing])
        finally:
            existing.close()
            await existing.wait_closed()
