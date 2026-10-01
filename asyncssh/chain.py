"""Support for structured multi-hop SSH connection chains

   This module provides :func:`connect_chain`, which connects to a
   target host through a chain of SSH jump hosts. Each hop in the
   chain is described by an :class:`SSHChainHop` with its own
   independent host key verification and authentication settings, so
   trust policies and agent forwarding settings are never implicitly
   inherited from one hop to the next.

"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Union

from .connection import SSHClientConnection, connect
from .known_hosts import KnownHostsArg
from .misc import BytesOrStr, Error
from .public_key import KeyPairListArg


class SSHChainError(Error):
    """A hop in a multi-hop SSH connection chain failed

       This error reports which hop in the chain failed, identified by
       its zero-based index, host, and port. The associated reason is
       taken from the underlying error, but never includes private key
       material or passphrases from the hop configuration.

       :param hop_index:
           The zero-based index of the hop which failed
       :param host:
           The host of the hop which failed
       :param port:
           The port of the hop which failed
       :param reason:
           A human-readable reason for the failure

    """

    def __init__(self, hop_index: int, host: str, port: int, reason: str):
        super().__init__(0, f'Hop {hop_index} ({host}:{port}): {reason}')

        self.hop_index = hop_index
        self.host = host
        self.port = port


@dataclass
class SSHChainHop:
    """Connection parameters for a single hop in an SSH chain

       Each hop carries its own fully independent set of connection
       parameters. Host key verification (``known_hosts``) and
       ``agent_forwarding`` are always passed explicitly to each hop,
       so the trust policy or agent forwarding setting of one hop is
       never implicitly carried over to any other hop.

       The ``passphrase`` and ``client_keys`` fields are excluded from
       this object's ``repr()`` to avoid leaking private key material
       into logs or error output.

       :param host:
           The host to connect to for this hop
       :param port: (optional)
           The port to connect to for this hop, defaulting to 22
       :param username: (optional)
           The username to authenticate as on this hop
       :param client_keys: (optional)
           The client keys to authenticate with on this hop
       :param passphrase: (optional)
           The passphrase used to decrypt this hop's client keys
       :param known_hosts: (optional)
           The known hosts to verify this hop's host key against,
           defaulting to the system and user default known hosts files
       :param agent_forwarding: (optional)
           Whether to allow agent forwarding on this hop, defaulting
           to :data:`False`
       :param options: (optional)
           Additional keyword arguments to pass to :func:`connect`
           for this hop

    """

    host: str
    port: int = 22
    username: Optional[str] = None
    client_keys: Optional[KeyPairListArg] = field(default=None, repr=False)
    passphrase: Optional[BytesOrStr] = field(default=None, repr=False)
    known_hosts: KnownHostsArg = ()
    agent_forwarding: bool = False
    options: Dict[str, Any] = field(default_factory=dict, repr=False)

    def connect_args(self) -> Dict[str, Any]:
        """Build the per-hop keyword arguments for :func:`connect`"""

        args = dict(self.options)

        if self.username is not None:
            args['username'] = self.username

        if self.client_keys is not None:
            args['client_keys'] = self.client_keys

        if self.passphrase is not None:
            args['passphrase'] = self.passphrase

        # Host key trust policy and agent forwarding are always set
        # explicitly on each hop, so they can never be inherited from
        # the settings of a previous hop.
        args['known_hosts'] = self.known_hosts
        args['agent_forwarding'] = self.agent_forwarding

        return args


HopSpec = Union[SSHClientConnection, SSHChainHop]


async def connect_chain(hops: Sequence[HopSpec]) -> SSHClientConnection:
    """Connect to a target host through a chain of SSH hops

       Each element of ``hops`` is either an :class:`SSHChainHop`
       describing a hop to connect to, or an existing
       :class:`SSHClientConnection` provided by the caller to be used
       as-is as a hop in the chain. The last element must be an
       :class:`SSHChainHop` describing the target host, and the
       connection to it is returned.

       Every hop performs its own host key verification and
       authentication based solely on its own :class:`SSHChainHop`
       parameters -- no trust policy, credentials, or agent forwarding
       settings are inherited from other hops.

       Connections created by this call are linked together, so
       closing the returned target connection will close all of the
       intermediate connections created by this call. Connections
       passed in by the caller are never closed by this function, and
       remain open after the returned connection is closed.

       If a hop fails, all connections created by this call are
       closed before an :class:`SSHChainError` is raised identifying
       the failed hop. Caller-provided connections are left open.

       :param hops:
           The sequence of hops to connect through
       :returns: An :class:`SSHClientConnection` to the target host
       :raises SSHChainError: if a hop in the chain fails
       :raises ValueError: if the hop list is empty or invalid

    """

    if not hops:
        raise ValueError('At least one hop is required')

    if isinstance(hops[-1], SSHClientConnection):
        raise ValueError('The last hop must be an SSHChainHop, '
                         'not an existing connection')

    created: List[SSHClientConnection] = []
    prev: Optional[SSHClientConnection] = None
    prev_owned = False

    try:
        for index, hop in enumerate(hops):
            if isinstance(hop, SSHClientConnection):
                prev, prev_owned = hop, False
            elif isinstance(hop, SSHChainHop):
                try:
                    conn = await connect(hop.host, hop.port,
                                         tunnel=prev or (),
                                         **hop.connect_args())
                except Exception as exc:
                    raise SSHChainError(index, hop.host, hop.port,
                                        str(exc)) from exc

                # Link connections created by this call, so that closing
                # the target connection releases the entire chain. Links
                # to caller-provided connections are deliberately not
                # created, so their ownership stays with the caller.
                if prev_owned:
                    conn.set_tunnel(prev)

                created.append(conn)
                prev, prev_owned = conn, True
            else:
                raise TypeError(f'Invalid hop at index {index}: '
                                f'{type(hop).__name__}')
    except BaseException:
        for conn in reversed(created):
            conn.close()

        for conn in reversed(created):
            await conn.wait_closed()

        raise

    assert prev is not None # pragma: no cover
    return prev
