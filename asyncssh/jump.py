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

"""Structured multi-hop SSH jump chain support

   This module provides :class:`SSHJumpHop` and :func:`connect_jump` to
   open an SSH connection to a target host through a chain of SSH jump
   hosts. Each hop in the chain carries its own independent connection
   parameters, so host key verification and authentication are performed
   separately for every hop. Settings such as the trusted host keys or
   agent forwarding configuration of one hop are never implicitly
   inherited by other hops in the chain.

"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Union

from .connection import SSHClientConnection, connect
from .known_hosts import KnownHostsArg
from .misc import BytesOrStr, Error, async_context_manager
from .public_key import KeyPairListArg


_private_key_pattern = re.compile(
    r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?'
    r'-----END [A-Z0-9 ]*PRIVATE KEY-----', re.DOTALL)


def _sanitize_reason(reason: str) -> str:
    """Remove any private key material from an error message"""

    return _private_key_pattern.sub('[private key redacted]', reason)


class SSHJumpError(Error):
    """Error raised when a hop in an SSH jump chain fails

       This exception reports which hop in the jump chain failed. The
       associated reason is sanitized to ensure it never contains
       private key material.

       :param hop_index:
           The index of the hop which failed, starting at 0 for the
           first hop in the chain
       :param host:
           The host of the hop which failed
       :param port:
           The port of the hop which failed
       :param reason:
           A human-readable reason for the failure
       :type hop_index: `int`
       :type host: `str`
       :type port: `int`
       :type reason: `str`

    """

    def __init__(self, hop_index: int, host: str, port: int, reason: str):
        self.hop_index = hop_index
        self.hop_host = host
        self.hop_port = port

        super().__init__(0, f'Jump chain hop {hop_index} '
                            f'({host}:{port}) failed: '
                            f'{_sanitize_reason(reason)}')


@dataclass
class SSHJumpHop:
    """Connection parameters for a single hop in an SSH jump chain

       Each hop explicitly specifies its own host key validation and
       authentication settings. Nothing is inherited from other hops:
       in particular, the ``known_hosts`` trust policy and the
       ``agent_forwarding`` setting apply only to the hop they are
       configured on.

       :param host:
           The hostname or address to connect to for this hop
       :param port: (optional)
           The port to connect to, defaulting to the default SSH port
       :param username: (optional)
           The username to authenticate as on this hop
       :param password: (optional)
           The password to authenticate with on this hop
       :param client_keys: (optional)
           The client keys to authenticate with on this hop
       :param passphrase: (optional)
           The passphrase used to decrypt encrypted client keys
       :param known_hosts: (optional)
           The trusted host keys used to validate this hop's server
           host key. If not specified, the default known hosts files
           are used, independently of any other hop's configuration.
       :param agent_path: (optional)
           The path of an SSH agent to use for authentication on this hop
       :param agent_forwarding: (optional)
           Whether to allow agent forwarding on this hop's connection,
           defaulting to `False`
       :param options: (optional)
           Additional keyword arguments to pass to
           :func:`asyncssh.connect` for this hop

    """

    host: str
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    client_keys: Optional[KeyPairListArg] = None
    passphrase: Optional[BytesOrStr] = None
    known_hosts: KnownHostsArg = ()
    agent_path: object = ()
    agent_forwarding: bool = False
    options: Dict[str, Any] = field(default_factory=dict)

    def _connect_kwargs(self) -> Dict[str, Any]:
        """Build keyword arguments for connecting to this hop only"""

        kwargs: Dict[str, Any] = dict(self.options)

        if self.port is not None:
            kwargs['port'] = self.port

        if self.username is not None:
            kwargs['username'] = self.username

        if self.password is not None:
            kwargs['password'] = self.password

        if self.client_keys is not None:
            kwargs['client_keys'] = self.client_keys

        if self.passphrase is not None:
            kwargs['passphrase'] = self.passphrase

        if self.agent_path != ():
            kwargs['agent_path'] = self.agent_path

        kwargs['known_hosts'] = self.known_hosts
        kwargs['agent_forwarding'] = self.agent_forwarding

        return kwargs


@async_context_manager
async def connect_jump(hops: Sequence[Union[SSHJumpHop,
                                            SSHClientConnection]]) -> \
        SSHClientConnection:
    """Open an SSH connection through a chain of jump hosts

       This function is a coroutine which connects through each hop in
       ``hops`` in order, returning an :class:`SSHClientConnection` to
       the final hop (the target). Each entry may be either an
       :class:`SSHJumpHop` describing the connection parameters for
       that hop, or an already-open :class:`SSHClientConnection`
       provided by the caller.

       Every hop performs its own host key verification and
       authentication based solely on its own configuration. No trust
       policy, credentials, or agent forwarding settings are inherited
       from previous hops.

       Connections created by this call are owned by the returned
       connection: closing it closes the intermediate connections which
       were created here. Connections passed in by the caller remain
       the caller's responsibility and are never closed by this
       function, neither on failure nor when the returned connection
       is closed.

       If connecting to a hop fails, all connections created by this
       call are closed before an :class:`SSHJumpError` is raised
       identifying the failed hop.

       :param hops:
           A non-empty sequence of hops to connect through, where the
           last entry is the target host
       :return: An :class:`SSHClientConnection` to the target host

    """

    if not hops:
        raise ValueError('At least one jump hop is required')

    created: List[SSHClientConnection] = []
    conn: Optional[SSHClientConnection] = None
    conn_owned = False

    try:
        for index, hop in enumerate(hops):
            if isinstance(hop, SSHClientConnection):
                conn, conn_owned = hop, False
                continue

            if not isinstance(hop, SSHJumpHop):
                raise TypeError(f'Jump chain hop {index} must be an '
                                f'SSHJumpHop or SSHClientConnection, '
                                f'got {type(hop).__name__}')

            kwargs = hop._connect_kwargs()

            if conn is not None:
                kwargs['tunnel'] = conn

            try:
                new_conn = await connect(hop.host, **kwargs)
            except Exception as exc:
                raise SSHJumpError(index, hop.host, hop.port or 22,
                                   str(exc)) from exc

            if conn_owned:
                # Chain ownership of connections created here, so that
                # closing the returned connection closes all of them.
                # Caller-provided connections are never chained this
                # way and remain owned by the caller.
                new_conn.set_tunnel(conn)

            created.append(new_conn)
            conn, conn_owned = new_conn, True
    except BaseException:
        for created_conn in reversed(created):
            created_conn.close()

        await asyncio.gather(*(created_conn.wait_closed()
                               for created_conn in reversed(created)),
                             return_exceptions=True)
        raise

    assert conn is not None # for mypy
    return conn
