# Copyright (c) 2013-2025 by Ron Frederick <ronf@timeheart.net> and others.
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

"""SSH port forwarding handlers"""

import asyncio
from collections import deque
import socket
from types import TracebackType
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Deque, Dict
from typing import Optional, Sequence, Tuple
from typing import Type, cast
from typing_extensions import Self

from .misc import ChannelOpenError, SockAddr
from .packet import Byte, PacketDecodeError, SSHPacket, String, UInt32


if TYPE_CHECKING:
    # pylint: disable=cyclic-import
    from .connection import SSHConnection


SSHForwarderCoro = Callable[..., Awaitable]

SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENTC_SIGN_REQUEST = 13

SSH_AGENT_FAILURE = 5
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENT_SIGN_RESPONSE = 14

SSH_AGENT_MAX_MESSAGE_SIZE = 256 * 1024


class SSHForwarder(asyncio.BaseProtocol):
    """SSH port forwarding connection handler"""

    def __init__(self, peer: Optional['SSHForwarder'] = None,
                 extra: Optional[Dict[str, Any]] = None):
        self._peer = peer
        self._transport: Optional[asyncio.Transport] = None
        self._inpbuf = b''
        self._eof_received = False

        if peer:
            peer.set_peer(self)

        if extra is None:
            extra = {}

        self._extra = extra

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, _exc_type: Optional[Type[BaseException]],
                        _exc_value: Optional[BaseException],
                        _traceback: Optional[TracebackType]) -> bool:
        self.close()
        return False

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """Get additional information about the forwarder

           This method returns extra information about the forwarder.
           Currently, the only information available is the value
           ``interface`` for TUN/TAP forwarders, returning the name of the
           local TUN/TAP network interface created for this forwarder.

        """

        return self._extra.get(name, default)

    def set_peer(self, peer: 'SSHForwarder') -> None:
        """Set the peer forwarder to exchange data with"""

        self._peer = peer

    def write(self, data: bytes) -> None:
        """Write data to the transport"""

        if not self._transport:
            return # pragma: no cover

        try:
            self._transport.write(data)
        except OSError: # pragma: no cover
            pass

    def write_eof(self) -> None:
        """Write end of file to the transport"""

        if not self._transport:
            return # pragma: no cover

        try:
            self._transport.write_eof()
        except OSError: # pragma: no cover
            pass

    def was_eof_received(self) -> bool:
        """Return whether end of file has been received or not"""

        return self._eof_received

    def pause_reading(self) -> None:
        """Pause reading from the transport"""

        assert self._transport is not None
        self._transport.pause_reading()

    def resume_reading(self) -> None:
        """Resume reading on the transport"""

        assert self._transport is not None
        self._transport.resume_reading()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a newly opened connection"""

        self._transport = cast(Optional['asyncio.Transport'], transport)

        sock = cast(socket.socket, transport.get_extra_info('socket'))

        if sock and sock.family in {socket.AF_INET, socket.AF_INET6}:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Handle an incoming connection close"""

        # pylint: disable=unused-argument

        self.close()

    def session_started(self) -> None:
        """Handle session start"""

    def data_received(self, data: bytes,
                      datatype: Optional[int] = None) -> None:
        """Handle incoming data from the transport"""

        # pylint: disable=unused-argument

        if self._peer:
            self._peer.write(data)
        else:
            self._inpbuf += data

    def eof_received(self) -> bool:
        """Handle an incoming end of file from the transport"""

        self._eof_received = True

        if self._peer:
            self._peer.write_eof()

            return not self._peer.was_eof_received()
        else:
            return True

    def pause_writing(self) -> None:
        """Pause writing by asking peer to pause reading"""

        if self._peer: # pragma: no branch
            self._peer.pause_reading()

    def resume_writing(self) -> None:
        """Resume writing by asking peer to resume reading"""

        if self._peer: # pragma: no branch
            self._peer.resume_reading()

    def close(self) -> None:
        """Close this port forwarder"""

        if self._transport:
            self._transport.close()
            self._transport = None

        if self._peer:
            peer = self._peer
            self._peer = None
            peer.close()


class SSHRestrictedAgentForwarder(SSHForwarder):
    """Restricted SSH agent forwarding connection handler"""

    def __init__(self, identities: Sequence[bytes],
                 peer: Optional[SSHForwarder] = None):
        super().__init__(peer)

        self._identities = set(identities)
        self._request_buf = b''
        self._response_buf = b''
        self._request_queue: Deque[bytes] = deque()
        self._outstanding_request: Optional[int] = None

    @staticmethod
    def _get_frame(buf: bytes) -> Tuple[Optional[bytes], bytes]:
        """Extract one complete SSH agent message from a buffer"""

        if len(buf) < 4:
            return None, buf

        msglen = int.from_bytes(buf[:4], 'big')

        if not 1 <= msglen <= SSH_AGENT_MAX_MESSAGE_SIZE or \
                len(buf) < 4 + msglen:
            if msglen > SSH_AGENT_MAX_MESSAGE_SIZE or msglen == 0:
                raise PacketDecodeError('Invalid SSH agent message length')

            return None, buf

        return buf[:4 + msglen], buf[4 + msglen:]

    def _denied(self) -> bytes:
        """Return an SSH agent failure message"""

        payload = Byte(SSH_AGENT_FAILURE)
        return UInt32(len(payload)) + payload

    def _check_request(self, frame: bytes) -> bool:
        """Validate a request and determine whether it may be forwarded"""

        packet = SSHPacket(frame[4:])
        msgtype = packet.get_byte()

        if msgtype == SSH_AGENTC_REQUEST_IDENTITIES:
            packet.check_end()
            return True
        elif msgtype == SSH_AGENTC_SIGN_REQUEST:
            key_blob = packet.get_string()
            packet.get_string()
            packet.get_uint32()
            packet.check_end()

            return key_blob in self._identities
        else:
            return False

    def _filter_identities(self, frame: bytes) -> bytes:
        """Return only the authorized identities in an agent response"""

        packet = SSHPacket(frame[4:])
        msgtype = packet.get_byte()

        if msgtype == SSH_AGENT_FAILURE:
            packet.check_end()
            return frame

        if msgtype != SSH_AGENT_IDENTITIES_ANSWER:
            raise PacketDecodeError('Unexpected SSH agent response')

        requested_keys = packet.get_uint32()
        identities = b''
        num_keys = 0

        for _ in range(requested_keys):
            key_blob = packet.get_string()
            comment = packet.get_string()

            if key_blob in self._identities:
                identities += String(key_blob) + String(comment)
                num_keys += 1

        packet.check_end()

        payload = Byte(SSH_AGENT_IDENTITIES_ANSWER) + UInt32(num_keys) + \
            identities
        return UInt32(len(payload)) + payload

    def _check_response(self, frame: bytes) -> bytes:
        """Validate and, where necessary, filter an agent response"""

        assert self._outstanding_request is not None

        packet = SSHPacket(frame[4:])
        msgtype = packet.get_byte()

        if msgtype == SSH_AGENT_FAILURE:
            packet.check_end()
        elif self._outstanding_request == SSH_AGENTC_REQUEST_IDENTITIES:
            frame = self._filter_identities(frame)
        elif self._outstanding_request == SSH_AGENTC_SIGN_REQUEST:
            if msgtype != SSH_AGENT_SIGN_RESPONSE:
                raise PacketDecodeError('Unexpected SSH agent response')

            packet.get_string()
            packet.check_end()
        else: # pragma: no cover
            raise PacketDecodeError('Unexpected SSH agent response')

        return frame

    def _send_next(self) -> None:
        """Send the next queued request, returning local failures inline"""

        try:
            while self._request_queue and self._outstanding_request is None:
                frame = self._request_queue.popleft()
                msgtype = frame[4]

                if self._check_request(frame):
                    self._outstanding_request = msgtype

                    assert self._peer is not None
                    self.pause_reading()
                    self._peer.write(frame)
                else:
                    SSHForwarder.write(self, self._denied())
        except PacketDecodeError:
            self.close()

    def _request_data_received(self, data: bytes) -> None:
        """Parse complete agent requests before forwarding them"""

        self._request_buf += data

        try:
            while self._request_buf:
                frame, self._request_buf = self._get_frame(self._request_buf)

                if frame is None:
                    break

                self._request_queue.append(frame)
        except PacketDecodeError:
            self.close()
            return

        self._send_next()

    def _response_data_received(self, data: bytes) -> None:
        """Validate complete agent responses before delivering them"""

        if self._outstanding_request is None:
            self.close()
            return

        self._response_buf += data

        try:
            frame, self._response_buf = self._get_frame(self._response_buf)

            if frame is None:
                return

            if self._response_buf:
                raise PacketDecodeError('Unexpected SSH agent message')

            frame = self._check_response(frame)
        except PacketDecodeError:
            self.close()
            return

        outstanding_request = self._outstanding_request
        self._outstanding_request = None
        SSHForwarder.write(self, frame)

        if self._transport:
            try:
                self.resume_reading()
            except OSError: # pragma: no cover
                self.close()
                return

        self._send_next()

        if outstanding_request is not None and self._eof_received and \
                not self._request_queue and self._outstanding_request is None:
            self.write_eof()

    def data_received(self, data: bytes, datatype: Optional[int] = None) \
            -> None:
        """Handle data from the remote agent client"""

        # pylint: disable=unused-argument

        self._request_data_received(data)

    def write(self, data: bytes) -> None:
        """Handle data received from the local SSH agent"""

        self._response_data_received(data)

    def write_eof(self) -> None:
        """Handle EOF received from the local SSH agent"""

        if self._outstanding_request is not None or self._request_queue or \
                self._request_buf:
            self.close()
        else:
            super().write_eof()

    def eof_received(self) -> bool:
        """Handle EOF received from the remote agent client"""

        if self._outstanding_request is not None or self._request_queue or \
                self._request_buf:
            self.close()
            return True

        return super().eof_received()


class SSHLocalForwarder(SSHForwarder):
    """Local forwarding connection handler"""

    def __init__(self, conn: 'SSHConnection', coro: SSHForwarderCoro):
        super().__init__()
        self._conn = conn
        self._coro = coro

    async def _forward(self, *args: object) -> None:
        """Begin local forwarding"""

        def session_factory() -> SSHForwarder:
            """Return an SSH forwarder"""

            return SSHForwarder(self)

        try:
            await self._coro(session_factory, *args)
        except ChannelOpenError as exc:
            self.connection_lost(exc)
            return

        assert self._peer is not None

        if self._inpbuf:
            self._peer.write(self._inpbuf)
            self._inpbuf = b''

        if self._eof_received:
            self._peer.write_eof()

    def forward(self, *args: object) -> None:
        """Start a task to begin local forwarding"""

        self._conn.create_task(self._forward(*args))


class SSHLocalPortForwarder(SSHLocalForwarder):
    """Local TCP port forwarding connection handler"""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a newly opened connection"""

        super().connection_made(transport)

        peername = cast(SockAddr, transport.get_extra_info('peername'))

        if peername: # pragma: no branch
            orig_host, orig_port = peername[:2]

        self.forward(orig_host, orig_port)


class SSHLocalPathForwarder(SSHLocalForwarder):
    """Local UNIX domain socket forwarding connection handler"""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a newly opened connection"""

        super().connection_made(transport)
        self.forward()
