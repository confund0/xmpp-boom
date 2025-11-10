#!/usr/bin/env python3
"""
Claude's MUC Bomb 💣
Reusable XMPP MUC presence manager with aggressive reconnection handling.

Features:
- Persistent MUC connections with auto-rejoin
- XEP-0045 (Multi-User Chat) support
- XEP-0199 (XMPP Ping) keepalive
- Graceful handling of kicks, bans, nick conflicts
- Detailed logging for debugging
"""

import logging
import asyncio
from typing import Dict, List, Optional, Callable
from slixmpp import ClientXMPP
from slixmpp.exceptions import IqError, IqTimeout


class MUCBomb(ClientXMPP):
    """
    Aggressive MUC presence manager that refuses to die.
    """

    def __init__(
        self,
        jid: str,
        password: str,
        rooms: Dict[str, Dict],
        reconnect_max_delay: int = 300,
        keepalive_interval: int = 60,
        on_message_callback: Optional[Callable] = None,
    ):
        """
        Initialize MUC Bomb.

        Args:
            jid: Bot JID (e.g., bot@example.com)
            password: Bot password
            rooms: Dict of {room_jid: {'nick': 'BotNick', 'password': 'optional'}}
            reconnect_max_delay: Max reconnect delay in seconds
            keepalive_interval: Ping interval in seconds
            on_message_callback: Optional callback for received messages
        """
        super().__init__(jid, password)

        self.rooms = rooms
        self.on_message_callback = on_message_callback
        self.logger = logging.getLogger(__name__)
        self.joined_rooms = set()
        self.reconnect_attempts = 0

        # Enable plugins
        self.register_plugin('xep_0045')  # Multi-User Chat
        self.register_plugin('xep_0199', {'keepalive': True, 'interval': keepalive_interval})  # XMPP Ping
        self.register_plugin('xep_0203')  # Delayed Delivery (for history)

        # Configure reconnection
        self.reconnect_max_delay = reconnect_max_delay

        # Event handlers
        self.add_event_handler("session_start", self._on_session_start)
        self.add_event_handler("session_end", self._on_session_end)
        self.add_event_handler("disconnected", self._on_disconnected)
        self.add_event_handler("failed_auth", self._on_failed_auth)
        self.add_event_handler("groupchat_message", self._on_groupchat_message)
        self.add_event_handler("muc::%s::got_online" % '*', self._on_muc_presence)
        self.add_event_handler("muc::%s::got_offline" % '*', self._on_muc_presence)
        self.add_event_handler("muc::%s::presence-error" % '*', self._on_muc_error)

    async def _on_session_start(self, event):
        """Handler for successful connection."""
        self.logger.info(f"Connected to XMPP server as {self.boundjid.bare}")
        self.reconnect_attempts = 0
        self.send_presence()
        await self.get_roster()
        await self._join_all_rooms()

    async def _on_session_end(self, event):
        """Handler for session end."""
        self.logger.warning("XMPP session ended")
        self.joined_rooms.clear()

    async def _on_disconnected(self, event):
        """Handler for disconnection - trigger slixmpp's reconnection."""
        self.logger.warning("Disconnected from XMPP server, reconnecting...")
        self.joined_rooms.clear()
        self.reconnect_attempts += 1

        # Trigger slixmpp's built-in reconnection with exponential backoff
        # This is what slixmpp SHOULD do automatically but doesn't after established connections drop
        self.connect()

    async def _on_failed_auth(self, event):
        """Handler for authentication failure."""
        self.logger.critical("XMPP authentication failed! Check JID/password.")
        # Don't retry on auth failure
        self.abort()

    async def _join_all_rooms(self):
        """Join all configured MUCs."""
        for room_jid, room_config in self.rooms.items():
            await self._join_room(room_jid, room_config)

    async def _join_room(self, room_jid: str, room_config: Dict):
        """
        Join a single MUC room.

        Args:
            room_jid: Room JID (e.g., alerts@conference.example.com)
            room_config: Dict with 'nick' and optional 'password'
        """
        nick = room_config.get('nick', 'Bot')
        password = room_config.get('password')

        # Handle different password config formats
        if password in [None, '', 'none', 'noauth']:
            password = None

        self.logger.info(f"Joining MUC: {room_jid} as {nick}")

        try:
            self.plugin['xep_0045'].join_muc(
                room_jid,
                nick,
                password=password,
            )
            self.joined_rooms.add(room_jid)
            self.logger.info(f"Successfully joined MUC: {room_jid}")
        except IqError as e:
            error_text = e.iq['error']['text'] if e.iq['error']['text'] else 'Unknown error'
            error_condition = e.iq['error']['condition']
            self.logger.error(f"Failed to join {room_jid}: {error_condition} - {error_text}")

            # Handle nick conflict (409)
            if error_condition == 'conflict':
                new_nick = f"{nick}_{self.reconnect_attempts}"
                self.logger.warning(f"Nick conflict, retrying as {new_nick}")
                room_config['nick'] = new_nick
                await asyncio.sleep(2)
                await self._join_room(room_jid, room_config)
        except IqTimeout:
            self.logger.error(f"Timeout joining {room_jid}, will retry on next reconnect")
        except Exception as e:
            self.logger.exception(f"Unexpected error joining {room_jid}: {e}")

    async def _on_muc_presence(self, presence):
        """Handler for MUC presence updates."""
        room = presence['from'].bare
        nick = presence['from'].resource
        ptype = presence['type']

        # Check if it's our own presence (status code 110)
        if presence['muc']['status_codes'] and '110' in presence['muc']['status_codes']:
            if ptype == 'unavailable':
                self.logger.warning(f"We left/got kicked from {room}")
                if room in self.joined_rooms:
                    self.joined_rooms.remove(room)
                # Attempt rejoin after delay
                asyncio.create_task(self._rejoin_room_delayed(room, 5))
            else:
                self.logger.debug(f"Self-presence confirmed in {room} as {nick}")
        else:
            self.logger.debug(f"Presence in {room}: {nick} - {ptype}")

    async def _on_muc_error(self, presence):
        """Handler for MUC presence errors."""
        room = presence['from'].bare
        error = presence['error']
        self.logger.error(f"MUC error in {room}: {error['condition']} - {error.get('text', '')}")

    async def _rejoin_room_delayed(self, room_jid: str, delay: int):
        """Rejoin a room after delay."""
        self.logger.info(f"Will attempt to rejoin {room_jid} in {delay}s")
        await asyncio.sleep(delay)
        if room_jid in self.rooms:
            await self._join_room(room_jid, self.rooms[room_jid])

    async def _on_groupchat_message(self, msg):
        """Handler for groupchat messages."""
        room = msg['from'].bare
        nick = msg['from'].resource
        body = msg['body']

        # Ignore empty messages, history, and our own messages
        if not body or msg['delay']['stamp'] or nick == self.plugin['xep_0045'].our_nicks.get(room):
            return

        self.logger.debug(f"Message in {room} from {nick}: {body[:50]}...")

        # Call user callback if provided
        if self.on_message_callback:
            try:
                await self.on_message_callback(room, nick, body, msg)
            except Exception as e:
                self.logger.exception(f"Error in message callback: {e}")

    async def send_to_muc(self, room_jid: str, message: str, message_type: str = 'groupchat'):
        """
        Send a message to a MUC room.

        Args:
            room_jid: Room JID
            message: Message text
            message_type: 'groupchat' or 'chat' (for private messages)
        """
        if room_jid not in self.joined_rooms:
            self.logger.warning(f"Not joined to {room_jid}, attempting to join first")
            if room_jid in self.rooms:
                await self._join_room(room_jid, self.rooms[room_jid])
                # Wait a bit for join to complete
                await asyncio.sleep(2)
            else:
                self.logger.error(f"Room {room_jid} not in configuration!")
                raise ValueError(f"Room {room_jid} not configured")

        if room_jid not in self.joined_rooms:
            self.logger.error(f"Failed to join {room_jid}, cannot send message")
            raise RuntimeError(f"Not joined to {room_jid}")

        self.logger.debug(f"Sending message to {room_jid}: {message[:100]}...")
        self.send_message(mto=room_jid, mbody=message, mtype=message_type)
        self.logger.info(f"Message sent to {room_jid}")

    async def send_private_message(self, jid: str, message: str):
        """
        Send a private message to a user.

        Args:
            jid: User JID (can be full or bare)
            message: Message text
        """
        self.logger.debug(f"Sending private message to {jid}: {message[:100]}...")
        self.send_message(mto=jid, mbody=message, mtype='chat')
        self.logger.info(f"Private message sent to {jid}")

    def is_connected(self) -> bool:
        """Check if connected and authenticated."""
        return self.is_connected and self.authenticated

    def is_joined(self, room_jid: str) -> bool:
        """Check if joined to a specific room."""
        return room_jid in self.joined_rooms

    def get_joined_rooms(self) -> List[str]:
        """Get list of currently joined rooms."""
        return list(self.joined_rooms)
