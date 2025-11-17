#!/usr/bin/env python3
"""
Claude's MUC Bomb 💣 - OMEMO Edition
Reusable XMPP MUC presence manager with OMEMO encryption support.

Features:
- Persistent MUC connections with auto-rejoin
- XEP-0045 (Multi-User Chat) support
- XEP-0199 (XMPP Ping) keepalive
- XEP-0384 (OMEMO) end-to-end encryption
- Graceful handling of kicks, bans, nick conflicts
- Automatic OMEMO version negotiation (0.3.0 and 0.8.0+)
- Blind Trust Before Verification (BTBV) for automatic trust
- Detailed logging for debugging
"""

import logging
import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Callable, FrozenSet, Set, Any
import aiohttp
from slixmpp import ClientXMPP
from slixmpp.jid import JID
from slixmpp.stanza import Message
from slixmpp.exceptions import IqError, IqTimeout
from slixmpp.plugins import register_plugin

# OMEMO imports
from omemo.storage import Storage, Maybe, Just, Nothing
from omemo.types import JSONType, DeviceInformation
from slixmpp_omemo import XEP_0384, TrustLevel


class OMEMOStorage(Storage):
    """
    OMEMO storage implementation using a JSON file backend.
    Based on the slixmpp-omemo example implementation.
    """

    def __init__(self, json_file_path: Path) -> None:
        super().__init__()
        self.__json_file_path = json_file_path
        self.__data: Dict[str, JSONType] = {}

        # Ensure parent directory exists
        self.__json_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing data
        try:
            with open(self.__json_file_path, encoding="utf8") as f:
                self.__data = json.load(f)
        except Exception:
            pass

    async def _load(self, key: str) -> Maybe[JSONType]:
        if key in self.__data:
            return Just(self.__data[key])
        return Nothing()

    async def _store(self, key: str, value: JSONType) -> None:
        self.__data[key] = value
        with open(self.__json_file_path, "w", encoding="utf8") as f:
            json.dump(self.__data, f, indent=2)

    async def _delete(self, key: str) -> None:
        self.__data.pop(key, None)
        with open(self.__json_file_path, "w", encoding="utf8") as f:
            json.dump(self.__data, f, indent=2)


class PluginCouldNotLoad(Exception):
    """Exception raised when OMEMO plugin fails to load."""
    pass


class XEP_0384Impl(XEP_0384):
    """
    OMEMO plugin implementation for MUCBomb.
    Supports both legacy OMEMO (0.3.0) and modern OMEMO (0.8.0+).
    """

    default_config = {
        "fallback_message": "This message is OMEMO encrypted.",
        "json_file_path": None
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.__storage: Storage

    def plugin_init(self) -> None:
        if not self.json_file_path:
            raise PluginCouldNotLoad("JSON file path not specified.")

        self.__storage = OMEMOStorage(Path(self.json_file_path))
        super().plugin_init()

    @property
    def storage(self) -> Storage:
        return self.__storage

    @property
    def _btbv_enabled(self) -> bool:
        """Enable Blind Trust Before Verification for automatic trust."""
        return True

    async def _devices_blindly_trusted(
        self,
        blindly_trusted: FrozenSet[DeviceInformation],
        identifier: Optional[str]
    ) -> None:
        """Called when devices are automatically trusted via BTBV."""
        log = logging.getLogger(__name__)
        log.info(f"[{identifier}] Devices trusted blindly: {blindly_trusted}")

    async def _prompt_manual_trust(
        self,
        manually_trusted: FrozenSet[DeviceInformation],
        identifier: Optional[str]
    ) -> None:
        """
        Called when manual trust decision is needed.
        Since BTBV is enabled, this should rarely be called.
        For now, we'll automatically trust all devices.
        """
        log = logging.getLogger(__name__)
        session_manager = await self.get_session_manager()

        for device in manually_trusted:
            log.info(f"[{identifier}] Auto-trusting device: {device}")
            await session_manager.set_trust(
                device.bare_jid,
                device.identity_key,
                TrustLevel.TRUSTED.value
            )


# Register our OMEMO plugin implementation
register_plugin(XEP_0384Impl)


class MUCBombOMEMO(ClientXMPP):
    """
    Aggressive MUC presence manager with OMEMO encryption support.
    """

    def __init__(
        self,
        jid: str,
        password: str,
        rooms: Dict[str, Dict],
        omemo_storage_path: Optional[str] = None,
        reconnect_max_delay: int = 300,
        keepalive_interval: int = 60,
        on_message_callback: Optional[Callable] = None,
        enable_omemo: bool = True,
    ):
        """
        Initialize MUC Bomb with OMEMO support.

        Args:
            jid: Bot JID (e.g., bot@example.com)
            password: Bot password
            rooms: Dict of {room_jid: {'nick': 'BotNick', 'password': 'optional'}}
            omemo_storage_path: Path to JSON file for OMEMO key storage (default: ~/.xmpp-omemo-{jid}.json)
            reconnect_max_delay: Max reconnect delay in seconds
            keepalive_interval: Ping interval in seconds
            on_message_callback: Optional callback for received messages
            enable_omemo: Enable OMEMO encryption (default: True)
        """
        super().__init__(jid, password)

        self.rooms = rooms
        self.on_message_callback = on_message_callback
        self.logger = logging.getLogger(__name__)
        self.joined_rooms = set()
        self.reconnect_attempts = 0
        self.omemo_enabled = enable_omemo
        self.omemo_ready = False

        # Set OMEMO storage path
        if omemo_storage_path:
            self.omemo_storage_path = Path(omemo_storage_path)
        else:
            # Default to home directory
            safe_jid = jid.split('@')[0].replace('/', '_').replace('.', '_')
            self.omemo_storage_path = Path.home() / f".xmpp-omemo-{safe_jid}.json"

        # Enable plugins (order matters for dependencies!)
        self.register_plugin('xep_0030')  # Service Discovery (required by many XEPs)
        self.register_plugin('xep_0128')  # Service Discovery Extensions (required by xep_0363)
        self.register_plugin('xep_0045')  # Multi-User Chat
        self.register_plugin('xep_0066')  # Out of Band Data (for inline media)
        self.register_plugin('xep_0199', {'keepalive': True, 'interval': keepalive_interval})  # XMPP Ping
        self.register_plugin('xep_0203')  # Delayed Delivery (for history)
        self.register_plugin('xep_0363')  # HTTP File Upload
        self.register_plugin('xep_0380')  # Explicit Message Encryption

        # Enable OMEMO if requested
        if self.omemo_enabled:
            try:
                self.register_plugin(
                    'xep_0384',
                    {'json_file_path': str(self.omemo_storage_path)},
                    module=sys.modules[__name__]
                )
                self.logger.info(f"OMEMO plugin registered (storage: {self.omemo_storage_path})")
            except Exception as e:
                self.logger.error(f"Failed to register OMEMO plugin: {e}")
                self.omemo_enabled = False

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

        if self.omemo_enabled:
            self.add_event_handler("omemo_initialized", self._on_omemo_initialized)

    async def _on_omemo_initialized(self, event):
        """Handler for OMEMO initialization completion."""
        self.omemo_ready = True
        self.logger.info("OMEMO encryption initialized and ready")

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
        self.omemo_ready = False

    async def _on_disconnected(self, event):
        """Handler for disconnection - trigger slixmpp's reconnection."""
        self.logger.warning("Disconnected from XMPP server, reconnecting...")
        self.joined_rooms.clear()
        self.reconnect_attempts += 1
        self.omemo_ready = False

        # Trigger slixmpp's built-in reconnection with exponential backoff
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
        Send an unencrypted message to a MUC room.

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

    async def send_encrypted_to_muc(self, room_jid: str, message: str):
        """
        Send an OMEMO-encrypted message to a MUC room.
        Automatically encrypts for all participants in the room.

        Args:
            room_jid: Room JID
            message: Message text to encrypt

        Raises:
            RuntimeError: If OMEMO is not enabled or not ready
            Exception: Various OMEMO-related exceptions from encryption process
        """
        if not self.omemo_enabled:
            raise RuntimeError("OMEMO is not enabled")

        if not self.omemo_ready:
            self.logger.warning("OMEMO not ready yet, waiting...")
            # Wait up to 10 seconds for OMEMO to initialize
            for _ in range(20):
                if self.omemo_ready:
                    break
                await asyncio.sleep(0.5)
            if not self.omemo_ready:
                raise RuntimeError("OMEMO initialization timeout")

        if room_jid not in self.joined_rooms:
            self.logger.warning(f"Not joined to {room_jid}, attempting to join first")
            if room_jid in self.rooms:
                await self._join_room(room_jid, self.rooms[room_jid])
                await asyncio.sleep(2)
            else:
                raise ValueError(f"Room {room_jid} not configured")

        if room_jid not in self.joined_rooms:
            raise RuntimeError(f"Not joined to {room_jid}")

        self.logger.debug(f"Sending OMEMO-encrypted message to {room_jid}: {message[:100]}...")

        # Get XEP-0045 and XEP-0384 plugins
        xep_0045 = self.plugin['xep_0045']
        xep_0384 = self.plugin['xep_0384']

        # Create message stanza
        stanza = self.make_message(mto=room_jid, mtype='groupchat')
        stanza['body'] = message

        # Get all participants in the room
        room_jid_obj = JID(room_jid)
        participants = xep_0045.get_roster(room_jid)

        # Get real JIDs of all participants
        recipient_jids: Set[JID] = set()
        for nick in participants:
            real_jid_str = xep_0045.get_jid_property(room_jid_obj, nick, 'jid')
            if real_jid_str:
                recipient_jids.add(JID(real_jid_str))
            else:
                self.logger.warning(f"Could not get real JID for {nick} in {room_jid}")

        if not recipient_jids:
            self.logger.warning(f"No recipients found in {room_jid}, cannot encrypt")
            raise RuntimeError(f"No recipients found in {room_jid}")

        self.logger.debug(f"Encrypting for {len(recipient_jids)} participants in {room_jid}")

        # Refresh device lists for all participants
        await xep_0384.refresh_device_lists(recipient_jids)

        # Encrypt the message
        try:
            messages, encryption_errors = await xep_0384.encrypt_message(stanza, recipient_jids)

            if encryption_errors:
                self.logger.warning(f"Encryption errors: {encryption_errors}")

            if not messages:
                raise RuntimeError("Encryption produced no messages")

            # Send all encrypted versions
            for namespace, encrypted_msg in messages.items():
                encrypted_msg['eme']['namespace'] = namespace
                encrypted_msg['eme']['name'] = self['xep_0380'].mechanisms.get(namespace, 'OMEMO')
                encrypted_msg.send()
                self.logger.info(f"OMEMO-encrypted message sent to {room_jid} (namespace: {namespace})")

        except Exception as e:
            self.logger.exception(f"Failed to encrypt message: {e}")
            raise

    async def send_private_message(self, jid: str, message: str):
        """
        Send an unencrypted private message to a user.

        Args:
            jid: User JID (can be full or bare)
            message: Message text
        """
        self.logger.debug(f"Sending private message to {jid}: {message[:100]}...")
        self.send_message(mto=jid, mbody=message, mtype='chat')
        self.logger.info(f"Private message sent to {jid}")

    async def send_encrypted_private_message(self, jid: str, message: str):
        """
        Send an OMEMO-encrypted private message to a user.

        Args:
            jid: User JID (can be full or bare)
            message: Message text to encrypt

        Raises:
            RuntimeError: If OMEMO is not enabled or not ready
            Exception: Various OMEMO-related exceptions from encryption process
        """
        if not self.omemo_enabled:
            raise RuntimeError("OMEMO is not enabled")

        if not self.omemo_ready:
            self.logger.warning("OMEMO not ready yet, waiting...")
            for _ in range(20):
                if self.omemo_ready:
                    break
                await asyncio.sleep(0.5)
            if not self.omemo_ready:
                raise RuntimeError("OMEMO initialization timeout")

        self.logger.debug(f"Sending OMEMO-encrypted private message to {jid}: {message[:100]}...")

        xep_0384 = self.plugin['xep_0384']

        # Create message stanza
        recipient_jid = JID(jid)
        stanza = self.make_message(mto=recipient_jid.bare, mtype='chat')
        stanza['body'] = message

        # Refresh device list for recipient
        await xep_0384.refresh_device_lists({recipient_jid})

        # Encrypt the message
        try:
            messages, encryption_errors = await xep_0384.encrypt_message(stanza, {recipient_jid})

            if encryption_errors:
                self.logger.warning(f"Encryption errors: {encryption_errors}")

            if not messages:
                raise RuntimeError("Encryption produced no messages")

            # Send all encrypted versions
            for namespace, encrypted_msg in messages.items():
                encrypted_msg['eme']['namespace'] = namespace
                encrypted_msg['eme']['name'] = self['xep_0380'].mechanisms.get(namespace, 'OMEMO')
                encrypted_msg.send()
                self.logger.info(f"OMEMO-encrypted private message sent to {jid} (namespace: {namespace})")

        except Exception as e:
            self.logger.exception(f"Failed to encrypt private message: {e}")
            raise

    async def upload_file(self, file_path: str, content_type: Optional[str] = None) -> str:
        """
        Upload a file using XEP-0363 (HTTP File Upload).

        Args:
            file_path: Path to the file to upload
            content_type: MIME type of the file (auto-detected if not provided)

        Returns:
            The HTTP URL of the uploaded file

        Raises:
            RuntimeError: If upload fails
            FileNotFoundError: If file doesn't exist
        """
        import mimetypes
        from pathlib import Path

        file = Path(file_path)
        if not file.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = file.stat().st_size
        file_name = file.name

        # Auto-detect content type if not provided
        if not content_type:
            content_type, _ = mimetypes.guess_type(file_name)
            if not content_type:
                content_type = 'application/octet-stream'

        self.logger.info(f"Uploading file: {file_name} ({file_size} bytes, {content_type})")

        # Request upload slot from server
        try:
            slot = await self['xep_0363'].upload_file(
                file_path,
                domain=None,  # Auto-detect from server
                timeout=30
            )
        except Exception as e:
            self.logger.exception(f"Failed to upload file: {e}")
            raise RuntimeError(f"File upload failed: {e}")

        self.logger.info(f"File uploaded successfully: {slot}")
        return slot

    async def send_attachment_to_muc(self, room_jid: str, file_path: str,
                                     caption: Optional[str] = None,
                                     content_type: Optional[str] = None):
        """
        Upload and send a file attachment to a MUC room.

        Args:
            room_jid: Room JID
            file_path: Path to the file to send
            caption: Optional caption/message to accompany the file
            content_type: MIME type of the file (auto-detected if not provided)

        Raises:
            RuntimeError: If not joined to room or upload fails
        """
        if room_jid not in self.joined_rooms:
            self.logger.warning(f"Not joined to {room_jid}, attempting to join first")
            if room_jid in self.rooms:
                await self._join_room(room_jid, self.rooms[room_jid])
                await asyncio.sleep(2)
            else:
                raise ValueError(f"Room {room_jid} not configured")

        if room_jid not in self.joined_rooms:
            raise RuntimeError(f"Not joined to {room_jid}")

        # Upload the file first
        url = await self.upload_file(file_path, content_type)

        # Build message with OOB data for inline display
        from pathlib import Path
        file_name = Path(file_path).name

        # Create message stanza
        msg = self.make_message(mto=room_jid, mtype='groupchat')

        # Set body: include URL in body for clients that don't support OOB
        # Real-world practice: always include URL in body for fallback
        if caption:
            msg['body'] = f"{caption}\n{url}"
        else:
            msg['body'] = url

        # Add OOB data for inline media display (this is what clients use for inline rendering)
        msg['oob']['url'] = url

        # Send the message
        msg.send()
        self.logger.info(f"Attachment sent to {room_jid}: {file_name}")

    async def send_encrypted_attachment_to_muc(self, room_jid: str, file_path: str,
                                               caption: Optional[str] = None,
                                               content_type: Optional[str] = None):
        """
        Upload and send an OMEMO-encrypted file attachment reference to a MUC room.
        Note: The file itself is uploaded via HTTP, but the message with the URL is encrypted.

        Args:
            room_jid: Room JID
            file_path: Path to the file to send
            caption: Optional caption/message to accompany the file
            content_type: MIME type of the file (auto-detected if not provided)

        Raises:
            RuntimeError: If OMEMO not enabled/ready or upload fails
        """
        if not self.omemo_enabled:
            raise RuntimeError("OMEMO is not enabled")

        if not self.omemo_ready:
            self.logger.warning("OMEMO not ready yet, waiting...")
            for _ in range(20):
                if self.omemo_ready:
                    break
                await asyncio.sleep(0.5)
            if not self.omemo_ready:
                raise RuntimeError("OMEMO initialization timeout")

        if room_jid not in self.joined_rooms:
            self.logger.warning(f"Not joined to {room_jid}, attempting to join first")
            if room_jid in self.rooms:
                await self._join_room(room_jid, self.rooms[room_jid])
                await asyncio.sleep(2)
            else:
                raise ValueError(f"Room {room_jid} not configured")

        if room_jid not in self.joined_rooms:
            raise RuntimeError(f"Not joined to {room_jid}")

        # Upload the file first
        url = await self.upload_file(file_path, content_type)

        # Build message with OOB data for inline display
        from pathlib import Path
        file_name = Path(file_path).name

        self.logger.debug(f"Sending OMEMO-encrypted attachment to {room_jid}: {file_name}")

        # Get XEP-0045 and XEP-0384 plugins
        xep_0045 = self.plugin['xep_0045']
        xep_0384 = self.plugin['xep_0384']

        # Create message stanza
        stanza = self.make_message(mto=room_jid, mtype='groupchat')

        # Set body: include URL in body for clients that don't support OOB
        # Real-world practice: always include URL in body for fallback
        if caption:
            stanza['body'] = f"{caption}\n{url}"
        else:
            stanza['body'] = url

        # Add OOB data for inline media display (this is what clients use for inline rendering)
        stanza['oob']['url'] = url

        # Get all participants in the room for encryption
        room_jid_obj = JID(room_jid)
        participants = xep_0045.get_roster(room_jid)

        # Get real JIDs of all participants
        recipient_jids: Set[JID] = set()
        for nick in participants:
            real_jid_str = xep_0045.get_jid_property(room_jid_obj, nick, 'jid')
            if real_jid_str:
                recipient_jids.add(JID(real_jid_str))
            else:
                self.logger.warning(f"Could not get real JID for {nick} in {room_jid}")

        if not recipient_jids:
            self.logger.warning(f"No recipients found in {room_jid}, cannot encrypt")
            raise RuntimeError(f"No recipients found in {room_jid}")

        self.logger.debug(f"Encrypting for {len(recipient_jids)} participants in {room_jid}")

        # Refresh device lists for all participants
        await xep_0384.refresh_device_lists(recipient_jids)

        # Encrypt the message
        try:
            messages, encryption_errors = await xep_0384.encrypt_message(stanza, recipient_jids)

            if encryption_errors:
                self.logger.warning(f"Encryption errors: {encryption_errors}")

            if not messages:
                raise RuntimeError("Encryption produced no messages")

            # Send all encrypted versions
            for namespace, encrypted_msg in messages.items():
                encrypted_msg['eme']['namespace'] = namespace
                encrypted_msg['eme']['name'] = self['xep_0380'].mechanisms.get(namespace, 'OMEMO')

                # NOTE: OOB extension not used with OMEMO - clients expect aesgcm:// URLs (XEP-0454)
                # For now, encrypted attachments will show as clickable URLs only

                encrypted_msg.send()
                self.logger.info(f"OMEMO-encrypted attachment sent to {room_jid} (namespace: {namespace}): {file_name}")

        except Exception as e:
            self.logger.exception(f"Failed to encrypt attachment message: {e}")
            raise

    async def send_attachment_to_user(self, jid: str, file_path: str,
                                      caption: Optional[str] = None,
                                      content_type: Optional[str] = None):
        """
        Upload and send a file attachment to a user via private message.

        Args:
            jid: User JID
            file_path: Path to the file to send
            caption: Optional caption/message to accompany the file
            content_type: MIME type of the file (auto-detected if not provided)

        Raises:
            RuntimeError: If upload fails
        """
        # Upload the file first
        url = await self.upload_file(file_path, content_type)

        # Build message with OOB data for inline display
        from pathlib import Path
        file_name = Path(file_path).name

        # Create message stanza
        msg = self.make_message(mto=jid, mtype='chat')

        # Set body: include URL in body for clients that don't support OOB
        # Real-world practice: always include URL in body for fallback
        if caption:
            msg['body'] = f"{caption}\n{url}"
        else:
            msg['body'] = url

        # Add OOB data for inline media display (this is what clients use for inline rendering)
        msg['oob']['url'] = url

        # Send the message
        msg.send()
        self.logger.info(f"Attachment sent to {jid}: {file_name}")

    async def send_encrypted_attachment_to_user(self, jid: str, file_path: str,
                                                caption: Optional[str] = None,
                                                content_type: Optional[str] = None):
        """
        Upload and send an OMEMO-encrypted file attachment reference to a user.
        Note: The file itself is uploaded via HTTP, but the message with the URL is encrypted.

        Args:
            jid: User JID
            file_path: Path to the file to send
            caption: Optional caption/message to accompany the file
            content_type: MIME type of the file (auto-detected if not provided)

        Raises:
            RuntimeError: If OMEMO not enabled/ready or upload fails
        """
        if not self.omemo_enabled:
            raise RuntimeError("OMEMO is not enabled")

        if not self.omemo_ready:
            self.logger.warning("OMEMO not ready yet, waiting...")
            for _ in range(20):
                if self.omemo_ready:
                    break
                await asyncio.sleep(0.5)
            if not self.omemo_ready:
                raise RuntimeError("OMEMO initialization timeout")

        # Upload the file first
        url = await self.upload_file(file_path, content_type)

        # Build message with OOB data for inline display
        from pathlib import Path
        file_name = Path(file_path).name

        self.logger.debug(f"Sending OMEMO-encrypted attachment to {jid}: {file_name}")

        xep_0384 = self.plugin['xep_0384']

        # Create message stanza
        recipient_jid = JID(jid)
        stanza = self.make_message(mto=recipient_jid.bare, mtype='chat')

        # Set body: include URL in body for clients that don't support OOB
        # Real-world practice: always include URL in body for fallback
        if caption:
            stanza['body'] = f"{caption}\n{url}"
        else:
            stanza['body'] = url

        # Add OOB data for inline media display (this is what clients use for inline rendering)
        stanza['oob']['url'] = url

        # Refresh device list for recipient
        await xep_0384.refresh_device_lists({recipient_jid})

        # Encrypt the message
        try:
            messages, encryption_errors = await xep_0384.encrypt_message(stanza, {recipient_jid})

            if encryption_errors:
                self.logger.warning(f"Encryption errors: {encryption_errors}")

            if not messages:
                raise RuntimeError("Encryption produced no messages")

            # Send all encrypted versions
            for namespace, encrypted_msg in messages.items():
                encrypted_msg['eme']['namespace'] = namespace
                encrypted_msg['eme']['name'] = self['xep_0380'].mechanisms.get(namespace, 'OMEMO')

                # NOTE: OOB extension not used with OMEMO - clients expect aesgcm:// URLs (XEP-0454)
                # For now, encrypted attachments will show as clickable URLs only

                encrypted_msg.send()
                self.logger.info(f"OMEMO-encrypted attachment sent to {jid} (namespace: {namespace}): {file_name}")

        except Exception as e:
            self.logger.exception(f"Failed to encrypt attachment message: {e}")
            raise

    def is_connected(self) -> bool:
        """Check if connected and authenticated."""
        return self.is_connected and self.authenticated

    def is_joined(self, room_jid: str) -> bool:
        """Check if joined to a specific room."""
        return room_jid in self.joined_rooms

    def get_joined_rooms(self) -> List[str]:
        """Get list of currently joined rooms."""
        return list(self.joined_rooms)

    def is_omemo_ready(self) -> bool:
        """Check if OMEMO encryption is ready to use."""
        return self.omemo_enabled and self.omemo_ready
