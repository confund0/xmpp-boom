#!/usr/bin/env python3
"""
AlertPusher - LibreNMS XMPP Alert Gateway

Receives HTTP webhooks from LibreNMS and forwards them to XMPP MUC rooms.
Built on Claude's MUC Bomb for aggressive presence management.
"""

import asyncio
import logging
import signal
import sys
import ssl
from pathlib import Path
from typing import Dict, Optional

import yaml
from aiohttp import web

from xmpp_muc import MUCBomb


class AlertPusher:
    """Main AlertPusher service."""

    def __init__(self, config_path: str = 'config.yaml'):
        """Initialize AlertPusher."""
        self.config = self._load_config(config_path)
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        self.xmpp_client: Optional[MUCBomb] = None
        self.http_app = None
        self.http_runner = None
        self.shutdown_event = asyncio.Event()

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file."""
        config_file = Path(config_path)
        if not config_file.exists():
            print(f"ERROR: Config file not found: {config_path}")
            sys.exit(1)

        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)

        # Validate required sections
        required_sections = ['xmpp', 'http', 'logging']
        for section in required_sections:
            if section not in config:
                print(f"ERROR: Missing required config section: {section}")
                sys.exit(1)

        return config

    def _setup_logging(self):
        """Setup logging based on config."""
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())

        # Create formatters
        formatter = logging.Formatter(
            fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)

        # Remove existing handlers
        root_logger.handlers.clear()

        # Console handler (stdout/stderr)
        if log_config.get('console', {}).get('enabled', True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)

        # File handler
        if log_config.get('file', {}).get('enabled', False):
            log_file = log_config['file'].get('path', 'logs/alertpusher.log')
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

        # Syslog handler
        if log_config.get('syslog', {}).get('enabled', False):
            try:
                from logging.handlers import SysLogHandler
                syslog_address = log_config['syslog'].get('address', '/dev/log')
                # Handle TCP syslog (host:port)
                if ':' in syslog_address:
                    host, port = syslog_address.split(':')
                    syslog_address = (host, int(port))
                syslog_handler = SysLogHandler(address=syslog_address)
                syslog_handler.setFormatter(formatter)
                root_logger.addHandler(syslog_handler)
            except Exception as e:
                print(f"WARNING: Failed to setup syslog: {e}")

    async def _init_xmpp(self):
        """Initialize XMPP client."""
        xmpp_config = self.config['xmpp']

        # Parse rooms config
        rooms = {}
        for room_config in xmpp_config.get('rooms', []):
            room_jid = room_config['jid']
            rooms[room_jid] = {
                'nick': room_config.get('nick', 'AlertPusher'),
                'password': room_config.get('password'),
            }

        self.logger.info(f"Initializing XMPP client: {xmpp_config['jid']}")
        self.xmpp_client = MUCBomb(
            jid=xmpp_config['jid'],
            password=xmpp_config['password'],
            rooms=rooms,
            reconnect_max_delay=xmpp_config.get('reconnect_max_delay', 300),
            keepalive_interval=xmpp_config.get('keepalive_interval', 60),
        )

        # Connect to server (use asyncio-friendly method)
        server_host = xmpp_config.get('server')
        server_port = xmpp_config.get('port', 5222)

        if server_host:
            address = (server_host, server_port)
        else:
            address = None

        # Configure proxy if enabled
        proxy_config = xmpp_config.get('proxy', {})
        if proxy_config.get('enabled', False):
            proxy_type = proxy_config.get('type', 'http')
            proxy_host = proxy_config.get('host')
            proxy_port = proxy_config.get('port', 3128)
            self.logger.info(f"Using {proxy_type} proxy: {proxy_host}:{proxy_port}")
            self.xmpp_client.use_proxy = True
            self.xmpp_client.proxy_config = {
                'type': proxy_type,
                'host': proxy_host,
                'port': proxy_port,
            }

        # Register and connect (returns immediately, connection happens in background)
        self.xmpp_client.register_plugin('xep_0199')  # Already done in MUCBomb, but ensure it's there
        if address:
            self.xmpp_client.connect(address)
        else:
            self.xmpp_client.connect()

        self.logger.info("XMPP client initialized and connecting...")

    async def _init_http(self):
        """Initialize HTTP server."""
        http_config = self.config['http']

        self.http_app = web.Application()
        self.http_app['alertpusher'] = self

        # Add routes
        self.http_app.router.add_get('/health', self._handle_health)
        self.http_app.router.add_get('/send', self._handle_send)
        self.http_app.router.add_post('/send', self._handle_send)

        self.http_runner = web.AppRunner(self.http_app)
        await self.http_runner.setup()

        # SSL configuration
        ssl_config = http_config.get('ssl', {})
        ssl_context = None

        if ssl_config.get('enabled', False):
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

            cert_file = ssl_config.get('cert')
            key_file = ssl_config.get('key')
            ca_file = ssl_config.get('ca')
            pem_file = ssl_config.get('pem')

            if pem_file:
                # Single PEM file with everything
                self.logger.info(f"Loading SSL from PEM: {pem_file}")
                ssl_context.load_cert_chain(pem_file)
            elif cert_file and key_file:
                # Separate cert and key
                self.logger.info(f"Loading SSL cert: {cert_file}, key: {key_file}")
                ssl_context.load_cert_chain(cert_file, key_file)
                if ca_file:
                    ssl_context.load_verify_locations(ca_file)
            else:
                self.logger.error("SSL enabled but no cert/key/pem configured!")
                sys.exit(1)

        # Start HTTP site
        bind_ip = http_config.get('bind', '0.0.0.0')
        bind_port = http_config.get('port', 8080)

        site = web.TCPSite(
            self.http_runner,
            bind_ip,
            bind_port,
            ssl_context=ssl_context
        )
        await site.start()

        protocol = 'https' if ssl_context else 'http'
        self.logger.info(f"HTTP server started: {protocol}://{bind_ip}:{bind_port}")

    async def _handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        status = {
            'status': 'ok',
            'xmpp_connected': self.xmpp_client.is_connected() if self.xmpp_client else False,
            'xmpp_rooms': self.xmpp_client.get_joined_rooms() if self.xmpp_client else [],
        }
        return web.json_response(status)

    async def _handle_send(self, request: web.Request) -> web.Response:
        """Handle alert webhook."""
        try:
            # Extract parameters based on request type
            if request.method == 'GET':
                params = dict(request.query)
            elif request.content_type == 'application/json':
                params = await request.json()
            else:
                # Form data or multipart
                params = dict(await request.post())

            # Validate token
            token = params.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')
            if not self._validate_token(token):
                self.logger.warning(f"Invalid token from {request.remote}")
                return web.json_response({'error': 'Unauthorized'}, status=401)

            # Extract message parameters
            to = params.get('to')
            subject = params.get('subject', '')
            message = params.get('message', '')

            if not to or not message:
                return web.json_response({'error': 'Missing required fields: to, message'}, status=400)

            # Format message
            full_message = self._format_message(subject, message)

            # Send to XMPP
            if not self.xmpp_client or not self.xmpp_client.is_connected():
                self.logger.error("XMPP client not connected!")
                return web.json_response({'error': 'XMPP not connected'}, status=503)

            # Determine if it's MUC or private message
            if '@conference.' in to or '@muc.' in to or to in self.xmpp_client.rooms:
                await self.xmpp_client.send_to_muc(to, full_message)
            else:
                await self.xmpp_client.send_private_message(to, full_message)

            self.logger.info(f"Alert sent to {to}")
            return web.json_response({'status': 'sent', 'to': to})

        except Exception as e:
            self.logger.exception(f"Error handling webhook: {e}")
            return web.json_response({'error': str(e)}, status=500)

    def _validate_token(self, token: str) -> bool:
        """Validate authentication token."""
        valid_tokens = self.config['http'].get('auth_tokens', [])
        return token in valid_tokens

    def _format_message(self, subject: str, message: str) -> str:
        """Format alert message."""
        if subject:
            return f"{subject}\n\n{message}"
        return message

    async def run(self):
        """Run the AlertPusher service."""
        self.logger.info("Starting AlertPusher...")

        # Setup signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_event_loop().add_signal_handler(
                sig, lambda: asyncio.create_task(self.shutdown())
            )

        try:
            # Initialize XMPP
            await self._init_xmpp()

            # Initialize HTTP
            await self._init_http()

            self.logger.info("AlertPusher started successfully")

            # Wait for shutdown signal (XMPP runs in background)
            await self.shutdown_event.wait()

        except Exception as e:
            self.logger.exception(f"Fatal error: {e}")
            sys.exit(1)

    async def shutdown(self):
        """Graceful shutdown."""
        self.logger.info("Shutting down AlertPusher...")

        # Stop HTTP server
        if self.http_runner:
            await self.http_runner.cleanup()

        # Disconnect XMPP
        if self.xmpp_client:
            self.xmpp_client.disconnect()

        self.shutdown_event.set()
        self.logger.info("AlertPusher stopped")


async def main():
    """Main entry point."""
    import argparse
    parser = argparse.ArgumentParser(description='AlertPusher - LibreNMS XMPP Gateway')
    parser.add_argument('-c', '--config', default='config.yaml', help='Config file path')
    args = parser.parse_args()

    pusher = AlertPusher(args.config)
    await pusher.run()


if __name__ == '__main__':
    asyncio.run(main())
