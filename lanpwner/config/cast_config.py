"""
Configuration settings for the Cast module
"""

# Default video settings
DEFAULT_VIDEO_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
DEFAULT_CONTENT_TYPE = "video/mp4"

# Rate limiting settings
MAX_ATTEMPTS_PER_DEVICE = 3
RATE_LIMIT_WINDOW = 60  # seconds
RETRY_DELAY = 5  # seconds
CONNECTION_TIMEOUT = 10  # seconds

# Connection pool settings
CONNECTION_POOL_LIMIT = 10
CONNECTION_KEEPALIVE_TIMEOUT = 30  # seconds

# Device discovery settings
DEFAULT_DISCOVERY_TIMEOUT = 5  # seconds
DEVICE_WAIT_TIMEOUT = 10  # seconds
PLAYBACK_STOP_WAIT = 1  # seconds

# Logging settings
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Content validation settings
SUPPORTED_CONTENT_TYPES = [
    'video/mp4',
    'video/webm',
    'video/ogg',
    'application/x-mpegURL',
    'application/vnd.apple.mpegurl',
    'video/mp2t'
]

# Error messages
ERROR_MESSAGES = {
    'device_not_found': "Target device '{}' not found",
    'rate_limit_exceeded': "Rate limit exceeded for {}. Please wait and try again.",
    'connection_timeout': "Connection timeout. Attempt {}/{}",
    'media_url_invalid': "Error: Could not access media URL {}",
    'missing_properties': "Skipping device with missing required properties: {}",
    'connection_failed': "Could not connect to {} device '{}'",
    'hijack_success': "Successfully hijacked {} session on {}",
    'hijack_failed': "Failed to hijack session after {} attempts",
    'retry_attempt': "Retrying in {} seconds...",
}

# Device type specific settings
DEVICE_SETTINGS = {
    'chromecast': {
        'required_properties': ['friendly_name', 'host', 'port'],
        'optional_properties': ['model_name', 'uuid', 'cast_type', 'manufacturer'],
    },
    'airplay': {
        'required_properties': ['name', 'address'],
        'optional_properties': ['model', 'identifier'],
    }
} 