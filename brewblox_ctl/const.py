"""
Const values
"""
import pathlib
import sys

ARGS = sys.argv
CLI = 'python3 -m brewblox_ctl'
HOST = 'https://localhost'

# The configuration version installed by brewblox-ctl
# This will be different from the env CFG_VERSION during updates
CFG_VERSION = '0.7.0'

# Keys to used environment variables
ENV_KEY_CFG_VERSION = 'BREWBLOX_CFG_VERSION'
ENV_KEY_CTL_RELEASE = 'BREWBLOX_CTL_RELEASE'
ENV_KEY_RELEASE = 'BREWBLOX_RELEASE'
ENV_KEY_SKIP_CONFIRM = 'BREWBLOX_SKIP_CONFIRM'
ENV_KEY_DEBUG = 'BREWBLOX_DEBUG'
ENV_KEY_ALLOW_ARMV6 = 'BREWBLOX_ALLOW_ARMV6'
ENV_KEY_PORT_HTTP = 'BREWBLOX_PORT_HTTP'
ENV_KEY_PORT_HTTPS = 'BREWBLOX_PORT_HTTPS'
ENV_KEY_PORT_MQTT = 'BREWBLOX_PORT_MQTT'

# Default values
DEFAULT_RELEASE = 'edge'
DEFAULT_PORT_HTTP = 80
DEFAULT_PORT_HTTPS = 443
DEFAULT_PORT_MQTT = 1883

# Default content of the .env file
# This is used by both brewblox-ctl and docker-compose
ENV_FILE_DEFAULTS = {
    # Declared by brewblox
    ENV_KEY_RELEASE: DEFAULT_RELEASE,
    ENV_KEY_PORT_HTTP: str(DEFAULT_PORT_HTTP),
    ENV_KEY_PORT_HTTPS: str(DEFAULT_PORT_HTTPS),
    ENV_KEY_PORT_MQTT: str(DEFAULT_PORT_MQTT),
    # Declared by docker-compose
    'COMPOSE_FILE': 'docker-compose.shared.yml:docker-compose.yml',
    'COMPOSE_PROJECT_NAME': 'brewblox',
}

# Prefixes for log messages
LOG_SHELL = 'SHELL'.ljust(10)
LOG_PYTHON = 'PYTHON'.ljust(10)
LOG_ENV = 'ENV'.ljust(10)
LOG_CONFIG = 'COMPOSE'.ljust(10)
LOG_INFO = 'INFO'.ljust(10)
LOG_WARN = 'WARN'.ljust(10)
LOG_ERR = 'ERROR'.ljust(10)

# Static file directories included in the brewblox-ctl package
DIR_CTL_ROOT = str(pathlib.Path(__file__).parent.resolve())
DIR_DEPLOYED_CONFIG = f'{DIR_CTL_ROOT}/deployed/config'
DIR_DEPLOYED_SCRIPTS = f'{DIR_CTL_ROOT}/deployed/scripts'

# Apt dependencies required to run brewblox
# This is a duplicate of the list in bootstrap-install.sh
APT_DEPENDENCIES = [
    'curl',
    'libssl-dev',
    'libffi-dev',
    'avahi-daemon',
]

# USB Vendor / Product IDs
VID_PARTICLE = 0x2b04
PID_PHOTON = 0xc006
PID_P1 = 0xc008
VID_ESPRESSIF = 0x10c4
PID_ESP32 = 0xea60
