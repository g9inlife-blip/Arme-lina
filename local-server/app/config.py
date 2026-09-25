"""Server-wide constants.

Values marked PROBABLE come from TASK-006 static evidence and must be
re-verified against decompile/runtime evidence before client testing.
"""
from __future__ import annotations

# HTTP API identifiers observed in ServerConst (static evidence)
API_ALLIN1 = "API_Allin1"
API_ANON = "API_Anon"
API_LOGIN = "API_Login"

# Parameter keys observed in ServerConst
PARAM_TOKEN = "token"
PARAM_DEVICE = "d"
PARAM_VERSION = "v"
PARAM_RETAIL = "r"

# Game server defaults (static evidence; PROBABLE)
DEFAULT_SERVER_HOST = "gm.aliother.com"  # PCAP observed: 182.92.62.79
DEFAULT_SERVER_PORT = 8000

# Game-server command constants (static evidence)
CMD_HANDSHAKE1 = 1
CMD_HANDSHAKE2 = 2
CMD_REQUEST = 3
CMD_PUSH = 4
CMD_ERROR = 5
CMD_COMPRESS = 64
CMD_ENCRYPT = 128

# Operation codes (static evidence)
OP_LOGIN = 2

# Local server bind address
HOST = "127.0.0.1"
PORT = 8080
DB_PATH = "data/player.db"
