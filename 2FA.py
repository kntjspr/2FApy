import hmac
import base64
import struct
import hashlib
import time

def generate_2fa_code(secret_key: str) -> str:
    # Convert secret key to bytes
    secret_bytes = base64.b32decode(secret_key)

    # Calculate number of 30-second intervals since Unix epoch
    current_time = int(time.time())
    time_interval = current_time // 30

    # Convert interval to bytes
    interval_bytes = struct.pack('>q', time_interval)

    # Calculate HMAC-SHA1 hash of interval using secret key
    hmac_hash = hmac.new(secret_bytes, interval_bytes, hashlib.sha1).digest()

    # Get 4-byte code from hash
    offset = hmac_hash[-1] & 0x0F
    truncated_hash = hmac_hash[offset:offset+4]

    # Convert bytes to integer
    code = struct.unpack('>L', truncated_hash)[0]

    # Generate 6-digit code by taking last 6 digits of code
    code = code % 10**6

    # Pad with leading zeros if necessary
    code = str(code).zfill(6)

    return code