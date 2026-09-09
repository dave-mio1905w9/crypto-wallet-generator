"""BIP32/44 key derivation for Bitcoin (P2PKH) and Ethereum."""

import hashlib
import hmac
import struct

def _hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))."""
    from Crypto.Hash import RIPEMD160
    h = RIPEMD160.new()
    h.update(hashlib.sha256(data).digest())
    return h.digest()

def _base58_encode(data: bytes) -> str:
    """Encode bytes to Base58Check string."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, "big")
    if num == 0:
        return alphabet[0] * len(data)
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(alphabet[rem])
    for b in data:
        if b == 0:
            result.append(alphabet[0])
        else:
            break
    return "".join(reversed(result))

def _derive_child(parent_key: bytes, parent_chain: bytes, index: int) -> tuple:
    """Derive a child key and chain code."""
    if index >= 0x80000000:
        data = b"\x00" + parent_key + struct.pack(">I", index)
    else:
        data = b"\x00" + parent_key + struct.pack(">I", index)
    
    i = hmac.new(parent_chain, data, hashlib.sha512).digest()
    child_key = (int.from_bytes(i[:32], "big") + int.from_bytes(parent_key, "big")) % (2**256)
    child_chain = i[32:]
    return child_key.to_bytes(32, "big"), child_chain

def _privkey_to_pubkey(privkey: bytes) -> bytes:
    """Uncompressed secp256k1 public key from private key."""
    from ecdsa import SigningKey, SECP256k1
    sk = SigningKey.from_string(privkey, curve=SECP256k1)
    vk = sk.get_verifying_key()
    return b"\x04" + vk.to_string()

def _pubkey_to_compressed_pubkey(pubkey: bytes) -> bytes:
    """Convert uncompressed pubkey to compressed format."""
    if len(pubkey) == 65 and pubkey[0] == 0x04:
        x = pubkey[1:33]
        y = pubkey[33:65]
        prefix = b"\x02" if y[-1] % 2 == 0 else b"\x03"
        return prefix + x
    return pubkey

def derive_btc_address(seed: bytes, path: str = "m/44'/0'/0'/0/0") -> str:
    """Derive Bitcoin P2PKH address from BIP39 seed."""
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_key = i[:32]
    master_chain = i[32:]
    
    parts = path.split("/")
    if parts[0] != "m":
        raise ValueError("path must start with m/")
    
    key = master_key
    chain = master_chain
    for p in parts[1:]:
        if p.endswith("'"):
            idx = 0x80000000 + int(p[:-1])
        else:
            idx = int(p)
        key, chain = _derive_child(key, chain, idx)
    
    pubkey = _privkey_to_pubkey(key)
    compressed = _pubkey_to_compressed_pubkey(pubkey)
    
    h160 = _hash160(compressed)
    versioned = b"\x00" + h160
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return _base58_encode(versioned + checksum)

def derive_eth_address(seed: bytes, path: str = "m/44'/60'/0'/0/0") -> str:
    """Derive Ethereum address from BIP39 seed."""
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_key = i[:32]
    master_chain = i[32:]
    
    parts = path.split("/")
    if parts[0] != "m":
        raise ValueError("path must start with m/")
    
    key = master_key
    chain = master_chain
    for p in parts[1:]:
        if p.endswith("'"):
            idx = 0x80000000 + int(p[:-1])
        else:
            idx = int(p)
        key, chain = _derive_child(key, chain, idx)
    
    pubkey = _privkey_to_pubkey(key)
    pub_no_prefix = pubkey[1:]
    
    from Crypto.Hash import keccak
    k = keccak.new(digest_bits=256)
    k.update(pub_no_prefix)
    digest = k.digest()
    
    address_bytes = digest[-20:]
    hex_addr_lower = address_bytes.hex()  # lowercase hex
    
    # EIP-55: hash the lowercase hex address (no 0x prefix)
    k2 = keccak.new(digest_bits=256)
    k2.update(hex_addr_lower.encode())
    hash_hex = k2.hexdigest()
    
    checksum_addr = []
    for i, ch in enumerate(hex_addr_lower):
        if ch in "abcdef" and int(hash_hex[i], 16) >= 8:
            checksum_addr.append(ch.upper())
        else:
            checksum_addr.append(ch)
    
    return "0x" + "".join(checksum_addr)
