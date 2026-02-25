import sys

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58decode(v: str) -> bytes:
    if not isinstance(v, str):
        v = v.decode('ascii')
    
    decimal = 0
    for char in v:
        decimal = decimal * 58 + b58.index(char)
        
    res = bytearray()
    while decimal > 0:
        decimal, mod = divmod(decimal, 256)
        res.append(mod)
        
    for char in v:
        if char == b58[0]:
            res.append(0)
        else:
            break
            
    res.reverse()
    return bytes(res)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 import_phantom.py <Phantom_Base58_Private_Key>")
        sys.exit(1)

    b58_key = sys.argv[1].strip()
    try:
        # Decode the base58 string
        decoded = b58decode(b58_key)
        
        # A full Solana keypair is 64 bytes (32 byte secret + 32 byte public).
        # We only need the first 32 bytes (the secret key) for zerox1-node.
        if len(decoded) == 64:
            secret_key = decoded[:32]
        elif len(decoded) == 32:
            secret_key = decoded
        else:
            print(f"Error: Invalid key length ({len(decoded)} bytes). Expected 64 or 32.")
            sys.exit(1)

        # Write the 32 raw bytes exactly as zerox1-node expects
        with open("my-phantom-key.key", "wb") as f:
            f.write(secret_key)
            
        print("Success! Created 'my-phantom-key.key' with your Phantom identity.")
        print("You can now run: cargo run -p zerox1-node -- --keypair-path my-phantom-key.key")
    except Exception as e:
        print(f"Failed to decode key: {e}")

if __name__ == "__main__":
    main()
