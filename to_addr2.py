from mnemonic import Mnemonic
from bip32 import BIP32
from bitcoinlib.keys import HDKey
from bitcoinlib.encoding import pubkeyhash_to_addr_bech32, to_hexstring
from coincurve.keys import PublicKey

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 0x2bc830a3
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def create_taproot_address(pubkey_bytes):
    """Create a Taproot address from a public key."""
    # Add witness version
    program = [1] + convertbits(pubkey_bytes, 8, 5)
    return bech32_encode('bc', program)

def generate_btc_address(mnemonic, account=0, change=0, address_index=0, address_type="native_segwit"):
    """
    生成比特币地址
    
    参数:
        mnemonic (str): 助记词
        account (int): 账户索引
        change (int): 0表示收款地址，1表示找零地址
        address_index (int): 地址索引
        address_type (str): 地址类型 - "legacy", "segwit", "native_segwit", "taproot"
    
    返回:
        str: 比特币地址
    """
    # 从助记词生成种子
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic)
    
    # 创建 HD 钱包
    hdkey = HDKey.from_seed(seed)
    
    # 根据不同地址类型选择不同的路径
    if address_type == "legacy":
        # Legacy address (P2PKH) - m/44'/0'/account'/change/index
        path = f"m/44'/0'/{account}'/{change}/{address_index}"
        key = hdkey.subkey_for_path(path)
        return key.address()
        
    elif address_type == "segwit":
        # SegWit address (P2SH-P2WPKH) - m/49'/0'/account'/change/index
        path = f"m/49'/0'/{account}'/{change}/{address_index}"
        key = hdkey.subkey_for_path(path)
        return key.address()
        
    elif address_type == "native_segwit":
        # Native SegWit address (P2WPKH) - m/84'/0'/account'/change/index
        path = f"m/84'/0'/{account}'/{change}/{address_index}"
        key = hdkey.subkey_for_path(path)
        return key.address()
        
    elif address_type == "taproot":
        # Taproot address (P2TR) - m/86'/0'/account'/change/index
        path = f"m/86'/0'/{account}'/{change}/{address_index}"
        key = hdkey.subkey_for_path(path)
        
        # 使用 coincurve 生成 Taproot 地址
        pubkey = PublicKey(key.public_byte)
        taproot_pubkey = pubkey.format()
        
        # 添加 Taproot 前缀
        taproot_pubkey = bytes([32]) + taproot_pubkey[1:]
        
        return create_taproot_address(taproot_pubkey)
        
    else:
        raise ValueError("Invalid address type. Choose 'legacy', 'segwit', 'native_segwit', or 'taproot'")

def generate_test_mnemonic():
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=128)  # 生成12个词的助记词

if __name__ == "__main__":
    # 生成测试助记词
    test_mnemonic = generate_test_mnemonic()
    print("测试助记词:", test_mnemonic)
    
    try:
        # 生成不同类型的地址
        native_segwit_address = generate_btc_address(
            test_mnemonic, 
            account=0, 
            change=0, 
            address_index=0, 
            address_type="native_segwit"
        )
        
        taproot_address = generate_btc_address(
            test_mnemonic, 
            account=0, 
            change=0, 
            address_index=0, 
            address_type="taproot"
        )
        
        print("\nNative SegWit Address (P2WPKH):", native_segwit_address)  # bc1q开头
        print("Taproot Address (P2TR):", taproot_address)  # bc1p开头
        
        # 验证地址前缀
        print("\n地址验证:")
        print(f"Native SegWit 是否以 bc1q 开头: {native_segwit_address.startswith('bc1q')}")
        print(f"Taproot 是否以 bc1p 开头: {taproot_address.startswith('bc1p')}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
