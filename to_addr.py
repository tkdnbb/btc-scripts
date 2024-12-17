from coincurve import PublicKey
from mnemonic import Mnemonic
from bip32 import BIP32
from bitcoinlib.keys import HDKey
from bitcoinlib.encoding import pubkeyhash_to_addr_bech32, to_hexstring
from bech32 import bech32_encode, bech32_hrp_expand

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
        return key.address()
        
    else:
        raise ValueError("Invalid address type. Choose 'legacy', 'segwit', 'native_segwit', or 'taproot'")

# 使用示例
if __name__ == "__main__":
    # 测试助记词 (请使用自己的助记词)
    mnemonic = "dinner lunch"
    
    try:
        # 生成不同类型的地址
        native_segwit_address = generate_btc_address(
            mnemonic, 
            account=0, 
            change=0, 
            address_index=0, 
            address_type="native_segwit"
        )
        
        taproot_address = generate_btc_address(
            mnemonic, 
            account=0, 
            change=0, 
            address_index=0, 
            address_type="taproot"
        )
        
        print("Native SegWit Address (P2WPKH):", native_segwit_address)  # bc1q开头
        print("Taproot Address (P2TR):", taproot_address)  # bc1p开头
        
    except Exception as e:
        print(f"Error: {str(e)}")
