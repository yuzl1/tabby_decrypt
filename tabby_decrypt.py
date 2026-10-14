#!/usr/bin/env python3
"""
Tabby 密码解密器 - 一体化版本
支持Vault加密和keytar系统密钥链两种存储方式

用法: python tabby_decrypt.py [config.yaml路径] [Vault密码短语]
"""

import subprocess

import os
import sys
import base64
import getpass
import json
from pathlib import Path

# Vault加密依赖
try:
    import yaml
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    import hashlib
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False

# Keytar依赖（Windows）
try:
    import win32cred
    KEYTAR_AVAILABLE = True
except ImportError:
    KEYTAR_AVAILABLE = False

# ============================================================
# Tabby Vault 加密参数（来自vault.service.ts）
# ============================================================
PBKDF_ITERATIONS = 100000
PBKDF_DIGEST = 'sha512'
CRYPT_ALG = 'aes-256-cbc'
CRYPT_KEY_LENGTH = 32  # 256 bits
CRYPT_IV_LENGTH = 16   # 128 bits


# ============================================================
# Vault 加密/解密功能
# ============================================================

# 注释原来的 from Crypto.Protocol.KDF import PBKDF2
# 新增依赖：cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_vault_key(passphrase: str, salt: bytes) -> bytes:
    """使用PBKDF2派生密钥，对齐Tabby原版实现"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=CRYPT_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def decrypt_vault(vault_data: dict, passphrase: str) -> dict:
    """解密Tabby Vault数据"""
    if vault_data.get('version') != 1:
        raise ValueError(f"不支持的vault版本: {vault_data.get('version')}")

    key_salt = bytes.fromhex(vault_data['keySalt'])
    iv = bytes.fromhex(vault_data['iv'])
    encrypted_contents = base64.b64decode(vault_data['contents'])

    key = derive_vault_key(passphrase, key_salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_contents)

    padding_length = decrypted_padded[-1]
    decrypted = decrypted_padded[:-padding_length]

    return json.loads(decrypted.decode('utf-8'))


def parse_vault_secrets(vault: dict) -> list:
    """解析Vault中的密码条目为统一格式"""
    results = []
    secrets = vault.get('secrets', [])

    for secret in secrets:
        secret_type = secret.get('type', 'unknown')
        key = secret.get('key', {})
        value = secret.get('value', '')

        if secret_type == 'ssh:password':
            results.append({
                'source': 'vault',
                'type': 'SSH密码',
                'host': key.get('host', 'N/A'),
                'port': key.get('port', 22),
                'username': key.get('user', 'N/A'),
                'password': value
            })

        elif secret_type == 'ssh:key-passphrase':
            results.append({
                'source': 'vault',
                'type': 'SSH私钥密码',
                'key_hash': key.get('hash', 'N/A'),
                'password': value
            })

        elif secret_type == 'file':
            results.append({
                'source': 'vault',
                'type': '文件',
                'file_id': key.get('id', 'N/A'),
                'description': key.get('description', 'N/A'),
                'value': value
            })

    return results


# ============================================================
# Keytar 系统密钥链读取功能
# ============================================================

def read_windows_credentials() -> list:
    """读取Windows凭据管理器中的Tabby密码"""
    if not KEYTAR_AVAILABLE:
        return []

    passwords = []

    try:
        creds = win32cred.CredEnumerate(None, 0)

        for cred in creds:
            cred_name = cred['TargetName'].lower()

            # Tabby SSH密码: ssh@host:port/user
            if cred_name.startswith('ssh@') or ':ssh:' in cred_name:
                username = cred.get('UserName', '')
                password = cred.get('CredentialBlob', b'').decode('utf-8', errors='ignore')

                # 解析目标名称
                target = cred['TargetName']
                if '/' in target:
                    target, user = target.rsplit('/', 1)
                    username = user

                passwords.append({
                    'source': 'keytar',
                    'type': 'SSH密码',
                    'target': target,
                    'host': target,
                    'port': 22,
                    'username': username,
                    'password': password
                })

            # Tabby私钥密码: ssh-private-key:id
            elif cred_name.startswith('ssh-private-key:'):
                password = cred.get('CredentialBlob', b'').decode('utf-8', errors='ignore')

                passwords.append({
                    'source': 'keytar',
                    'type': 'SSH私钥密码',
                    'key_id': cred_name.replace('ssh-private-key:', ''),
                    'password': password
                })

    except Exception as e:
        print(f"[!] 读取Windows凭据失败: {e}")

    return passwords


def read_macos_keychain() -> list:
    """读取macOS钥匙串中的Tabby密码"""
    passwords = []
    try:
        # 列出所有 generic-password，查找包含tabby的条目
        result = subprocess.run(
            ['security', 'find-generic-password', '-g', '-a', '', '-s', '',  '2>&1'],
            capture_output=True,
            text=True,
            timeout=15
        )
        raw = result.stderr + result.stdout
        entries = raw.split("keychain:")
        for entry in entries:
            if "tabby" not in entry.lower():
                continue
            account = None
            service = None
            secret = None
            for line in entry.splitlines():
                line = line.strip()
                if line.startswith('"acct"<blob>="'):
                    account = line.split('"acct"<blob>="')[1].rstrip('"')
                elif line.startswith('"svce"<blob>="'):
                    service = line.split('"svce"<blob>="')[1].rstrip('"')
                elif line.startswith("password: "):
                    # password: "xxxx"
                    pwd_line = line.replace("password: ", "").strip()
                    if pwd_line.startswith('"'):
                        secret = pwd_line.strip('"')
            if secret and service:
                if service.startswith("ssh@"):
                    passwords.append({
                        'source': 'keytar',
                        'type': 'SSH密码',
                        'target': service,
                        'host': service,
                        'port':22,
                        'username': account,
                        'password': secret
                    })
                elif service.startswith("ssh-private-key:"):
                    passwords.append({
                        'source': 'keytar',
                        'type': 'SSH私钥密码',
                        'key_id': service.replace('ssh-private-key:', ''),
                        'password': secret
                    })
    except Exception as e:
        print(f"[!] 读取macOS钥匙串失败: {e}")
    return passwords



def read_linux_secret_tool() -> list:
    """读取Linux (GNOME) libsecret中的Tabby密码"""
    passwords = []

    try:
        import subprocess
        result = subprocess.run(['secret-tool', 'search', '--all'], capture_output=True, text=True)

        output = result.stdout
        lines = output.split('\n')
        current_item = {}

        for line in lines:
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                current_item[key.strip()] = value.strip()
            elif line == '' and current_item:
                label = current_item.get('label', '')
                if 'ssh' in label.lower():
                    passwords.append({
                        'source': 'keytar',
                        'type': 'SSH密码',
                        'label': label,
                        **current_item
                    })
                current_item = {}

    except Exception as e:
        pass

    return passwords


def read_keytar_passwords() -> list:
    """根据操作系统读取keytar存储的密码"""
    if sys.platform == 'win32':
        return read_windows_credentials()
    elif sys.platform == 'darwin':
        return read_macos_keychain()
    else:
        return read_linux_secret_tool()


# ============================================================
# 配置文件查找
# ============================================================

def find_config_file():
    """尝试查找Tabby配置文件"""
    possible_paths = []

    if sys.platform == 'win32':
        appdata = os.environ.get('APPDATA', '')
        possible_paths.append(Path(appdata) / 'tabby' / 'config.yaml')
        possible_paths.append(Path(appdata) / 'tabby' / 'config.yaml.backup')
    elif sys.platform == 'darwin':
        home = Path.home()
        possible_paths.append(home / 'Library' / 'Application Support' / 'tabby' / 'config.yaml')
        possible_paths.append(home / 'Library' / 'Application Support' / 'tabby' / 'config.yaml.backup')
    else:
        home = Path.home()
        possible_paths.append(home / '.config' / 'tabby' / 'config.yaml')
        possible_paths.append(home / '.config' / 'tabby' / 'config.yaml.backup')

    config_dir = os.environ.get('TABBY_CONFIG_DIRECTORY')
    if config_dir:
        possible_paths.append(Path(config_dir) / 'config.yaml')
        possible_paths.append(Path(config_dir) / 'config.yaml.backup')

    for path in possible_paths:
        if path.exists():
            return path
    return None


# ============================================================
# 输出格式化
# ============================================================

def print_passwords(passwords):
    """美化输出密码信息"""
    print("\n" + "="*60)
    print("Tabby 密码解密结果".center(60))
    print("="*60)

    if not passwords:
        print("\n[!] 未找到任何密码")
        print("\n可能的原因:")
        print("  1. Tabby未保存任何密码")
        print("  2. 密码短语错误（针对Vault）")
        print("  3. 需要管理员权限（针对keytar）")
        return

    ssh_count = 0
    key_count = 0
    file_count = 0

    for pwd in passwords:
        print(f"\n{'='*60}")
        print(f"来源: {pwd.get('source', 'Unknown').upper()}")
        print(f"类型: {pwd.get('type', 'Unknown')}")

        if pwd.get('type') == 'SSH密码':
            ssh_count += 1
            print(f"主机: {pwd.get('host', pwd.get('target', 'N/A'))}")
            if pwd.get('port') and pwd.get('port') != 22:
                print(f"端口: {pwd.get('port')}")
            print(f"用户: {pwd.get('username', 'N/A')}")
            print(f"密码: {pwd.get('password', 'N/A')}")

        elif pwd.get('type') == 'SSH私钥密码':
            key_count += 1
            if pwd.get('key_hash'):
                key_hash = pwd['key_hash']
                if len(key_hash) > 16:
                    key_hash = f"{key_hash[:8]}...{key_hash[-8:]}"
                print(f"私钥哈希: {key_hash}")
            elif pwd.get('key_id'):
                print(f"私钥ID: {pwd['key_id']}")
            print(f"密码: {pwd.get('password', 'N/A')}")

        elif pwd.get('type') == '文件':
            file_count += 1
            print(f"文件ID: {pwd.get('file_id', 'N/A')}")
            print(f"描述: {pwd.get('description', 'N/A')}")

    print(f"\n{'='*60}")
    print(f"统计: SSH密码={ssh_count}, 私钥密码={key_count}, 文件={file_count}, 总计={len(passwords)}")
    print("="*60 + "\n")


# ============================================================
# 主程序
# ============================================================

def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║          Tabby 密码解密器 v2.0 - 一体化版                ║
║          支持 Vault + Keytar 两种存储方式                ║
╚══════════════════════════════════════════════════════════╝
    """)

    # 获取配置文件路径
    if len(sys.argv) > 1:
        config_path = Path(sys.argv[1])
    else:
        config_path = find_config_file()

    if not config_path or not config_path.exists():
        print(f"[*] 配置文件: {config_path or '未找到'}")
        print("[*] 配置文件不存在，直接读取系统密钥链...")
        config = {}
    else:
        print(f"[*] 配置文件: {config_path}")
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            print(f"[!] 读取配置文件失败: {e}")
            print("[*] 尝试直接读取系统密钥链...")
            config = {}

    all_passwords = []

    # 检查是否启用Vault
    vault_data = config.get('vault')
    if vault_data and VAULT_AVAILABLE:
        print("[*] 检测到Vault加密")
        print(f"[*] Vault版本: {vault_data.get('version')}")
        print(f"[*] 配置加密: {config.get('encrypted', False)}")

        # 获取密码短语
        if len(sys.argv) > 2:
            passphrase = sys.argv[2]
        else:
            passphrase = getpass.getpass("请输入Vault密码短语: ")

        if passphrase:
            try:
                print("[*] 正在解密Vault...")
                vault = decrypt_vault(vault_data, passphrase)
                print("[*] Vault解密成功!")
                all_passwords.extend(parse_vault_secrets(vault))
            except Exception as e:
                print(f"[!] Vault解密失败: {e}")
                print("[*] 尝试读取系统密钥链...")
    else:
        if vault_data and not VAULT_AVAILABLE:
            print("[!] 检测到Vault但缺少依赖库")
            print("    pip install pyyaml pycryptodome")
        else:
            print("[*] 未启用Vault加密，读取系统密钥链...")

    # 读取keytar密码
    print("[*] 正在读取系统密钥链...")

    if sys.platform == 'win32':
        print(f"[*] 平台: Windows")
        if KEYTAR_AVAILABLE:
            keytar_passwords = read_windows_credentials()
        else:
            print("[!] 需要安装pywin32: pip install pywin32")
            keytar_passwords = []
    elif sys.platform == 'darwin':
        print(f"[*] 平台: macOS")
        keytar_passwords = read_macos_keychain()
    else:
        print(f"[*] 平台: Linux")
        keytar_passwords = read_linux_secret_tool()

    all_passwords.extend(keytar_passwords)

    # 输出结果
    print_passwords(all_passwords)


if __name__ == '__main__':
    main()
