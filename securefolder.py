import os
import sys
import stat
import logging
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
from datetime import datetime
import json
from pathlib import Path

# 常量定义
IV_SIZE = 16
HMAC_SIZE = 32
FILENAME_HEADER_SIZE = 2  # 文件名长度使用2字节表示
CHUNK_SIZE = 64 * 1024  # 64KB分块处理
DEFAULT_EXCLUDE = {'pagefile.sys', 'hiberfil.sys', 'swapfile.sys', '.DS_Store'}
PATHMAP_FILENAME = '.pathmap'
PATHMAP_MAGIC = b'FFPATHMAP\x00'
PATHMAP_VERSION = 1
PATHMAP_ENCRYPTION_SALT = b'pathmap_salt_001'  # 固定盐值，可修改
PATHMAP_ENCRYPTION_INFO = b'pathmap_encryption'  # HKDF info

def derive_pathmap_key(password: str) -> bytes:
    """派生.pathmap文件专用的加密密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=PATHMAP_ENCRYPTION_SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_pathmap_content(data: dict, password: str) -> bytes:
    """加密.pathmap文件内容"""
    key = derive_pathmap_key(password)
    nonce = os.urandom(12)
    
    # 序列化数据
    plaintext = json.dumps(data).encode()
    
    # 加密
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # 组装最终文件内容
    return (PATHMAP_MAGIC + 
            bytes([PATHMAP_VERSION]) + 
            nonce + 
            ciphertext + 
            encryptor.tag)

def decrypt_pathmap_content(encrypted_data: bytes, password: str) -> dict:
    """解密.pathmap文件内容"""
    # 解析文件头
    magic = encrypted_data[:len(PATHMAP_MAGIC)]
    if magic != PATHMAP_MAGIC:
        raise ValueError("Invalid pathmap file magic")
    
    version = encrypted_data[len(PATHMAP_MAGIC)]
    if version != PATHMAP_VERSION:
        raise ValueError(f"Unsupported pathmap version {version}")
    
    nonce = encrypted_data[len(PATHMAP_MAGIC)+1:len(PATHMAP_MAGIC)+13]
    ciphertext = encrypted_data[len(PATHMAP_MAGIC)+13:-16]
    tag = encrypted_data[-16:]
    
    # 解密
    key = derive_pathmap_key(password)
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return json.loads(plaintext.decode())

def create_pathmap(folder_path: str, renamed_dirs: dict, password: str) -> str:
    """创建加密的路径映射文件"""
    pathmap_data = {
        'original_dirs': renamed_dirs,
        'timestamp': datetime.now().isoformat()
    }
    
    pathmap_path = os.path.join(folder_path, PATHMAP_FILENAME)
    encrypted_content = encrypt_pathmap_content(pathmap_data, password)
    
    with open(pathmap_path, 'wb') as f:
        f.write(encrypted_content)
    
    return pathmap_path

def read_pathmap(folder_path: str, password: str) -> dict:
    """读取并解密路径映射文件"""
    pathmap_path = os.path.join(folder_path, PATHMAP_FILENAME)
    if not os.path.exists(pathmap_path):
        return None
    
    with open(pathmap_path, 'rb') as f:
        encrypted_data = f.read()
    
    try:
        return decrypt_pathmap_content(encrypted_data, password)
    except Exception as e:
        logging.error(f"解密.pathmap文件失败: {str(e)}")
        return None

def encrypt_folder_structure(root_path: str, password: str, obfuscate: bool, exclude_dirs: set) -> dict:
    """加密文件夹结构并创建加密的.pathmap文件"""
    renamed_dirs = {}
    
    # 从下往上处理目录树（叶子目录先处理）
    for root, dirs, _ in os.walk(root_path, topdown=False):
        # 过滤排除目录
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        current_renamed = {}
        for dir_name in dirs:
            original_path = os.path.join(root, dir_name)
            
            if obfuscate:
                # 生成随机目录名
                import uuid
                new_name = str(uuid.uuid4())
                new_path = os.path.join(root, new_name)
                
                try:
                    os.rename(original_path, new_path)
                    current_renamed[new_name] = dir_name
                    logging.info(f"目录名混淆: {dir_name} -> {new_name}")
                except Exception as e:
                    logging.error(f"目录重命名失败 {original_path}: {str(e)}")
                    continue
            else:
                # 非混淆模式仍记录映射，保持一致性
                current_renamed[dir_name] = dir_name
        
        # 如果有目录被重命名，创建加密的.pathmap文件
        if current_renamed:
            relative_path = os.path.relpath(root, start=root_path)
            renamed_dirs[relative_path] = current_renamed
            
            try:
                pathmap_data = {
                    'version': PATHMAP_VERSION,
                    'original_dirs': current_renamed,
                    'timestamp': datetime.now().isoformat(),
                    'relative_path': relative_path
                }
                
                # 创建加密的.pathmap文件
                pathmap_path = os.path.join(root, PATHMAP_FILENAME)
                encrypted_content = encrypt_pathmap_content(pathmap_data, password)
                
                with open(pathmap_path, 'wb') as f:
                    f.write(encrypted_content)
                
                # 在Windows上设置为隐藏文件
                if os.name == 'nt':
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(pathmap_path, 2)
                
                logging.info(f"创建加密的.pathmap文件: {pathmap_path}")
            except Exception as e:
                logging.error(f"创建.pathmap文件失败 {root}: {str(e)}")
    
    return renamed_dirs

def decrypt_folder_structure(root_path: str, password: str) -> None:
    """解密文件夹结构（修复子目录未解密问题）"""
    # 使用栈实现手动遍历，避免os.walk的顺序问题
    stack = [(root_path, False)]  # (path, visited)
    
    while stack:
        current_path, visited = stack.pop()
        
        if visited:
            # 后序处理：检查并处理.pathmap文件
            pathmap_path = os.path.join(current_path, PATHMAP_FILENAME)
            
            if os.path.exists(pathmap_path):
                try:
                    # 解密.pathmap文件内容
                    with open(pathmap_path, 'rb') as f:
                        pathmap_data = decrypt_pathmap_content(f.read(), password)
                    
                    if not pathmap_data:
                        continue
                    
                    # 恢复目录名
                    dir_entries = list(os.scandir(current_path))
                    for entry in dir_entries:
                        if entry.is_dir() and entry.name in pathmap_data['original_dirs']:
                            original_name = pathmap_data['original_dirs'][entry.name]
                            original_path = os.path.join(current_path, original_name)
                            
                            try:
                                os.rename(entry.path, original_path)
                                logging.info(f"恢复目录名: {entry.name} -> {original_name}")
                            except Exception as e:
                                logging.error(f"目录恢复失败 {entry.path}: {str(e)}")
                    
                    # 删除.pathmap文件
                    try:
                        os.remove(pathmap_path)
                    except Exception as e:
                        logging.error(f"删除.pathmap文件失败 {pathmap_path}: {str(e)}")
                
                except Exception as e:
                    logging.error(f"处理.pathmap文件失败 {pathmap_path}: {str(e)}")
        
        else:
            # 前序处理：将子目录压入栈
            stack.append((current_path, True))  # 标记为已访问
            
            try:
                # 获取当前目录下的子目录（包括尚未恢复的混淆名目录）
                dir_entries = list(os.scandir(current_path))
                for entry in sorted(dir_entries, key=lambda x: x.name, reverse=True):
                    if entry.is_dir() and entry.name != PATHMAP_FILENAME:
                        stack.append((entry.path, False))
            except Exception as e:
                logging.error(f"扫描目录失败 {current_path}: {str(e)}")

def setup_logging(log_enabled: bool, log_file: str = None):
    if not log_enabled:
        logging.disable(logging.CRITICAL)
        return
    log_file = log_file or f"crypto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def make_file_writable(filepath: str) -> bool:
    if not os.path.exists(filepath):
        return True
    try:
        if os.name == 'nt':
            os.chmod(filepath, stat.S_IWRITE)
        else:
            os.chmod(filepath, stat.S_IWUSR | stat.S_IRUSR)
        return True
    except Exception as e:
        logging.warning(f"无法修改文件权限 {filepath} - {str(e)}")
        return False

def derive_keys(password: str, salt: bytes, use_salt_file: bool = False):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    keys = kdf.derive(password.encode())
    return keys[:32], keys[32:], salt

def encrypt_file(src_path: str, dst_path: str, password: str, obfuscate: bool = False):
    if not make_file_writable(src_path):
        raise PermissionError(f"无法读取: {src_path}")
    try:
        salt = os.urandom(16)
        enc_key, hmac_key, _ = derive_keys(password, salt)
        iv = os.urandom(IV_SIZE)

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(salt)
        h.update(iv)

        original_filename = os.path.basename(src_path)
        with open(src_path, 'rb') as fin, open(dst_path, 'wb') as fout:
            # 写入文件头
            fout.write(salt)
            fout.write(iv)
            
            # 如果需要混淆文件名，将原始文件名写入头部
            if obfuscate:
                encoded_name = base64.urlsafe_b64encode(original_filename.encode()).strip(b'=')
                name_len = len(encoded_name)
                fout.write(name_len.to_bytes(FILENAME_HEADER_SIZE, 'big'))
                fout.write(encoded_name)
                h.update(name_len.to_bytes(FILENAME_HEADER_SIZE, 'big'))
                h.update(encoded_name)

            # 加密文件内容
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                padded_chunk = padder.update(chunk)
                if padded_chunk:
                    encrypted_chunk = encryptor.update(padded_chunk)
                    h.update(encrypted_chunk)
                    fout.write(encrypted_chunk)

            final_padded = padder.finalize()
            final_encrypted = encryptor.update(final_padded) + encryptor.finalize()
            h.update(final_encrypted)
            fout.write(final_encrypted)
            fout.write(h.finalize())

        logging.info(f"加密成功: {src_path} -> {dst_path}")
        return True
    except Exception as e:
        if os.path.exists(dst_path):
            os.remove(dst_path)
        logging.error(f"加密失败 {src_path}: {str(e)}")
        return False

def decrypt_file(src_path: str, dst_path: str, password: str, obfuscate: bool = False):
    if not make_file_writable(src_path):
        raise PermissionError(f"无法读取: {src_path}")
    try:
        with open(src_path, 'rb') as fin:
            salt = fin.read(16)
            iv = fin.read(IV_SIZE)
            enc_key, hmac_key, _ = derive_keys(password, salt)

            cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()

            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(salt)
            h.update(iv)

            # 读取文件名信息（如果有）
            original_name = None
            if obfuscate:
                name_len = int.from_bytes(fin.read(FILENAME_HEADER_SIZE), 'big')
                encoded_name = fin.read(name_len)
                original_name = base64.urlsafe_b64decode(encoded_name + b'=' * (4 - (name_len % 4))).decode()
                h.update(name_len.to_bytes(FILENAME_HEADER_SIZE, 'big'))
                h.update(encoded_name)

            file_size = os.path.getsize(src_path)
            header_size = 16 + IV_SIZE + (FILENAME_HEADER_SIZE + len(encoded_name) if obfuscate else 0)
            data_length = file_size - header_size - HMAC_SIZE
            remaining = data_length

            # 如果混淆了文件名，使用原始文件名作为输出路径
            if obfuscate and original_name:
                dst_dir = os.path.dirname(dst_path)
                dst_path = os.path.join(dst_dir, original_name)

            with open(dst_path, 'wb') as fout:
                while remaining > 0:
                    chunk_size = min(CHUNK_SIZE, remaining)
                    chunk = fin.read(chunk_size)
                    h.update(chunk)
                    decrypted_chunk = decryptor.update(chunk)
                    remaining -= chunk_size

                    if remaining > 0:
                        fout.write(unpadder.update(decrypted_chunk))
                    else:
                        decrypted_chunk += decryptor.finalize()
                        fout.write(unpadder.update(decrypted_chunk))
                        fout.write(unpadder.finalize())

                stored_hmac = fin.read(HMAC_SIZE)
                h.verify(stored_hmac)

        logging.info(f"解密成功: {src_path} -> {dst_path}")
        return True
    except Exception as e:
        if os.path.exists(dst_path):
            os.remove(dst_path)
        logging.error(f"解密失败 {src_path}: {str(e)}")
        return False

def process_single_file(file_info, action, password, exclude_files, obfuscate):
    root, file = file_info
    src_path = os.path.join(root, file)
    
    # 跳过.pathmap文件和排除文件
    if file == PATHMAP_FILENAME or file in exclude_files:
        logging.info(f"跳过特殊文件: {src_path}")
        return (src_path, "skipped (special)")
    
    try:
        if action == 'encrypt' and not file.endswith('.enc'):
            if obfuscate:
                # 生成随机文件名
                import uuid
                random_name = str(uuid.uuid4())
                dst_path = os.path.join(root, random_name + '.enc')
            else:
                dst_path = src_path + '.enc'
            
            if encrypt_file(src_path, dst_path, password, obfuscate):
                os.remove(src_path)
                return (src_path, "encrypted")
                
        elif action == 'decrypt' and file.endswith('.enc'):
            dst_path = src_path[:-4]  # 临时路径，实际路径会在decrypt_file中修正
            if decrypt_file(src_path, dst_path, password, obfuscate):
                os.remove(src_path)
                return (src_path, "decrypted")
                
        return (src_path, "no action needed")
    except Exception as e:
        return (src_path, f"failed: {str(e)}")

def process_folder(args):
    # 加密流程
    if args.action == 'encrypt':
        # 先处理文件夹结构
        if args.obfuscate:
            encrypt_folder_structure(args.path, args.password, args.obfuscate, set(args.exclude_dirs))
    
    # 解密流程
    elif args.action == 'decrypt':
        # 先恢复文件夹结构
        decrypt_folder_structure(args.path, args.password)
    
    file_list = []
    for root, dirs, files in os.walk(args.path):
        dirs[:] = [d for d in dirs if d not in args.exclude_dirs]
        file_list.extend([(root, f) for f in files if f not in args.exclude_files])

    results = []
    if args.parallel:
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            results = list(executor.map(
                lambda f: process_single_file(f, args.action, args.password, 
                                           args.exclude_files, args.obfuscate),
                file_list
            ))
    else:
        results = [process_single_file(f, args.action, args.password, 
                                     args.exclude_files, args.obfuscate)
                   for f in file_list]

    success = failed = skipped = 0
    print("\n处理结果汇总:")
    for file, status in results:
        if "failed" in status:
            failed += 1
            print(f"[失败] {file}: {status}")
        elif "skipped" in status:
            skipped += 1
            print(f"[跳过] {file}")
        else:
            success += 1
            print(f"[成功] {file}: {status}")
    print(f"\n总计: {success} 成功, {failed} 失败, {skipped} 跳过")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="文件夹加密/解密工具")
    parser.add_argument("action", choices=['encrypt', 'decrypt'], help="加密或解密")
    parser.add_argument("path", help="目标文件夹路径")
    parser.add_argument("--password", help="密码（可选，不提供则提示输入）")
    parser.add_argument("--parallel", action="store_true", help="启用并行处理")
    parser.add_argument("--log", action="store_true", help="启用日志记录")
    parser.add_argument("--log-file", help="指定日志文件路径")
    parser.add_argument("--exclude-files", nargs="+", default=[], help="要排除的文件名列表")
    parser.add_argument("--exclude-dirs", nargs="+", default=[], help="要排除的目录名列表")
    parser.add_argument("--obfuscate", action="store_true", help="启用文件名混淆")

    args = parser.parse_args()
    setup_logging(args.log, args.log_file)
    args.exclude_files = set(args.exclude_files).union(DEFAULT_EXCLUDE)

    if not args.password:
        args.password = getpass.getpass("输入密码: ")
        password_confirm = getpass.getpass("确认密码: ")
        if args.password != password_confirm:
            print("错误: 密码不匹配")
            sys.exit(1)

    if not os.path.exists(args.path):
        print(f"错误: 路径不存在 {args.path}")
        sys.exit(1)

    try:
        process_folder(args)
    except Exception as e:
        logging.critical(f"致命错误: {str(e)}")
        sys.exit(1)
