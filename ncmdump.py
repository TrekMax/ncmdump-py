# -*- coding: utf-8 -*-
"""
网易云音乐 NCM 文件解密工具
"""

import binascii
import struct
import base64
import json
import os
import argparse
import sys
import time
from pathlib import Path
from Crypto.Cipher import AES
from rich import print as rprint

def ncm_dump(file_path, save_cover=False, show_progress=True):
    """
    解密网易云音乐NCM格式文件
    
    Args:
        file_path (str): NCM文件路径
        save_cover (bool): 是否保存封面图片
        show_progress (bool): 是否显示进度
        
    Returns:
        str: 解密后的文件名
        
    Raises:
        ValueError: 如果文件不是有效的NCM格式
    """
    # 十六进制转字符串
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    unpad = lambda s: s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]
    
    # 获取文件大小用于进度显示
    if show_progress:
        file_size = os.path.getsize(file_path)
        processed_size = 0
        last_update_time = 0
    
    try:
        with open(file_path, 'rb') as f:
            # 校验NCM文件头
            header = f.read(8)
            if binascii.b2a_hex(header) != b'4354454e4644414d':
                raise ValueError("不是有效的NCM文件格式")
                
            # 跳过2字节
            f.seek(2, 1)
            
            # 读取并解密key数据
            key_length = struct.unpack('<I', f.read(4))[0]
            key_data = bytearray(f.read(key_length))
            
            # 异或解密
            for i in range(len(key_data)):
                key_data[i] ^= 0x64
                
            # AES解密
            cryptor = AES.new(core_key, AES.MODE_ECB)
            key_data = unpad(cryptor.decrypt(bytes(key_data)))[17:]
            key_length = len(key_data)
            key_data = bytearray(key_data)
            
            # 构建解密用的box
            key_box = bytearray(range(256))
            c = 0
            last_byte = 0
            key_offset = 0
            
            for i in range(256):
                swap = key_box[i]
                c = (swap + last_byte + key_data[key_offset]) & 0xff
                key_offset += 1
                if key_offset >= key_length:
                    key_offset = 0
                key_box[i] = key_box[c]
                key_box[c] = swap
                last_byte = c
            
            # 读取并解密meta数据
            meta_length = struct.unpack('<I', f.read(4))[0]
            meta_data = bytearray(f.read(meta_length))
            
            # 异或解密
            for i in range(len(meta_data)):
                meta_data[i] ^= 0x63
                
            # 注意: base64 解码需要处理字节而非字符串
            meta_data = bytes(meta_data)
            try:
                meta_data = base64.b64decode(meta_data[22:])
                cryptor = AES.new(meta_key, AES.MODE_ECB)
                meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
                meta_data = json.loads(meta_data)
                rprint(f"元数据: {meta_data}")
            except Exception as e:
                raise ValueError(f"元数据解析失败: {str(e)}")
            
            # 读取CRC校验和图片数据
            crc32 = struct.unpack('<I', f.read(4))[0]
            f.seek(5, 1)
            
            # 读取图片数据
            try:
                image_size = struct.unpack('<I', f.read(4))[0]
                image_data = f.read(image_size) if image_size > 0 else b''
            except Exception:
                # 如果读取图片失败，继续处理音频数据
                image_data = b''
                image_size = 0
            
            # 如果需要，保存封面图片
            if save_cover and image_size > 0:
                cover_name = Path(file_path).stem + '.jpg'
                cover_path = os.path.join(os.path.dirname(file_path), cover_name)
                with open(cover_path, 'wb') as cover_file:
                    cover_file.write(image_data)
                    if show_progress:
                        print(f"已保存封面图片: {cover_name}")
            
            # 确定输出文件名和格式
            file_format = meta_data.get('format', 'mp3')  # 默认为mp3格式
            output_filename = Path(file_path).stem + '.' + file_format
            output_path = os.path.join(os.path.dirname(file_path), output_filename)
            
            # 开始解密音频数据
            with open(output_path, 'wb') as m:
                if show_progress:
                    print(f"开始解密: {Path(file_path).name}")
                    processed_size = f.tell()
                
                while True:
                    chunk = f.read(0x8000)
                    if not chunk:
                        break
                        
                    chunk = bytearray(chunk)
                    chunk_length = len(chunk)
                    
                    # 解密音频数据
                    for i in range(chunk_length):
                        j = (i + 1) & 0xff
                        chunk[i] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
                    
                    m.write(chunk)
                    
                    # 更新进度 (限制更新频率，避免过多输出)
                    if show_progress:
                        processed_size += chunk_length
                        current_time = time.time()
                        if current_time - last_update_time > 0.5:  # 每0.5秒更新一次
                            progress = processed_size / file_size * 100
                            print(f"\r解密进度: {progress:.1f}%", end="", flush=True)
                            last_update_time = current_time
                
                if show_progress:
                    print(f"\r解密进度: 100.0%")
            
            return output_filename
            
    except FileNotFoundError:
        raise ValueError(f"文件不存在: {file_path}")
    except Exception as e:
        raise Exception(f"解密过程出错: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='网易云音乐NCM文件解密工具')
    parser.add_argument('files', nargs='+', help='要解密的NCM文件路径')
    parser.add_argument('-o', '--output', help='输出目录路径')
    parser.add_argument('-c', '--cover', action='store_true', help='保存封面图片')
    parser.add_argument('-q', '--quiet', action='store_true', help='不显示进度')
    
    args = parser.parse_args()
    
    # 设置输出目录
    if args.output:
        output_dir = Path(args.output)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)
    else:
        output_dir = None
    
    success_count = 0
    fail_count = 0
    
    for file_path in args.files:
        if not file_path.lower().endswith('.ncm'):
            print(f"跳过非NCM文件: {file_path}")
            continue
        
        # 如果指定了输出目录，则修改文件路径
        if output_dir:
            original_path = Path(file_path)
            file_path = str(output_dir / original_path.name)
            if not Path(file_path).exists():
                # 复制文件到输出目录
                import shutil
                shutil.copy2(str(original_path), file_path)
            
        try:
            output_file = ncm_dump(file_path, args.cover, not args.quiet)
            print(f"成功解密: {output_file}")
            success_count += 1
        except Exception as e:
            print(f"解密失败 {file_path}: {str(e)}")
            fail_count += 1
    
    # 总结
    if success_count > 0 or fail_count > 0:
        print(f"\n总结: 成功 {success_count} 个文件, 失败 {fail_count} 个文件")


if __name__ == '__main__':
    # 检查命令行参数
    if len(sys.argv) == 1:
        print("使用示例:")
        print("1. 解密指定NCM文件: python ncmdump.py 音乐文件.ncm")
        print("2. 解密多个NCM文件: python ncmdump.py 音乐1.ncm 音乐2.ncm")
        print("3. 解密并保存封面: python ncmdump.py 音乐.ncm --cover")
        print("4. 解密当前目录所有NCM文件: python ncmdump.py *.ncm")
        print("5. 指定输出目录: python ncmdump.py 音乐.ncm -o 输出目录")
        print("使用 --help 查看更多选项")
        
        # 检查当前目录是否有NCM文件
        current_dir_files = [f for f in os.listdir('.') if f.lower().endswith('.ncm')]
        if current_dir_files:
            print(f"\n检测到当前目录有 {len(current_dir_files)} 个NCM文件，要解密它们吗? (y/n): ", end='')
            choice = input().strip().lower()
            if choice == 'y':
                for file in current_dir_files:
                    try:
                        output_file = ncm_dump(file, save_cover=False, show_progress=True)
                        print(f"成功解密: {output_file}")
                    except Exception as e:
                        print(f"解密失败 {file}: {str(e)}")
    else:
        main()