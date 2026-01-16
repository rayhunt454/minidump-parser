from datetime import datetime
from typing import Optional
import struct


class MiniDumpParser:
    """Парсер мини-дампов Windows"""
    
    MINIDUMP_SIGNATURE = 0x504D444D
    MINIDUMP_VERSION = 0xA793
    
    STREAM_TYPES = {
        3: "ThreadListStream",                # Список потоков (MINIDUMP_THREAD_LIST)
        4: "ModuleListStream",                # Список модулей (MINIDUMP_MODULE_LIST)
        8: "ThreadExListStream",              # Расширенная информация о потоках
        17: "ThreadInfoListStream",           # Доп. информация о потоках (время, приоритеты)
        24: "ThreadNamesStream",              # Имена потоков
        
        5: "MemoryListStream",                # Список диапазонов памяти (32-bit)
        9: "Memory64ListStream",              # Список диапазонов памяти (64-bit)
        10: "CommentStreamA",                 # Комментарии (ASCII)
        11: "CommentStreamW",                 # Комментарии (Unicode)
        13: "FunctionTableStream",            # Таблица функций
        16: "MemoryInfoListStream",           # Информация о памяти (прототипы)
        21: "SystemMemoryInfoStream",         # Системная информация о памяти
        22: "ProcessVmCountersStream",        # Счетчики виртуальной памяти процесса
        
        6: "ExceptionStream",                 # Информация об исключении
        
        7: "SystemInfoStream",                # Информация о системе
        
        12: "HandleDataStream",               # Данные о хэндлах
        18: "HandleOperationListStream",      # Список операций с хэндлами
        19: "TokenStream",                    # Информация о токенах безопасности
        
        14: "UnloadedModuleListStream",       # Список выгруженных модулей
        15: "MiscInfoStream",                 # Разная информация (базовая)
        23: "MiscInfoStream2",                # Разная информация (расширенная)
        25: "MiscInfoStream3",                # Разная информация (версия 3)
        26: "MiscInfoStream4",                # Разная информация (версия 4)
        27: "MiscInfoStream5",     
    }
    
    def __init__(self, dump_file: str):
        self.dump_file = dump_file
        self.header = {}
        self.streams = {}
        self.file_handle = None
        
    def open(self):
        self.file_handle = open(self.dump_file, 'rb')
        return self.file_handle
        
    def close(self):
        if self.file_handle:
            self.file_handle.close()
            
    def parse(self) -> bool:
        try:
            self.file_handle = self.open()
            
            if not self.parse_header():
                return False
                
            if not self.parse_stream_directory():
                return False
            
            return True
            
        except Exception as e:
            print(f"[-] Ошибка парсинга: {e}")
            return False
    
    def parse_header(self) -> bool:
        try:
            data = self.file_handle.read(32)
            if len(data) < 32:
                return False
            
            signature, version, streams_count, stream_dir_rva, checksum, timestamp, flags = \
                struct.unpack('<IIIIIII', data[:28])
            
            if signature != self.MINIDUMP_SIGNATURE:
                print(f"[-] Неверная сигнатура: 0x{signature:08X}")
                return False
            
            self.header = {
                'signature': signature,
                'version': version,
                'streams_count': streams_count,
                'stream_dir_rva': stream_dir_rva,
                'checksum': checksum,
                'timestamp': timestamp,
                'flags': flags,
                'dump_time': datetime.fromtimestamp(timestamp)
            }
            
            return True
            
        except Exception as e:
            print(f"[-] Header minidump parsing error: {e}")
            return False
    
    def parse_stream_directory(self) -> bool:
        try:
            self.file_handle.seek(self.header['stream_dir_rva'])
            
            for i in range(self.header['streams_count']):
                data = self.file_handle.read(12)
                if len(data) < 12:
                    break
                    
                stream_type, data_size, rva = struct.unpack('<III', data)
                
                stream_name = self.STREAM_TYPES.get(stream_type, f"Unknown_{stream_type}")
                self.streams[stream_type] = {
                    'type': stream_type,
                    'name': stream_name,
                    'size': data_size,
                    'rva': rva
                }
            
            return True
            
        except Exception as e:
            print(f"[-] Error parsing stream directory: {e}")
            return False
    
    def get_stream_data(self, stream_type: int) -> Optional[bytes]:
        if stream_type not in self.streams:
            return None
            
        stream = self.streams[stream_type]
        self.file_handle.seek(stream['rva'])
        return self.file_handle.read(stream['size'])
    
    def read_unicode_string(self, rva: int) -> Optional[str]:
        """Чтение UNICODE строки с фильтрацией"""
        try:
            if rva == 0:
                return None
                
            self.file_handle.seek(rva)
            
            length_data = self.file_handle.read(4)
            if len(length_data) < 4:
                return None
                
            length = struct.unpack('<I', length_data)[0]
            if length == 0 or length > 65536:
                return None
            
            string_data = self.file_handle.read(length)
            if len(string_data) < length:
                return None
            
            try:
                decoded = string_data.decode('utf-16-le', errors='ignore')
                filtered = ''.join(c for c in decoded if c == '\t' or c == '\n' or c == '\r' or (ord(c) >= 32 and ord(c) != 0xFFFF))
                filtered = filtered.rstrip('\x00')
                
                if not filtered.strip():
                    return None
                    
                return filtered.strip()
            except:
                return None
                
        except:
            return None