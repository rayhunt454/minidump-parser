from datetime import datetime
from typing import Optional, List, Dict
import struct
from .minidump_parser import MiniDumpParser
import os
import hashlib
from pathlib import Path
from .minidump_structs import ModuleInfo, VersionInfo

    

class ModuleExtractor:
    """Извлечение модулей с информацией о версиях"""
    
    def __init__(self, parser: MiniDumpParser):
        self.parser = parser
        self.modules = []
        
    def extract_modules(self) -> List[Dict]:
        
        data = self.parser.get_stream_data(4)
        if not data:
            print("[-] Stream with modules not found")
            return []
        
        try:
            reader = 0
            num_modules = struct.unpack_from('<I', data, reader)[0]
            reader += 4
            
            for i in range(num_modules):
                module = self.parse_module(data, reader, i)
                if module:
                    self.modules.append(module)
                reader += 108
            
            return self.modules
            
        except Exception as e:
            print(f"[-] Module parsing error: {e}")
            return []
    
    def parse_module(self, data: bytes, offset: int, index: int) -> Optional[ModuleInfo]:
        try:
            # MINIDUMP_MODULE структура (108 байт)
            base_of_image = struct.unpack_from('<Q', data, offset)[0]
            size_of_image = struct.unpack_from('<I', data, offset + 8)[0]
            checksum = struct.unpack_from('<I', data, offset + 12)[0]
            timestamp = struct.unpack_from('<I', data, offset + 16)[0]
            module_name_rva = struct.unpack_from('<I', data, offset + 20)[0]
            
            # VS_FIXEDFILEINFO структура (52 байта)
            version_info_offset = offset + 24
            version_info = self.parse_version_info(data, version_info_offset)
            
            # CV и Misc записи (пропускаем по 8 байт каждая)
            cv_record_size = struct.unpack_from('<I', data, version_info_offset + 52)[0]
            cv_record_rva = struct.unpack_from('<I', data, version_info_offset + 56)[0]
            misc_record_size = struct.unpack_from('<I', data, version_info_offset + 60)[0]
            misc_record_rva = struct.unpack_from('<I', data, version_info_offset + 64)[0]
            
            # Читаем имя модуля
            module_name = self.parser.read_unicode_string(module_name_rva)
            if not module_name:
                module_name = f"module_{index}"
            
            module_type = self.get_module_type(module_name)
            
            module_info = ModuleInfo(
                Name=os.path.basename(module_name),
                FilePath=module_name,
                BaseAddress=f"0x{base_of_image:016X}",
                Size=size_of_image,
                Checksum=f"0x{checksum:08X}",
                TimeStamp=datetime.fromtimestamp(timestamp),
                Type=module_type,
                Version=version_info
            )
            
            print(f"  [{len(self.modules)+1}] {module_info.Name} "
                  f"(0x{base_of_image:016X}, {size_of_image:,} байт, {module_type})")
            
            if version_info.FileVersion:
                print(f"      Версия: {version_info.FileVersion}")
            
            return module_info
            
        except Exception as e:
            return None
    
    def parse_version_info(self, data: bytes, offset: int) -> VersionInfo:
        """Парсинг VS_FIXEDFILEINFO структуры"""
        version_info = VersionInfo() 

        try:
            # Читаем сигнатуру
            signature = struct.unpack_from('<I', data, offset)[0]
            if signature != 0xFEEF04BD:  # VS_FFI_SIGNATURE
                return version_info
            
            version_info.Signature = signature #version_info['signature'] = signature
            
            # Читаем версии
            file_version_ms = struct.unpack_from('<I', data, offset + 8)[0]
            file_version_ls = struct.unpack_from('<I', data, offset + 12)[0]
            product_version_ms = struct.unpack_from('<I', data, offset + 16)[0]
            product_version_ls = struct.unpack_from('<I', data, offset + 20)[0]
            
            # Форматируем версии
            file_version = f"{file_version_ms >> 16}.{file_version_ms & 0xFFFF}." \
                          f"{file_version_ls >> 16}.{file_version_ls & 0xFFFF}"
            product_version = f"{product_version_ms >> 16}.{product_version_ms & 0xFFFF}." \
                             f"{product_version_ls >> 16}.{product_version_ls & 0xFFFF}"
            
            # Определяем тип файла
            file_type = struct.unpack_from('<I', data, offset + 32)[0]
            file_type_str = self.get_file_type(file_type)
            
            version_info.FileVersion = file_version
            version_info.ProductVersion = product_version
            version_info.FileType = file_type_str
            version_info.IsValid = True
            
        except Exception as e:
            print("Error: ", e)
            pass
        
        return version_info
    
    def get_file_type(self, file_type: int) -> str:
        file_types = {
            0x00000001: "Application",
            0x00000002: "DLL",
            0x00000003: "Driver",
            0x00000004: "Font",
            0x00000005: "Virtual Device",
            0x00000007: "Static Library"
        }
        
        return file_types.get(file_type, f"Unknown (0x{file_type:08X})")
    
    def get_module_type(self, module_name: str) -> str:
        lower_name = module_name.lower()
        if lower_name.endswith('.dll'):
            return 'DLL'
        elif lower_name.endswith('.exe'):
            return 'EXE'
        elif lower_name.endswith('.sys'):
            return 'DRIVER'
        else:
            return 'OTHER'


    def dump_module(self, module_info: ModuleInfo, output_dir: str) -> Optional[str]:
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            base_address = int(module_info.BaseAddress, 16)
            size = module_info.Size
            
            module_data = self.extract_module_memory(base_address, size)
            if not module_data:
                print(f"    [-] Failed to retrieve module data {module_info.Name}")
                return None
            
            safe_name = self._create_filename(module_info)
            
            filepath = output_path / safe_name
            
            with open(filepath, 'wb') as f:
                f.write(module_data)
            
            file_hash = hashlib.sha256(module_data).hexdigest()[:16]
            
            print(f"    [+] Save: {safe_name} ({len(module_data):,} bytes, SHA256:{file_hash})")
            
            return str(filepath)
            
        except Exception as e:
            print(f"    [-] Error saving module {module_info.Name}: {e}")
            return None
    
    def dump_all_modules(self, output_dir: str, 
                        filter_types: Optional[List[str]] = None,
                        min_size: int = 1024) -> Dict[str, str]:
        """
        Дамп всех модулей в указанную директорию
        
        Args:
            output_dir: Директория для сохранения
            modules: Список модулей для дампа
            filter_types: Фильтр по типам модулей (например, ['DLL', 'EXE'])
            min_size: Минимальный размер модуля для дампа
            
        Returns:
            Словарь {имя_файла: путь_к_файлу}
        """
        if not self.modules:
            print("[-] Нет модулей для дампа")
            return {}
        
        # Применяем фильтры
        modules_to_dump = []
        
        for module in self.modules:
            # Фильтр по типу
            if filter_types and module.Type not in filter_types:
                continue
            
            # Фильтр по размеру
            if module.Size < min_size:
                continue
            
            modules_to_dump.append(module)
        
        if not modules_to_dump:
            print(f"[-] There are no modules matching the filters.")
            return {}
              
        dumped_files = {}
        
        for i, module in enumerate(modules_to_dump, 1):
            
            filepath = self.dump_module(module, output_dir)
            if filepath:
                dumped_files[module.Name] = filepath
        
        return dumped_files
    
    def extract_module_memory(self, base_address: int, size: int) -> Optional[bytes]:
        """
        Извлечение данных модуля из всех фрагментов памяти
        
        Args:
            base_address: Базовый адрес модуля
            size: Размер модуля
            
        Returns:
            Байты модуля или None
        """

        module_buffer = bytearray(size)
        bytes_filled = 0
        
        data_64 = self.parser.get_stream_data(9)
        if data_64:
            bytes_filled += self._collect_from_memory64(data_64, base_address, size, module_buffer)

        data_5 = self.parser.get_stream_data(5)
        if data_5:
            bytes_filled += self._collect_from_memory_list(data_5, base_address, size, module_buffer)
        
        if bytes_filled == 0:
            return None
        
        return bytes(module_buffer)
    
    def _collect_from_memory64(self, data: bytes, base_address: int, size: int, buffer: bytearray) -> int:
        """Сбор данных из Memory64ListStream"""
        bytes_collected = 0
        
        try:
            reader = 0
            num_ranges = struct.unpack_from('<Q', data, reader)[0]
            reader += 8
            base_rva = struct.unpack_from('<Q', data, reader)[0]
            reader += 8
            
            current_rva = base_rva
            
            for _ in range(num_ranges):
                start_addr = struct.unpack_from('<Q', data, reader)[0]
                reader += 8
                data_size = struct.unpack_from('<Q', data, reader)[0]
                reader += 8
                
                # Проверяем пересечение диапазона с модулем
                intersect_start = max(start_addr, base_address)
                intersect_end = min(start_addr + data_size, base_address + size)
                
                if intersect_start < intersect_end:
                    # Вычисляем смещения
                    module_offset = intersect_start - base_address
                    range_offset = intersect_start - start_addr
                    intersect_size = intersect_end - intersect_start
                    
                    # Читаем данные из файла
                    self.parser.file_handle.seek(current_rva + range_offset)
                    memory_data = self.parser.file_handle.read(intersect_size)
                    
                    # Копируем в буфер модуля
                    buffer[module_offset:module_offset + intersect_size] = memory_data
                    bytes_collected += intersect_size
                
                current_rva += data_size
            
            return bytes_collected
            
        except Exception as e:
            print(f"      [-] Error collecting from Memory64Stream: {e}")
            return bytes_collected
    
    def _collect_from_memory_list(self, data: bytes, base_address: int, size: int, buffer: bytearray) -> int:
        """Сбор данных из MemoryListStream"""
        bytes_collected = 0
        
        try:
            reader = 0
            num_entries = struct.unpack_from('<I', data, reader)[0]
            reader += 4
            
            for _ in range(num_entries):
                start_addr = struct.unpack_from('<Q', data, reader)[0]
                reader += 16  # пропускаем 16 байт (start_addr + зарезервировано)
                
                data_size = struct.unpack_from('<I', data, reader)[0]
                reader += 4
                data_rva = struct.unpack_from('<I', data, reader)[0]
                reader += 4
                
                intersect_start = max(start_addr, base_address)
                intersect_end = min(start_addr + data_size, base_address + size)
                
                if intersect_start < intersect_end:
                    module_offset = intersect_start - base_address
                    range_offset = intersect_start - start_addr
                    intersect_size = intersect_end - intersect_start
                    
                    self.parser.file_handle.seek(data_rva + range_offset)
                    memory_data = self.parser.file_handle.read(intersect_size)
                    
                    buffer[module_offset:module_offset + intersect_size] = memory_data
                    bytes_collected += intersect_size
                    
            return bytes_collected
            
        except Exception as e:
            print(f"      [-] Error collecting from MemoryListStream: {e}")
            return bytes_collected
    
    def _create_filename(self, module_info: ModuleInfo) -> str:
        """
        Создание файла для модуля
        
        Args:
            module_info: Информация о модуле
            
        Returns:
            Безопасное имя файла
        """
        base_name = module_info.Name
        
        if not base_name or base_name == "unknown":
            base_name = f"module_{module_info.BaseAddress.replace('0x', '')}"
        
        if '\\' in base_name:
            base_name = base_name.split('\\')[-1]
        if '/' in base_name:
            base_name = base_name.split('/')[-1]
        
        import re
        safe_name = re.sub(r'[<>:"/\\|?*]', '_', base_name)
        
        if len(safe_name) > 100:
            name, ext = os.path.splitext(safe_name)
            safe_name = name[:100 - len(ext)] + ext
        
        timestamp = ""
        if module_info.TimeStamp:
            timestamp = f"_{module_info.TimeStamp.strftime('%Y%m%d_%H%M%S')}"
        
        if not safe_name.lower().endswith(('.dll', '.exe', '.sys', '.drv', '.ocx', '.cpl')):
            safe_name += f"_{module_info.Type.lower()}"
        
        return safe_name + timestamp + ".bin"