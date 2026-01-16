from typing import List, Dict
import struct
from .minidump_parser import MiniDumpParser
import re

class URLProcessor:
    """Очистка URL"""
    
    @staticmethod
    def clean_url(url: str) -> str:
        if not url:
            return ""
        
        cleaned = ''.join(char for char in url if 32 <= ord(char) < 127)
        
        url_endings = [' ', '\t', '\n', '\r', '<', '>', '"', "'", '\\', ']', ')', '}']
        end_pos = len(cleaned)
        
        for ending in url_endings:
            pos = cleaned.find(ending)
            if pos != -1 and pos < end_pos:
                end_pos = pos
        
        if end_pos < len(cleaned):
            cleaned = cleaned[:end_pos]
        
        while cleaned and cleaned[-1] in ['.', ',', ';', ':', '!', '?', '-', '_', '\\']:
            if any(cleaned.endswith(ext) for ext in ['.com', '.ru', '.org', '.net', '.io']):
                break
            cleaned = cleaned[:-1]
        
        return cleaned.strip()
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        if not url or len(url) < 10:
            return False
        
        if not (url.startswith('http://') or url.startswith('https://')):
            return False
        
        if '.' not in url[8:]:
            return False
        
        if url.endswith('.'):
            return False
        
        return True


class ArtifactScanner:
    """Сканер артефактов"""
    
    def __init__(self, parser: MiniDumpParser):
        self.parser = parser
        self.url_processor = URLProcessor()
        
        self.patterns = {
            'urls': re.compile(r'https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]+'),
            'ip_addresses': re.compile(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                              r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                              r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                              r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            'domains': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
                                 r'[a-zA-Z]{2,}\b')
        }
    
    def scan(self) -> Dict:
        
        # Создаем результаты для каждого паттерна
        results = {name: [] for name in self.patterns.keys()}
        
        memory_blocks = self.get_memory_blocks()
        if not memory_blocks:
            print("[-] Memory blocks not found")
            return results
        
        total_scanned = 0
        
        for i, block in enumerate(memory_blocks):
            if i % 10 == 0 and i > 0:
                print(f"  Scanning... {i}/{len(memory_blocks)}")
            
            data = block['data']
            
            try:
                text = data.decode('utf-8', errors='ignore')
                total_scanned += len(data)
            except:
                continue
            
            # Сканируем всеми паттернами
            for pattern_name, pattern in self.patterns.items():
                matches = pattern.finditer(text)
                for match in matches:
                    found_text = match.group()
                    
                    # Обработка в зависимости от типа паттерна
                    if pattern_name == 'urls':
                        cleaned = self.url_processor.clean_url(found_text)
                        if cleaned and self.url_processor.is_valid_url(cleaned):
                            results[pattern_name].append(cleaned)
                    
                    elif pattern_name == 'domains':
                        domain = found_text.lower()
                        if self.is_valid_domain(domain):
                            results['domains'].append(domain)
                    else:
                        results[pattern_name].append(found_text)
        
        # Удаляем дубликаты
        for pattern_name in results:
            unique_results = []
            seen = set()
            for item in results[pattern_name]:
                if item not in seen:
                    seen.add(item)
                    unique_results.append(item)
            results[pattern_name] = unique_results
        
        return results
    
    def get_memory_blocks(self) -> List[Dict]:
        memory_blocks = []
        
        data_64 = self.parser.get_stream_data(9)
        if data_64:
            memory_blocks.extend(self.parse_memory64(data_64))
        
        data_5 = self.parser.get_stream_data(5)
        if data_5:
            memory_blocks.extend(self.parse_memory_list(data_5))
        
        memory_blocks.sort(key=lambda x: len(x['data']), reverse=True)
        
        return memory_blocks
    
    def parse_memory64(self, data: bytes) -> List[Dict]:
        blocks = []
        
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
                
                if data_size > 0:
                    self.parser.file_handle.seek(current_rva)
                    memory_data = self.parser.file_handle.read(min(data_size, 2 * 1024 * 1024))
                    
                    blocks.append({
                        'start': start_addr,
                        'size': data_size,
                        'data': memory_data
                    })
                
                current_rva += data_size
                
        except:
            pass
        
        return blocks
    
    def parse_memory_list(self, data: bytes) -> List[Dict]:
        blocks = []
        
        try:
            reader = 0
            num_entries = struct.unpack_from('<I', data, reader)[0]
            reader += 4
            
            for _ in range(num_entries):
                start_addr = struct.unpack_from('<Q', data, reader)[0]
                reader += 16
                data_size = struct.unpack_from('<I', data, reader)[0]
                reader += 4
                data_rva = struct.unpack_from('<I', data, reader)[0]
                reader += 4
                
                if data_size > 0:
                    self.parser.file_handle.seek(data_rva)
                    memory_data = self.parser.file_handle.read(min(data_size, 2 * 1024 * 1024))
                    
                    blocks.append({
                        'start': start_addr,
                        'size': data_size,
                        'data': memory_data
                    })
                    
        except:
            pass
        
        return blocks
    
    def is_valid_domain(self, domain: str) -> bool:
        if not domain or len(domain) < 4:
            return False
        
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        tld = parts[-1]
        if len(tld) < 2 or tld in ['exe', 'dll', 'sys', 'txt', 'log']:
            return False
        
        if parts[0][0].isdigit():
            return False
        
        return True