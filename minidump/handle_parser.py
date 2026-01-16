from datetime import datetime
from typing import Optional, List, Dict
import struct
import time
from .minidump_parser import MiniDumpParser
from .minidump_structs import HadnleInfo


class HandleParser:
    """Парсер хэндлов"""
    
    TARGET_TYPES = {'Key', 'Mutant', 'File'}
    
    def __init__(self, parser: MiniDumpParser):
        self.parser = parser
        self.handles = []
        
    def parse_handles(self) -> List[Dict]:
       
        
        data = self.parser.get_stream_data(12)
        if not data:
            print("[-] Stream with handles not found")
            return []
        
        try:
            reader = 0
            size_of_header = struct.unpack_from('<I', data, reader)[0]
            reader += 4
            size_of_descriptor = struct.unpack_from('<I', data, reader)[0]
            reader += 4
            number_of_descriptors = struct.unpack_from('<I', data, reader)[0]
            reader += 4
            reader += 4
            
            print(f"[+] Handle descriptors: {number_of_descriptors}")
            
            processed = 0
            valid_handles = 0
            
            for i in range(number_of_descriptors): 
                processed += 1
                
                if size_of_descriptor == 32:
                    handle_info = self.parse_handle_descriptor_2(data, reader)
                else:
                    handle_info = self.parse_handle_descriptor(data, reader)
                
                if handle_info:
                    self.handles.append(handle_info)
                    valid_handles += 1
                    
                    if valid_handles <= 10:
                        obj_name = handle_info.ObjectName
                        if len(obj_name) > 30:
                            obj_name = obj_name[:27] + "..."
                        print(f"  [{valid_handles}] {handle_info.Type}: "
                              f"{handle_info.Handle} {obj_name}")
                
                reader += size_of_descriptor
                
                if processed % 1000 == 0:
                    print(f"    Processed {processed}/{number_of_descriptors}...")
            
            return self.handles
            
        except Exception as e:
            print(f"[-] Error Hadnle Parse: {e}")
            return []
    
    def parse_handle_descriptor(self, data: bytes, offset: int) -> Optional[HadnleInfo]:
        try:
            handle = struct.unpack_from('<Q', data, offset)[0]
            type_name_rva = struct.unpack_from('<I', data, offset + 8)[0]
            object_name_rva = struct.unpack_from('<I', data, offset + 12)[0]
            attributes = struct.unpack_from('<I', data, offset + 16)[0]
            granted_access = struct.unpack_from('<I', data, offset + 20)[0]
            handle_count = struct.unpack_from('<I', data, offset + 24)[0]
            pointer_count = struct.unpack_from('<I', data, offset + 28)[0]
            
            type_name = self.parser.read_unicode_string(type_name_rva)
            if not type_name or type_name not in self.TARGET_TYPES:
                return None
            
            object_name = self.parser.read_unicode_string(object_name_rva)
            if not object_name:
                return None
            
            if len(object_name) > 0:
                handle_info = HadnleInfo(
                    Handle=f"0x{handle:X}",
                    Type=type_name,
                    ObjectName=object_name,
                    PointCount=pointer_count,
                    AccessRight=self.decode_access_rights(type_name, granted_access)
                )                
                return handle_info
            
            return None
        except Exception as e:
            print("Error Hadnle Descriptor: ", e)
            return None
    
    def parse_handle_descriptor_2(self, data: bytes, offset: int) -> Optional[HadnleInfo]:
        try:
            handle = struct.unpack_from('<Q', data, offset)[0]
            type_name_rva = struct.unpack_from('<I', data, offset + 8)[0]
            object_name_rva = struct.unpack_from('<I', data, offset + 12)[0]
            attributes = struct.unpack_from('<I', data, offset + 16)[0]
            granted_access = struct.unpack_from('<I', data, offset + 20)[0]
            handle_count = struct.unpack_from('<I', data, offset + 24)[0]
            pointer_count = struct.unpack_from('<I', data, offset + 28)[0]
            object_info_rva = struct.unpack_from('<I', data, offset + 32)[0]
            reserved0 = struct.unpack_from('<I', data, offset + 36)[0]
            
            type_name = self.parser.read_unicode_string(type_name_rva)
            if not type_name or type_name not in self.TARGET_TYPES:
                return None
            
            object_name = self.parser.read_unicode_string(object_name_rva)
            if not object_name:
                return None
            
            if len(object_name) > 0:
                handle_info = HadnleInfo(
                    Handle=f"0x{handle:X}",
                    Type=type_name,
                    ObjectName=object_name,
                    PointCount=pointer_count,
                    AccessRight=self.decode_access_rights(type_name, granted_access)
                )
          
                return handle_info
            
            return None
            
        except Exception as e:
            print("Error Hadnle Descriptor 2: ", e)
            return None
    
    def decode_access_rights(self, type_name: str, access_mask: int) -> List[str]:
        rights = []
        
        if type_name == 'Key':
            if access_mask & 0x00020006: rights.append("KEY_QUERY_VALUE")
            if access_mask & 0x0002000E: rights.append("KEY_SET_VALUE")
            if access_mask & 0x00020019: rights.append("KEY_CREATE_SUB_KEY")
            if access_mask & 0x00020004: rights.append("KEY_ENUMERATE_SUB_KEYS")
            if access_mask & 0x000F003F: rights.append("KEY_ALL_ACCESS")
            
        elif type_name == 'File':
            if access_mask & 0x80000000: rights.append("GENERIC_READ")
            if access_mask & 0x40000000: rights.append("GENERIC_WRITE")
            if access_mask & 0x20000000: rights.append("GENERIC_EXECUTE")
            if access_mask & 0x10000000: rights.append("GENERIC_ALL")
            if access_mask & 0x00000100: rights.append("FILE_READ_DATA")
            if access_mask & 0x00000200: rights.append("FILE_WRITE_DATA")
            
        elif type_name == 'Mutant':
            if access_mask & 0x001F0001: rights.append("MUTANT_ALL_ACCESS")
            if access_mask & 0x00000001: rights.append("SYNCHRONIZE")
            if access_mask & 0x00010000: rights.append("QUERY_STATE")
        
        return rights if rights else [f"0x{access_mask:08X}"]