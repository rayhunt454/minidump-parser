from typing import Optional
import struct
from datetime import datetime
from .minidump_parser import MiniDumpParser
from .minidump_structs import ProcessInfo

class ProcessInfoExtractor:
    """Извлечение информации о процессе из потока MiscInfoStream и MiscInfoStream2"""
    
    def __init__(self, parser: MiniDumpParser):
        self.parser = parser
        
    def extract_process_info(self) -> ProcessInfo:
        
        data = self.parser.get_stream_data(23)
        if data:
            process_info = self.parse_misc_info_2(data)
            if process_info and process_info.IsAvailable:
                return process_info
            
        data = self.parser.get_stream_data(15)
        if data:
            process_info = self.parse_misc_info(data)
            if process_info and process_info.IsAvailable:
                return process_info
                    
        print("[-] Information about the process was not found.")
        return process_info
    
    def parse_misc_info(self, data: bytes) -> Optional[ProcessInfo]:
        try:
            reader = 0
            size_of_info = struct.unpack_from('<I', data, reader)[0]
            
            if size_of_info < 24:
                return None
            
            flags1 = struct.unpack_from('<I', data, reader + 4)[0]
            process_id = struct.unpack_from('<I', data, reader + 8)[0]
            process_create_time = struct.unpack_from('<I', data, reader + 12)[0]
            process_user_time = struct.unpack_from('<I', data, reader + 16)[0]
            process_kernel_time = struct.unpack_from('<I', data, reader + 20)[0]
            
            if not (flags1 & 0x00000002):
                return None
            
            create_time = datetime.fromtimestamp(process_create_time) if process_create_time > 0 else None

            user_time_ns = process_user_time * 100
            kernel_time_ns = process_kernel_time * 100
            
            uptime = self.calculate_uptime(create_time)

            return ProcessInfo(
                Pid=process_id,
                CreateTime=datetime.fromtimestamp(process_create_time),
                Uptime=uptime,
                UserTime=str(user_time_ns) + "ns",
                KernelTime=str(kernel_time_ns) + "ns",
                IsAvailable=True
            )
            
        except Exception as e:
            print("Error: ",e)
            return None
    
    def calculate_uptime(self,create_time):
        uptime = None
        if create_time and self.parser.header.get('dump_time'):
            uptime = self.parser.header['dump_time'] - create_time

        return uptime
    
    def parse_misc_info_2(self, data: bytes) -> Optional[ProcessInfo]:
        try:
            reader = 0
            size_of_info = struct.unpack_from('<I', data, reader)[0]
            
            if size_of_info < 24:
                return self.parse_misc_info(data)
            
            flags1 = struct.unpack_from('<I', data, reader + 4)[0]
            
            if not (flags1 & 0x00000002):
                return None
            
            process_id = struct.unpack_from('<I', data, reader + 8)[0]
            process_create_time = struct.unpack_from('<I', data, reader + 12)[0]
            process_user_time = struct.unpack_from('<I', data, reader + 16)[0]
            process_kernel_time = struct.unpack_from('<I', data, reader + 20)[0]
            
            create_time = datetime.fromtimestamp(process_create_time) if process_create_time > 0 else None
            
            user_time_ns = process_user_time * 100
            kernel_time_ns = process_kernel_time * 100
            
            uptime = self.calculate_uptime(create_time)
            
            return ProcessInfo(
                Pid=process_id,
                CreateTime=process_create_time,
                Uptime=uptime,
                UserTime=str(user_time_ns) + "ns",
                KernelTime=str(kernel_time_ns) + "ns",
                IsAvailable=True
            )
            
        except:
            return None