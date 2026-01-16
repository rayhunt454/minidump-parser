from typing import Optional, List, Dict
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
import json

@dataclass
class ProcessInfo:
    Pid: int = 0
    CreateTime: Optional[datetime] = None
    Uptime: Optional[timedelta] = None
    UserTime: str = ""
    KernelTime: str = ""
    IsAvailable: bool = False

@dataclass
class HadnleInfo:
    Handle: int = 0
    Type: str = ""
    ObjectName: str = ""
    AccessRight: List[str] = None
    PointCount: int = 0

@dataclass
class VersionInfo:
    FileVersion: str = ""
    ProductVersion: str =  ""
    FileType: str = ""
    Signature: int =  0
    IsValid: bool =  False


@dataclass
class ModuleInfo:
    Name: str = ""
    FilePath: str = ""
    BaseAddress: str = ""
    Size: int = 0
    Checksum: str = ""
    TimeStamp: Optional[datetime] = None
    Type: str = ""
    Version: VersionInfo = field(default=None)

@dataclass
class MiniDump:
    TimeLine: datetime = field(default=None)
    FilePath: str = ""
    Process: ProcessInfo = field(default=None)
    Modules: List[ModuleInfo] = field(default_factory=list)
    Handles: List[HadnleInfo] = field(default_factory=list)
    Artifacts: Dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
    
    def save(self, filename: str):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, 
                     ensure_ascii=False, 
                     indent=2, 
                     default=str)
