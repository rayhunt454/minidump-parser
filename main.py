import argparse
import os
import time
from datetime import datetime
from minidump import handle_parser
from minidump import minidump_parser
from minidump import process_parser
from minidump import module_parser
from minidump import artifacts
from minidump.minidump_structs import MiniDump


def format_timedelta(td):
    if not td:
        return "Unknown"
    
    total_seconds = int(td.total_seconds())
    
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    days, hours = divmod(hours, 24)
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if seconds > 0 or not parts:
        parts.append(f"{seconds}s")
    
    return "".join(parts)

def main():
    parser = argparse.ArgumentParser(
        description='Mini-dump parser for DFIR',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-f','--dump-file', help='Mini dump file (.dmp)')
    parser.add_argument('-o', '--output', default='analysis.json',help='File for saving a JSON report')
    parser.add_argument('-dump', type=bool, default=False, help="Flag to dump all DLL/EXE from mini-dump")
    parser.add_argument('-dump-dir',default=os.path.join(os.getcwd(), "extract_modules"), help='Path to save all DLL/EXE modules')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.dump_file):
        print(f"[-] File not found: {args.dump_file}")
        return 1
    
    print(f"[*] File analysis: {args.dump_file}")
    print(f"[*] Size: {os.path.getsize(args.dump_file):,} bytes")
    
    start_time = time.time()
    
    # Парсинг дампа
    dump_parser = minidump_parser.MiniDumpParser(args.dump_file)
    if not dump_parser.parse():
        return 1
    
    print(f"[+] The dump header has been parsed.")
    print(f"    TimeLine: {datetime.fromtimestamp(dump_parser.header['timestamp'])}")
    print(f"    Streams: {len(dump_parser.streams)}/{dump_parser.header['streams_count']}")

    # Информация о процессе
    process_extractor = process_parser.ProcessInfoExtractor(dump_parser)
    process_info = process_extractor.extract_process_info()
    print(process_info.Pid)
    
    # Извлечение модулей
    print(f"\n[*] Search for modules...")
    module_extractor = module_parser.ModuleExtractor(dump_parser)
    modules = module_extractor.extract_modules()
    print(f"[+] Modules found: {len(modules)}")
    
    # Парсинг хэндлов
    print(f"\n[*] Search for handles (Key, Mutant, File)...")
    handle_extractor = handle_parser.HandleParser(dump_parser)
    handles = handle_extractor.parse_handles()
    print(f"[+] Open process handles found: {len(handles)}")

    # Поиск сетевых артефактов
    print(f"\n[*] Searching for artifacts in memory...")
    network_scanner = artifacts.ArtifactScanner(dump_parser)
    network_artifacts = network_scanner.scan()
    
    minidump_info = MiniDump(
        TimeLine = dump_parser.header.get('dump_time'),
        FilePath=args.dump_file,
        Process=process_info,
        Modules=modules,
        Handles=handles,
        Artifacts=network_artifacts
    )

    # Дамп модулей в каталог
    if args.dump:
        modules_to_dump = module_extractor.dump_all_modules(args.dump_dir)
        print(f"\n{'='*60}")
        print(f"    Total: {len(modules_to_dump)}")
        print(f"\n  Saved files in: {args.dump_dir}")
    
    minidump_info.save(args.output)    
    dump_parser.close()
    
    print(f"\n" + "="*60)
    print("SUMMARY OF ANALYSIS")
    print("="*60)
    print(f"Analysis time: {time.time() - start_time:.2f} s")
    
    if process_info.IsAvailable:
        print(f"\nProcess Information:")
        print(f"  PID: {process_info.Pid}")
        if process_info.CreateTime:
            print(f"  Create time: {process_info.CreateTime}")
        if process_info.Uptime:
            print(f"  Opening hours: {format_timedelta(process_info.Uptime)}")
        print(f"  User CPU time: {process_info.UserTime}")
        print(f"  Core CPU time: {process_info.KernelTime}")
    
    print(f"\nModules: {len(modules)}")
    print(f"Handles: {len(handles)}")
    print(f"URL: {len(network_artifacts['urls'])}")
    print(f"Domains: {len(network_artifacts['domains'])}")
    print(f"IPs: {len(network_artifacts['ip_addresses'])}")
    print(f"\nThe report is saved in: {args.output}")
    print("="*60)
    
    return 0


if __name__ == "__main__":
    exit(main())