#!/usr/bin/env python3
"""
static_analyzer.py
Safe static analysis MVP:
- computes hashes
- extracts printable strings
- computes byte-entropy
- (optionally) extracts PE metadata if pefile installed
- basic heuristic pattern checks
Outputs a JSON report (no execution).
"""

import os
import sys
import json
import argparse
import hashlib
import math
import string
from datetime import datetime

REPORT_KEYS = [
    "path","size","sha256","sha1","md5",
    "entropy","strings_preview","pe_info",
    "heuristics","timestamp"
]

def file_hashes(path):
    h_sha256 = hashlib.sha256()
    h_sha1 = hashlib.sha1()
    h_md5 = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h_sha256.update(chunk)
            h_sha1.update(chunk)
            h_md5.update(chunk)
    return h_sha256.hexdigest(), h_sha1.hexdigest(), h_md5.hexdigest()

def extract_printable_strings(data: bytes, min_len=4, max_results=200):
    results = []
    current = []
    for b in data:
        c = chr(b)
        if c in string.printable and c != '\x0b' and c != '\x0c':
            current.append(c)
        else:
            if len(current) >= min_len:
                results.append(''.join(current))
                if len(results) >= max_results:
                    break
            current = []
    # final
    if len(current) >= min_len and len(results) < max_results:
        results.append(''.join(current))
    return results

def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

def detect_heu_patterns(data: bytes) -> dict:
    hexs = data.hex()
    patterns = {}
    # heuristic checks (non-exhaustive)
    patterns['nop_sled'] = '90' * 16 in hexs  # long run of 0x90
    patterns['xorpivots'] = any(sig in hexs for sig in ['4831c0', '31c0'])  # xor rax/rax variants
    patterns['suspicious_strings'] = False
    strs = extract_printable_strings(data, min_len=6, max_results=20)
    for s in strs:
        low = s.lower()
        if any(k in low for k in ['password','api_key','secret','token','cmd','shell','exec']):
            patterns['suspicious_strings'] = True
            break
    # entropy
    patterns['high_entropy'] = byte_entropy(data) > 7.5
    patterns['packed_like'] = byte_entropy(data) > 7.0
    return patterns

def pe_info(path):
    try:
        import pefile
    except ImportError:
        return {"pefile": "not_installed"}
    try:
        pe = pefile.PE(path, fast_load=True)
        info = {
            "is_pe": True,
            "entrypoint_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "file_size": pe.OPTIONAL_HEADER.SizeOfImage,
            "machine_type": hex(pe.FILE_HEADER.Machine),
            "imports": [],
            "exports": [],
            "sections": []
        }
        
        # Extract sections info
        for section in pe.sections:
            info['sections'].append({
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': section.get_entropy()
            })
        
        # Extract imports
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore') if isinstance(entry.dll, bytes) else str(entry.dll)
                imports = []
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode('utf-8', errors='ignore'))
                    else:
                        imports.append(f"Ordinal_{imp.ordinal}")
                info['imports'].append({'dll': dll, 'functions': imports})
        except AttributeError:
            pass
        
        # Extract exports
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    export_name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"Ordinal_{exp.ordinal}"
                    info['exports'].append(export_name)
        except AttributeError:
            pass
        
        return info
    except Exception as e:
        return {"pe_error": str(e)}

def analyze(path):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    report = {}
    report['path'] = os.path.abspath(path)
    report['size'] = os.path.getsize(path)
    sha256, sha1, md5 = file_hashes(path)
    report['sha256'] = sha256
    report['sha1'] = sha1
    report['md5'] = md5
    with open(path, "rb") as f:
        data = f.read()
    report['entropy'] = round(byte_entropy(data), 4)
    report['strings_preview'] = extract_printable_strings(data, min_len=4, max_results=100)
    report['heuristics'] = detect_heu_patterns(data)
    # Optional PE info
    report['pe_info'] = pe_info(path)
    report['timestamp'] = datetime.utcnow().isoformat() + "Z"
    return report

def main():
    parser = argparse.ArgumentParser(description="Safe Static Analyzer MVP")
    parser.add_argument("path", help="File to analyze")
    parser.add_argument("--out", help="Output JSON path", default=None)
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"❌ Error: File does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)
    
    rep = analyze(args.path)
    if args.out:
        os.makedirs(os.path.dirname(args.out) if os.path.dirname(args.out) else '.', exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(rep, f, indent=2)
        print(f"💾 Saved report: {args.out}")
    else:
        print(json.dumps(rep, indent=2))

if __name__ == "__main__":
    main()
