#!/usr/bin/env python3
import subprocess
import re
import sys
import os
import json
import argparse

def parse_by_line_func_addr(lines):
    entries = []
    in_section = False
    for ln in lines:
        if ln.startswith('# by_line_func_addr:'):
            in_section = True
            continue
        if in_section:
            if ln.startswith('#') and 'by_' in ln:
                break
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split(',')
            if len(parts) < 4:
                continue
            file_line = parts[0]
            cycles = parts[1]
            # Support both legacy (no count) and new (with count)
            if parts[2].startswith('0x'):
                addr = parts[2]
                count = ''
            else:
                count = parts[2]
                addr = parts[3]
            entries.append((file_line, cycles, addr, count))
    return entries

def parse_by_line(lines):
    entries = []
    in_section = False
    for ln in lines:
        if ln.startswith('# by_line:'):
            in_section = True
            continue
        if in_section:
            if ln.startswith('#') and 'by_' in ln:
                break
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split(',')
            if len(parts) < 2:
                continue
            file_line = parts[0]
            cycles = parts[1]
            entries.append((file_line, cycles))
    return entries

def load_decodedline(elf):
    # Returns map: (basename, line)-> address string '0x....'
    cmd = ['llvm-objdump', '--dwarf=decodedline', elf]
    out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
    m = {}
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        # Expect lines like: 0x0284ac  /path/to/object.c:344
        mobj = re.match(r'^(0x[0-9a-fA-F]+)\s+(.+):(\d+)$', ln)
        if not mobj:
            continue
        addr = mobj.group(1)
        path = mobj.group(2)
        line = mobj.group(3)
        base = path.split('/')[-1]
        key = (base, line)
        if key not in m:
            m[key] = addr
    return m

def symbolize(elf, addr):
    # Return only top function name (backward compatible)
    chain = symbolize_chain(elf, addr)
    if chain:
        return chain.split(' ; ')[0]
    return '??'

def symbolize_chain(elf, addr):
    # Prefer cross addr2line for m68k (-i prints inline chain as pairs: func, file:line)
    try:
        out = subprocess.check_output(['m68k-neogeo-elf-addr2line', '-e', elf, '-f', '-C', '-i', addr], stderr=subprocess.STDOUT, universal_newlines=True)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        # function names are on even indices (0,2,4,...) with file:line following
        funcs = [lines[i] for i in range(0, len(lines), 2)] if lines else []
        if funcs:
            # Reverse to get top -> bottom and join with " -> "
            return ' -> '.join(funcs[::-1])
    except Exception:
        pass
    # Try llvm-symbolizer (prints func then file:line per frame)
    try:
        out = subprocess.check_output(['llvm-symbolizer', '--inlines', '-e', elf, addr], stderr=subprocess.STDOUT, universal_newlines=True)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        funcs = [lines[i] for i in range(0, len(lines), 2)] if lines else []
        if funcs:
            return ' -> '.join(funcs[::-1])
    except Exception:
        pass
    # Fallback to llvm-addr2line
    try:
        out = subprocess.check_output(['llvm-addr2line', '-e', elf, '-f', '-C', '-i', addr], stderr=subprocess.STDOUT, universal_newlines=True)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        funcs = [lines[i] for i in range(0, len(lines), 2)] if lines else []
        if funcs:
            return ' -> '.join(funcs[::-1])
    except Exception:
        pass
    return ''

def main():
    # Support CLI args with env fallbacks
    parser = argparse.ArgumentParser(description='Resolve Geo profiler JSON to include inline function chains and ensure source text.')
    parser.add_argument('--elf', dest='elf', default=None, help='Path to ELF with DWARF (overrides GEO_PROF_ELF)')
    parser.add_argument('--input', dest='inp', default=None, help='Path to profiler JSON (overrides GEO_PROF_JSON)')
    parser.add_argument('--src-base', dest='src_base', default=None, help='Optional source root for reading source lines (overrides GEO_PROF_SRC_BASE)')
    args = parser.parse_args()

    ELF_PATH = args.elf or os.environ.get('GEO_PROF_ELF')
    INPUT_PATH = args.inp or os.environ.get('GEO_PROF_JSON')
    SRC_BASE = args.src_base or os.environ.get('GEO_PROF_SRC_BASE')
    if not ELF_PATH or not INPUT_PATH:
        print('Provide --elf and --input or set GEO_PROF_ELF and GEO_PROF_JSON.', file=sys.stderr)
        parser.print_usage(sys.stderr)
        sys.exit(2)

    with open(INPUT_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # If JSON array, enrich it and print
    s = content.lstrip()
    if s.startswith('['):
        try:
            data = json.loads(content)
        except Exception as e:
            print('# error: failed to parse JSON input', file=sys.stderr)
            sys.exit(1)
        results = []
        for obj in data:
            # Copy and enrich: never remove fields
            out = dict(obj)
            addr = obj.get('address')
            if addr:
                out['function_chain'] = symbolize_chain(ELF_PATH, addr)
            # Ensure source is present
            if not out.get('source') and SRC_BASE:
                fn = out.get('file'); lno = out.get('line') or 0
                if isinstance(fn, str) and isinstance(lno, int) and lno > 0:
                    base = os.path.basename(fn)
                    src_path = os.path.join(SRC_BASE, base)
                    if os.path.exists(src_path):
                        try:
                            with open(src_path, 'r', encoding='utf-8', errors='ignore') as sf:
                                for idx, sl in enumerate(sf, start=1):
                                    if idx == lno:
                                        out['source'] = sl.rstrip('\n').rstrip('\r')
                                        break
                        except Exception:
                            pass
            results.append(out)
        sys.stdout.write(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
        return
    else:
        lines = content.splitlines()

    entries = parse_by_line_func_addr(lines)
    fallback_by_line = False
    if not entries:
        # Try fallback from by_line using decodedline
        bl = parse_by_line(lines)
        if not bl:
            print('No by_line_func_addr or by_line section found; regenerate profile with profiler_version >= 8.', file=sys.stderr)
            sys.exit(1)
        decoded = load_decodedline(ELF_PATH)
        # Build synthetic (file_line, cycles, addr) entries
        tmp = []
        for file_line, cycles in bl:
            if ':' not in file_line:
                continue
            fn, ln = file_line.rsplit(':', 1)
            addr = decoded.get((fn, ln))
            if not addr:
                # try without path (fn already base)
                addr = decoded.get((fn.split('/')[-1], ln))
            if addr:
                tmp.append((file_line, cycles, addr))
        if not tmp:
            print('Could not resolve any addresses via llvm-objdump decodedline.', file=sys.stderr)
            sys.exit(1)
        entries = tmp
        fallback_by_line = True

    # Build JSON output
    results = []
    for ent in entries:
        if len(ent) == 4:
            file_line, cycles, addr, count = ent
            base_fun = ''
            base_inl = ''
        else:
            file_line, cycles, addr, count, base_fun, base_inl = ent
        chain = symbolize_chain(ELF_PATH, addr)
        # Read source text
        src_txt = ''
        fpath = file_line
        lno = 0
        if ':' in file_line:
            fn, ln = file_line.rsplit(':', 1)
            fpath = fn
            try:
                lno = int(ln)
            except ValueError:
                lno = 0
            base = os.path.basename(fn)
            src_path = os.path.join(SRC_BASE, base) if SRC_BASE else None
            if src_path and os.path.exists(src_path) and lno > 0:
                try:
                    with open(src_path, 'r', encoding='utf-8', errors='ignore') as sf:
                        for idx, sl in enumerate(sf, start=1):
                            if idx == lno:
                                src_txt = sl.rstrip('\n').rstrip('\r')
                                break
                except Exception:
                    pass
        obj = {
            'file': fpath,
            'line': lno,
            'cycles': int(cycles) if str(cycles).isdigit() else cycles,
            'address': addr,
            'function_chain': chain,
            'source': src_txt
        }
        if count != '':
            try:
                obj['count'] = int(count)
            except ValueError:
                obj['count'] = count
        if base_fun:
            obj['function'] = base_fun
        if base_inl:
            obj['inline'] = base_inl
        results.append(obj)
    # Print as a single JSON array
    sys.stdout.write(json.dumps(results, ensure_ascii=False, indent=2) + '\n')

if __name__ == '__main__':
    main()
