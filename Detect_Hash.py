#!/usr/bin/env python3
"""
detect_hashs_cli.py

Batch hash-type detector CLI.

Usage:
    python detect_hashs_cli.py -i hashes.txt
    python detect_hashs_cli.py -i hashes_with_usernames.txt -o out.csv --format csv --pair-separator ":" --verbose

Input file accepts:
 - One hash per line:
     482c811da5d5b4bc6d497ffa98491e38
 - Or "username:hash" or "username,hash" lines if you use --parse-pairs (auto tries common separators).

Output:
 - Printed table to stdout by default.
 - Optional CSV (--format csv) or JSON (--format json) saved with --output <file>.

Only uses local heuristics (length / charset / known prefixes).
"""

from __future__ import annotations
import argparse
import csv
import json
import re
from typing import List, Tuple, Dict, Optional
from collections import Counter, defaultdict

HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')

def is_hex(s: str) -> bool:
    return bool(HEX_RE.fullmatch(s))

def is_base64(s: str) -> bool:
    return bool(B64_RE.fullmatch(s))

def detect_by_prefix(s: str) -> List[Tuple[str, str]]:
    s = s.strip()
    out = []
    if s.startswith(('$2a$', '$2b$', '$2y$')) or s.startswith('2a$') or s.startswith('2y$'):
        out.append(('bcrypt', 'bcrypt starts with $2a$/$2b$/$2y$ and includes salt; ~60 chars total'))
    if s.startswith('$argon2'):
        out.append(('argon2', 'Argon2 formatted string with parameters (prefix $argon2...)'))
    if s.lower().startswith('pbkdf2') or s.startswith('pbkdf2:') or s.startswith('pbkdf2$'):
        out.append(('PBKDF2', 'PBKDF2-style string (often contains algo/iterations/salt)'))
    if s.startswith('$scrypt$') or s.lower().startswith('scrypt'):
        out.append(('scrypt', 'scrypt formatted string'))
    if s.startswith('$P$') or s.startswith('$H$') or s.startswith('$S$'):
        out.append(('phpass', 'phpass-style portable hashes (WordPress/Joomla legacy)'))
    if s.startswith('sha1$') or s.startswith('sha256$') or s.startswith('sha512$'):
        out.append(('named-hash-prefixed', 'framework-prefixed hash like "sha1$..."'))
    return out

def detect_by_length_and_charset(s: str) -> List[Tuple[str, str]]:
    s = s.strip()
    n = len(s)
    candidates: List[Tuple[str, str]] = []

    if is_hex(s):
        if n == 32:
            candidates.append(('MD5', '32 hex chars → typical MD5 (also NTLM/MD4 share 32 hex)'))
        if n == 40:
            candidates.append(('SHA-1', '40 hex chars → typical SHA-1'))
        if n == 56:
            candidates.append(('SHA-224', '56 hex chars → SHA-224'))
        if n == 64:
            candidates.append(('SHA-256', '64 hex chars → SHA-256'))
        if n == 96:
            candidates.append(('SHA-384', '96 hex chars → SHA-384'))
        if n == 128:
            candidates.append(('SHA-512', '128 hex chars → SHA-512'))
        if n not in (32, 40, 56, 64, 96, 128):
            # still hex but not common cryptographic lengths
            candidates.append((f'hex_{n}', f'Hex string of length {n} — could be truncated, raw bytes expressed as hex, or non-standard.'))
    else:
        if is_base64(s):
            candidates.append(('base64', 'Looks like base64 — could be raw hash bytes encoded in base64'))
        # bcrypt typical length ~60 (prefix handled above but include a fallback)
        if 50 <= n <= 72 and ('$2' in s or s.startswith('$')):
            candidates.append(('bcrypt-like', 'Length/prefix looks like bcrypt-like formatted string (~60 chars) or other parameterized scheme'))
        # catches other lengths that are common when Base64 or salted
        if 43 <= n <= 88 and is_base64(s):
            candidates.append(('base64_binary_common', 'Base64 likely representing binary hash (common lengths)'))
    return candidates

def detect_hash_type(s: str) -> List[Tuple[str, str]]:
    s = s.strip()
    if not s:
        return []
    results = []
    results.extend(detect_by_prefix(s))
    results.extend(detect_by_length_and_charset(s))
    if not results:
        if len(s) in (32,40,64,128) and is_hex(s):
            results.append(('unknown-hex', 'Matches common hex lengths but not assigned by heuristics'))
        else:
            results.append(('unknown', 'Could not confidently match by prefix/length/charset — maybe salted, truncated or non-standard encoding'))
    # dedupe preserving order
    seen = set()
    uniq = []
    for name, note in results:
        if name not in seen:
            uniq.append((name, note))
            seen.add(name)
    return uniq

def parse_line(line: str, parse_pairs: bool = True, pair_sep: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (identifier, hash) where identifier may be username or None.
    If parse_pairs=True, tries to split on pair_sep, or on common separators (':', ',', whitespace).
    """
    orig = line
    line = line.strip()
    if not line:
        return (None, None)
    # If explicit pair separator provided
    if parse_pairs and pair_sep:
        if pair_sep in line:
            parts = line.split(pair_sep, 1)
            return (parts[0].strip(), parts[1].strip())
    # Try common separators
    if parse_pairs:
        for sep in (':', ',', '\t', ' '):
            if sep in line:
                parts = line.split(sep, 1)
                # be conservative: if the second part looks like a hash (hex/base64/prefixed), accept it
                if parts[1].strip():
                    return (parts[0].strip(), parts[1].strip())
    # else treat whole line as hash
    return (None, line)

def process_file(filename: str, parse_pairs: bool=True, pair_sep: Optional[str]=None, skip_empty: bool=True) -> List[Dict]:
    results = []
    with open(filename, 'r', encoding='utf-8', errors='ignore') as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.rstrip('\n\r')
            if skip_empty and not line.strip():
                continue
            ident, cand = parse_line(line, parse_pairs=parse_pairs, pair_sep=pair_sep)
            if cand is None or not cand.strip():
                # nothing to analyze
                continue
            det = detect_hash_type(cand)
            results.append({
                'lineno': lineno,
                'input': line,
                'identifier': ident,
                'hash': cand,
                'detections': det
            })
    return results

def summarize(results: List[Dict]) -> Dict[str, int]:
    counter = Counter()
    # count the top candidate if available, otherwise 'unknown'
    for r in results:
        if r['detections']:
            top = r['detections'][0][0]
            counter[top] += 1
        else:
            counter['unknown'] += 1
    return dict(counter)

def write_csv(results: List[Dict], outpath: str):
    with open(outpath, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.writer(fh)
        writer.writerow(['lineno', 'identifier', 'hash', 'likely_types', 'notes'])
        for r in results:
            types = ';'.join([t for t, _ in r['detections']]) if r['detections'] else ''
            notes = ' | '.join([n for _, n in r['detections']]) if r['detections'] else ''
            writer.writerow([r['lineno'], r['identifier'] or '', r['hash'], types, notes])

def write_json(results: List[Dict], outpath: str):
    # convert detections to plain lists
    serial = []
    for r in results:
        serial.append({
            'lineno': r['lineno'],
            'identifier': r['identifier'],
            'hash': r['hash'],
            'detections': [{'type': t, 'note': n} for t, n in r['detections']]
        })
    with open(outpath, 'w', encoding='utf-8') as fh:
        json.dump(serial, fh, indent=2)

def pretty_print(results: List[Dict], limit: Optional[int] = 20):
    if not results:
        print("No entries found.")
        return
    print(f"Processed {len(results)} entries. Showing up to {limit} lines:\n")
    for i, r in enumerate(results[:limit], start=1):
        ident = r['identifier'] or '(no id)'
        types = ', '.join([t for t, _ in r['detections']]) if r['detections'] else 'unknown'
        notes = '; '.join([n for _, n in r['detections']]) if r['detections'] else ''
        print(f"{i:3}. line {r['lineno']:4}  id={ident:20}  hash={r['hash']}")
        print(f"      -> likely: {types}")
        if notes:
            print(f"         notes: {notes}")
        print()

def main():
    parser = argparse.ArgumentParser(description="Batch detect likely hash types from a file.")
    parser.add_argument('-i', '--input', required=True, help="Input file with one hash per line or username:hash pairs")
    parser.add_argument('-o', '--output', help="Optional output file (CSV or JSON). Use --format to select")
    parser.add_argument('--format', choices=['csv', 'json', 'plain'], default='plain', help="Output format when using --output (default: plain print).")
    parser.add_argument('--parse-pairs', action='store_true', help="Attempt to parse lines as username:hash or username,hash pairs.")
    parser.add_argument('--pair-separator', help="Force a specific separator for pairs (e.g. ':', ','). If omitted, common separators are tried.")
    parser.add_argument('--skip-empty', action='store_true', default=True, help="Skip empty lines (default: True). Use --no-skip-empty to keep blank lines.")
    parser.add_argument('--no-skip-empty', dest='skip_empty', action='store_false', help="Do not skip empty lines.")
    parser.add_argument('--limit', type=int, default=20, help="How many example lines to print to stdout (default 20).")
    parser.add_argument('--verbose', action='store_true', help="Verbose output during processing.")
    args = parser.parse_args()

    if args.verbose:
        print(f"[+] Input file: {args.input}")
        print(f"[+] Parse pairs: {args.parse_pairs}, pair_sep: {args.pair_separator}")
        print(f"[+] Skip empty: {args.skip_empty}")

    results = process_file(args.input, parse_pairs=args.parse_pairs, pair_sep=args.pair_separator, skip_empty=args.skip_empty)

    if args.output:
        fmt = args.format
        if fmt == 'csv':
            write_csv(results, args.output)
            if args.verbose:
                print(f"[+] Wrote CSV to {args.output}")
        elif fmt == 'json':
            write_json(results, args.output)
            if args.verbose:
                print(f"[+] Wrote JSON to {args.output}")
        else:
            # plain: write a simple text report
            with open(args.output, 'w', encoding='utf-8') as fh:
                for r in results:
                    types = ','.join([t for t,_ in r['detections']]) if r['detections'] else 'unknown'
                    fh.write(f"{r['lineno']}\t{r['identifier'] or ''}\t{r['hash']}\t{types}\n")
            if args.verbose:
                print(f"[+] Wrote plain text to {args.output}")

    # Print summary and preview
    summary = summarize(results)
    print("\nSummary (top predicted type counts):")
    for k, v in sorted(summary.items(), key=lambda kv: -kv[1]):
        print(f"  {k:20} : {v}")
    print()
    pretty_print(results, limit=args.limit)

if __name__ == "__main__":
    main()
