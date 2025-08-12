#!/usr/bin/env python3
import argparse
import sys
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict
import re

def read_csv_auto(path: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.read_csv(path, sep=';')

def normalize_hostname(name: str) -> str:
    if not isinstance(name, str):
        return ''
    s = name.strip().split()[0]
    if '.' in s:
        s = s.split('.')[0]
    s = s.rstrip('$')
    return s.casefold()

def truthy(val) -> bool:
    if isinstance(val, (bool, np.bool_)):
        return bool(val)
    if val is None:
        return False
    s = str(val).strip().lower()
    return s in {'true','t','1','yes','y','sim','verdadeiro'}

def bool_str(b: bool) -> str:
    return 'true' if bool(b) else 'false'

import warnings
warnings.filterwarnings(
    "ignore",
    message="Could not infer format, so each element will be parsed individually",
    category=UserWarning
)

def parse_date_to_dmy(series: pd.Series) -> pd.Series:
    dt = pd.to_datetime(series, errors='coerce', utc=True)
    out = dt.dt.tz_convert(None).dt.strftime('%d/%m/%Y')
    return out.fillna('')

def normalize_windows_os(os_value: str) -> str:
    if not isinstance(os_value, str) or not os_value.strip():
        return ''
    s = os_value.strip()
    low = s.lower()
    if 'server' in low:
        m = re.search(r'(2008|2012|2016|2019|2022|2025)', s)
        r2 = bool(re.search(r'\bR2\b', s, flags=re.IGNORECASE))
        if m:
            year = m.group(1)
            return f'Microsoft Windows Server {year}' + (' R2' if r2 and year == '2012' else '')
        return 'Microsoft Windows Server'
    for ver in ['11','10','8.1','8','7']:
        if re.search(rf'\b{ver}\b', s):
            return f'Microsoft Windows {ver}'
    if 'windows' in low:
        return 'Microsoft Windows'
    return s

def load_sentinelone(path: Path) -> pd.DataFrame:
    df = read_csv_auto(path)
    # Hostname
    host_col = None
    for c in df.columns:
        if c.lower().strip() in {'endpoint name','computer name','device name'}:
            host_col = c; break
    if host_col is None:
        for c in df.columns:
            cl = c.lower()
            if 'endpoint' in cl and 'name' in cl:
                host_col = c; break
    # OS + Version
    os_col = None; osver_col = None
    for c in df.columns:
        cl = c.lower()
        if cl == 'os':
            os_col = c
        if cl == 'os version':
            osver_col = c
    # Last Seen
    last_seen_col = None
    for c in df.columns:
        cl = c.lower()
        if 'last active' in cl:
            last_seen_col = c; break
    if last_seen_col is None:
        for c in df.columns:
            if c.lower().strip() == 'last seen':
                last_seen_col = c; break
    # Apenas Windows
    if os_col is not None:
        df = df[df[os_col].astype(str).str.contains('Windows', case=False, na=False)].copy()
    elif osver_col is not None:
        df = df[df[osver_col].astype(str).str.contains('Windows', case=False, na=False)].copy()
    # OS + build
    if osver_col is not None:
        parts = df[osver_col].astype(str).str.split(',', n=1, expand=True)
        operating_system = parts[0].str.strip()
        build_number = parts[1].str.strip() if parts.shape[1] > 1 else ''
    else:
        operating_system = df[os_col] if os_col in df else ''
        build_number = ''
    # IP via 'Last Reported IP' (exclusivo quando existir)
    last_reported_ip_col = None
    for c in df.columns:
        if c.lower().strip() == 'last reported ip':
            last_reported_ip_col = c; break
    if last_reported_ip_col:
        ip_series = df[last_reported_ip_col].astype(str).fillna('')
        ip_series = ip_series.map(lambda v: v.split(',')[0].split('|')[0].strip() if isinstance(v, str) else '')
    else:
        ip_cols = [c for c in df.columns if 'ip' in c.lower()]
        prio = ['console visible ip','ip addresses']
        def best_ip(row):
            for p in prio:
                for c in ip_cols:
                    if c.lower() == p:
                        v = str(row.get(c, '')).strip()
                        if v:
                            return v.split(',')[0].split('|')[0].strip()
            for c in ip_cols:
                v = str(row.get(c, '')).strip()
                if v:
                    return v.split(',')[0].split('|')[0].strip()
            return ''
        ip_series = df.apply(best_ip, axis=1) if len(ip_cols) else ''
    out = pd.DataFrame({
        'Hostname': df[host_col].astype(str).str.strip() if host_col in df else '',
        'IP Address': ip_series,
        'Operating System': pd.Series(operating_system).fillna(''),
        'Build Number': pd.Series(build_number).fillna(''),
        'SentinelOne': True,
        'Sentinel Last Seen': df[last_seen_col] if last_seen_col in df else '',
        '_key': (df[host_col] if host_col in df else '').astype(str).map(normalize_hostname),
    })
    out = out[out['_key']!='']
    if 'Sentinel Last Seen' in out:
        out = out.sort_values(by=['Sentinel Last Seen'], ascending=True).drop_duplicates('_key', keep='last')
    else:
        out = out.drop_duplicates('_key', keep='last')
    return out.reset_index(drop=True)

def load_crowdstrike(path: Path) -> pd.DataFrame:
    df = read_csv_auto(path)
    host_col = None
    for c in df.columns:
        if c.lower().strip() in {'hostname','device name','device hostname','host name'}:
            host_col = c; break
    if host_col is None:
        for c in df.columns:
            cl = c.lower()
            if 'host' in cl and 'name' in cl:
                host_col = c; break
    platform_col = None
    for c in df.columns:
        if c.lower().strip() == 'platform':
            platform_col = c; break
    osver_col = None
    for c in df.columns:
        if c.lower().strip() == 'os version':
            osver_col = c; break
    build_col = None
    for c in df.columns:
        if c.lower().strip() == 'build number':
            build_col = c; break
    last_seen_col = None
    for c in df.columns:
        if c.lower().strip() == 'last seen':
            last_seen_col = c; break
    if last_seen_col is None:
        for c in df.columns:
            if 'last seen' in c.lower():
                last_seen_col = c; break
    ip_cols = [c for c in df.columns if 'ip' in c.lower()]
    prio = ['ip address (last seen)','sensor ip address','ip addresses','local ip address(es)']
    if platform_col in df:
        df = df[df[platform_col].astype(str).str.contains('Windows', case=False, na=False)].copy()
    elif osver_col in df:
        df = df[df[osver_col].astype(str).str.contains('Windows', case=False, na=False)].copy()
    def best_ip(row):
        for p in prio:
            for c in ip_cols:
                if c.lower() == p:
                    v = str(row.get(c, '')).strip()
                    if v:
                        return v.split(',')[0].split('|')[0].strip()
        for c in ip_cols:
            v = str(row.get(c, '')).strip()
            if v:
                return v.split(',')[0].split('|')[0].strip()
        return ''
    operating_system = df[osver_col] if osver_col in df else (df[platform_col] if platform_col in df else '')
    build_number = df[build_col] if build_col in df else ''
    out = pd.DataFrame({
        'Hostname': df[host_col].astype(str).str.strip() if host_col in df else '',
        'IP Address': df.apply(best_ip, axis=1),
        'Operating System': operating_system.fillna(''),
        'Build Number': build_number.fillna(''),
        'FalconCS': True,
        'Falcon Last Seen': df[last_seen_col] if last_seen_col in df else '',
        '_key': (df[host_col] if host_col in df else '').astype(str).map(normalize_hostname),
    })
    out = out[out['_key']!='']
    if 'Falcon Last Seen' in out:
        out = out.sort_values(by=['Falcon Last Seen'], ascending=True).drop_duplicates('_key', keep='last')
    else:
        out = out.drop_duplicates('_key', keep='last')
    return out.reset_index(drop=True)

def load_nessus_hosts(path: Path) -> pd.DataFrame:
    df = read_csv_auto(path)
    cols_lower = {c.lower(): c for c in df.columns}
    is_host_level = ('hostname' in cols_lower) and (('credentialed scan' in cols_lower) or ('credentialed_scan' in cols_lower))
    if is_host_level:
        hcol = cols_lower.get('hostname')
        ccol = cols_lower.get('credentialed scan', cols_lower.get('credentialed_scan'))
        ipcol = cols_lower.get('ip address', None)
        oscol = cols_lower.get('operating system', None)
        out = pd.DataFrame({
            'Hostname': df[hcol].astype(str).str.strip(),
            'IP Address': df[ipcol] if ipcol else '',
            'Credentialed Scan': df[ccol].map(truthy),
            'Operating System': df[oscol] if oscol else '',
            '_key': df[hcol].astype(str).map(normalize_hostname)
        })
        return out[out['_key']!=''].drop_duplicates('_key', keep='last').reset_index(drop=True)
    nb = cols_lower.get('netbios_name')
    cred = cols_lower.get('credentialed_scan')
    oscol = cols_lower.get('operating_system')
    ipcol = cols_lower.get('host_ip')
    if not nb or not cred:
        raise ValueError("CSV do Nessus não possui colunas esperadas. Esperado 'netbios_name' e 'Credentialed_Scan'.")
    df['_key'] = df[nb].astype(str).map(normalize_hostname)
    df['_is_win'] = True
    if oscol:
        df['_is_win'] = df[oscol].astype(str).str.contains('Windows', case=False, na=False)
    df['_cred'] = df[cred].map(truthy)
    agg = df.groupby('_key').agg({
        nb: 'last',
        ipcol: 'last' if ipcol else (lambda s: ''),
        oscol: 'last' if oscol else (lambda s: ''),
        '_cred': 'max',
        '_is_win': 'max'
    }).reset_index()
    agg = agg[agg['_is_win']]
    out = pd.DataFrame({
        'Hostname': agg[nb].astype(str).str.strip(),
        'IP Address': agg[ipcol] if ipcol else '',
        'Operating System': agg[oscol] if oscol else '',
        'Credentialed Scan': agg['_cred'],
        '_key': agg['_key']
    })
    return out[out['_key']!=''].reset_index(drop=True)

def consolidate_inventory(s1: pd.DataFrame, cs: pd.DataFrame, nessus: pd.DataFrame):
    s1 = s1.copy(); cs = cs.copy(); nessus = nessus.copy()
    keys = set(s1['_key']).union(set(cs['_key']))
    rows = []
    for k in sorted(keys):
        r = {'_key': k, 'Hostname': '', 'IP Address': '', 'Operating System': '', 'Build Number': '',
             'SentinelOne': False, 'Sentinel Last Seen': '', 'FalconCS': False, 'Falcon Last Seen': '',
             'Nessus': False}
        srow = s1[s1['_key']==k].head(1)
        crow = cs[cs['_key']==k].head(1)
        if len(srow):
            r['Hostname'] = srow.iloc[0]['Hostname']
            r['IP Address'] = srow.iloc[0]['IP Address'] or r['IP Address']
            r['Operating System'] = srow.iloc[0]['Operating System'] or r['Operating System']
            r['Build Number'] = srow.iloc[0]['Build Number'] or r['Build Number']
            r['SentinelOne'] = True
            r['Sentinel Last Seen'] = srow.iloc[0]['Sentinel Last Seen']
        if len(crow):
            if not r['Hostname']:
                r['Hostname'] = crow.iloc[0]['Hostname']
            if not r['IP Address']:
                r['IP Address'] = crow.iloc[0]['IP Address']
            if not r['Operating System']:
                r['Operating System'] = crow.iloc[0]['Operating System']
            if not r['Build Number']:
                r['Build Number'] = crow.iloc[0]['Build Number']
            r['FalconCS'] = True
            r['Falcon Last Seen'] = crow.iloc[0]['Falcon Last Seen']
        nrow = nessus[nessus['_key']==k]
        if len(nrow) and nrow['Credentialed Scan'].any():
            r['Nessus'] = True
        rows.append(r)
    inv = pd.DataFrame(rows)
    # Datas
    for col in ['Sentinel Last Seen','Falcon Last Seen']:
        inv[col] = parse_date_to_dmy(inv[col])
    # OS
    inv['Operating System'] = inv['Operating System'].map(normalize_windows_os)
    # Servers vs Workstations
    inv['_is_server'] = inv['Operating System'].astype(str).str.contains('Windows Server', case=False, na=False)
    inv_ws = inv[~inv['_is_server']].drop(columns=['_is_server','_key'])
    inv_sv = inv[inv['_is_server']].drop(columns=['_is_server','_key'])
    # booleanos como 'true'/'false'
    for df in (inv_ws, inv_sv):
        for c in ['SentinelOne','FalconCS','Nessus']:
            df[c] = df[c].map(bool_str)
        df.sort_values('Hostname', inplace=True)
    # Abas auxiliares
    s1_out = s1.drop(columns=['_key','SentinelOne'], errors='ignore').sort_values('Hostname')
    cs_out = cs.drop(columns=['_key','FalconCS'], errors='ignore').sort_values('Hostname')
    nessus_host = nessus.drop_duplicates('_key', keep='last').drop(columns=['_key'], errors='ignore')
    if 'Credentialed Scan' in nessus_host.columns:
        nessus_host['Credentialed Scan'] = nessus_host['Credentialed Scan'].map(bool_str)
    if 'Operating System' in nessus_host.columns:
        nessus_host['Operating System'] = nessus_host['Operating System'].map(normalize_windows_os)
    return inv_ws, inv_sv, s1_out, cs_out, nessus_host

def build_parser():
    ap = argparse.ArgumentParser(
        description='Consolida inventário Windows (SentinelOne e CrowdStrike) x cobertura Nessus (scan autenticado).',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=True
    )
    ap.add_argument('--man', action='store_true', help='Exibe manual.')
    ap.add_argument('--sentinel','-s', dest='sentinel', required=False, help='CSV export do SentinelOne')
    ap.add_argument('--crowdstrike','-c', dest='crowdstrike', required=False, help='CSV export do CrowdStrike Falcon')
    ap.add_argument('--nessus','-n', dest='nessus', required=False, help='CSV do Nessus (obtido com script "nessus_to_csv.py")')
    ap.add_argument('-o','--output', default='inventario_consolidado.xlsx', help='Arquivo XLSX de saída')
    return ap

def print_manual():
    man = '''
NOME
    edr2nessus.py - Inventário Windows (S1/CS) x cobertura Nessus autenticada

SINOPSE
    python edr2nessus.py --sentinel S1.csv --crowdstrike CS.csv --nessus NESSUS.csv --output OUTPUT.xlsx
    python edr2nessus.py -s S1.csv -c CS.csv -n NESSUS.csv -o OUTPUT.xlsx
'''
    print(man.strip())

def main():
    banner()
    ap = build_parser()
    args = ap.parse_args()
    if args.man or (not args.sentinel or not args.crowdstrike or not args.nessus):
        if args.man:
            print_manual()
            return 0
        else:
            ap.print_help(sys.stderr)
            return 2
    s1 = load_sentinelone(Path(args.sentinel))
    print(f'[OK] Arquivo {args.sentinel} - CARREGADO')
    cs = load_crowdstrike(Path(args.crowdstrike))
    print(f'[OK] Arquivo {args.crowdstrike} - CARREGADO')
    ness = load_nessus_hosts(Path(args.nessus))
    print(f'[OK] Arquivo {args.nessus} - CARREGADO')
    inv_ws, inv_sv, s1_out, cs_out, ness_host = consolidate_inventory(s1, cs, ness)
    with pd.ExcelWriter(args.output, engine='xlsxwriter') as xw:
        inv_ws.to_excel(xw, index=False, sheet_name='Inventario - Workstation')
        inv_sv.to_excel(xw, index=False, sheet_name='Inventario - Servers')
        s1_out.to_excel(xw, index=False, sheet_name='SentinelOne')
        cs_out.to_excel(xw, index=False, sheet_name='FalconCS')
        ness_host.to_excel(xw, index=False, sheet_name='Nessus')
    total = len(inv_ws) + len(inv_sv)
    print(f'[OK] Análise de cruzamento de dados concluída')
    covered = (inv_ws['Nessus'].eq('true').sum() + inv_sv['Nessus'].eq('true').sum())
    print(f'[OK] Hosts (EDR): {total} | Escaneados (Nessus): {covered} ({covered/max(total,1):.1%})')
    print(f'[OK] Arquivo gerado: {args.output}')
    print()
    return 0

def banner():
    print("███████╗██████╗ ██████╗       ██████╗       ███╗   ██╗███████╗███████╗███████╗██╗   ██╗███████╗")
    print("██╔════╝██╔══██╗██╔══██╗      ╚════██╗      ████╗  ██║██╔════╝██╔════╝██╔════╝██║   ██║██╔════╝")
    print("█████╗  ██║  ██║██████╔╝█████╗ █████╔╝█████╗██╔██╗ ██║█████╗  ███████╗███████╗██║   ██║███████╗")
    print("██╔══╝  ██║  ██║██╔══██╗╚════╝██╔═══╝ ╚════╝██║╚██╗██║██╔══╝  ╚════██║╚════██║██║   ██║╚════██║")
    print("███████╗██████╔╝██║  ██║      ███████╗      ██║ ╚████║███████╗███████║███████║╚██████╔╝███████║")
    print("╚══════╝╚═════╝ ╚═╝  ╚═╝      ╚══════╝      ╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝")
    print("                                EDR Inventory 2 Nessus Coverage                   by: 0xdryleaf")
    print()
                                                                                               
if __name__ == '__main__':
    raise SystemExit(main())
