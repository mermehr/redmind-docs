\
#!/usr/bin/env python3
\"\"\"recon_parser.py - extended parser

Accepts:
  - nmap normal (-oN) file (required)
  - optional: --xml <nmap.xml> for richer parse (service banners, script output)
  - zero or more gobuster/ffuf CSV/text outputs
Outputs:
  - <target>_recon.md (detailed markdown)
  - <target>_recon.csv (machine-friendly ports/services)
  - <target>_recon.txt (plain text summary)
\"\"\"
import argparse, re, os, sys, csv, pathlib, xml.etree.ElementTree as ET
from typing import List, Tuple

def parse_nmap_text(path):
    host=None; ips=[]; ports=[]
    os_info=[]
    try:
        with open(path,'r',errors='ignore') as f:
            for line in f:
                if 'Nmap scan report for' in line:
                    m=re.search(r'Nmap scan report for (\S+)', line)
                    if m: host=m.group(1)
                    ipm=re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ipm and ipm.group(1) not in ips: ips.append(ipm.group(1))
                m=re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?$', line.strip())
                if m:
                    port,proto,state,service,rest = m.groups()
                    version = rest or ''
                    ports.append({'proto':proto,'port':int(port),'state':state,'service':service,'version':version.strip()})
                if line.startswith('OS details:') or line.startswith('Aggressive OS guesses:') or line.startswith('Running:'):
                    os_info.append(line.strip())
    except FileNotFoundError:
        pass
    return host, ips, ports, os_info

def parse_nmap_xml(path):
    # parse for host, ips, ports, banners, script output
    host=None; ips=[]; ports=[]
    try:
        tree=ET.parse(path); root=tree.getroot()
        for host_el in root.findall('host'):
            addr=host_el.find('address')
            if addr is not None and addr.get('addr') not in ips:
                ips.append(addr.get('addr'))
            hostnames = host_el.find('hostnames')
            if hostnames is not None:
                hn = hostnames.find('hostname')
                if hn is not None and hn.get('name'): host = hn.get('name')
            ports_el = host_el.find('ports')
            if ports_el is None: continue
            for p in ports_el.findall('port'):
                proto=p.get('protocol')
                portid=int(p.get('portid'))
                state_el=p.find('state')
                state=state_el.get('state') if state_el is not None else ''
                svc=p.find('service')
                service = svc.get('name') if svc is not None and 'name' in svc.keys() else ''
                version=''
                if svc is not None:
                    parts=[]
                    for k in ('product','version','extrainfo','hostname'):
                        if svc.get(k): parts.append(svc.get(k))
                    version=' '.join(parts)
                script_out=''
                scripts = p.findall('script')
                if scripts:
                    script_out='; '.join([s.get('output','') for s in scripts])
                ports.append({'proto':proto,'port':portid,'state':state,'service':service,'version':version,'script':script_out})
    except Exception as e:
        # XML may be malformed, ignore
        pass
    return host, ips, ports

def parse_gobuster_text(path):
    endpoints=[]
    try:
        with open(path,'r',errors='ignore') as f:
            data=f.read()
            # try CSV ffuf output (simple)
            for m in re.findall(r'/(.*?)\\,?\\d*\\,?\\d*\\,?\\d*\\n', data):
                if m:
                    endpoints.append('/'+m.strip())
            # fallback gobuster style
            endpoints += re.findall(r'(/\\S+)\\s+\\(Status:\\s*\\d+', data)
    except FileNotFoundError:
        pass
    return sorted(set(endpoints))

def write_txt(path, target, ips, ports, os_info, endpoints):
    lines=[]
    lines.append(f'[+] Target: {target}')
    lines.append('')
    if ips:
        lines.append('[+] IPs:'); lines += [f'  - {i}' for i in ips]; lines.append('')
    if ports:
        lines.append('[+] Open ports:')
        for p in sorted(ports, key=lambda x:(x['proto'], x['port'])):
            v = f\" | {p.get('version','')}\" if p.get('version') else ''
            s = f\" | script: {p.get('script')}\" if p.get('script') else ''
            lines.append(f\"  - {p['proto'].upper()} {p['port']} | {p['service']}{v}{s}\")
        lines.append('')
    if os_info:
        lines.append('[+] OS fingerprint:'); lines += [f'  - {x}' for x in os_info]; lines.append('')
    lines.append('[+] HTTP endpoints:'); lines += [f'  - {e}' for e in endpoints] if endpoints else lines.append('  - _None detected_')
    with open(path,'w') as f: f.write('\\n'.join(lines)+'\\n')

def write_md(path, target, ips, ports, os_info, endpoints):
    md=[f'# Recon Summary — {target}','']
    if ips: md += ['## IPs'] + [f'- {i}' for i in ips] + ['']
    if ports:
        md += ['## Open Ports','']
        for p in sorted(ports, key=lambda x:(x['proto'], x['port'])):
            ver = f' — {p.get("version")}' if p.get('version') else ''
            script = f'  \n  - script: `{p.get("script")}`' if p.get('script') else ''
            md.append(f'- **{p["proto"].upper()} {p["port"]}**: {p.get("service","unknown")}{ver}{script}')
        md += ['']
    if os_info:
        md += ['## OS Fingerprint'] + [f'- {x}' for x in os_info] + ['']
    md += ['## HTTP Endpoints','']
    if endpoints:
        md += [f'- `{e}`' for e in endpoints]
    else:
        md += ['- _None detected_']
    md.append('')
    with open(path,'w') as f: f.write('\\n'.join(md)+'\\n')

def write_csv(path, ports):
    with open(path,'w',newline='') as csvf:
        w=csv.writer(csvf)
        w.writerow(['proto','port','state','service','version','script'])
        for p in sorted(ports, key=lambda x:(x['proto'], x['port'])):
            w.writerow([p.get('proto'), p.get('port'), p.get('state'), p.get('service'), p.get('version',''), p.get('script','')])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('nmap', help='nmap -oN file (plaintext)')
    ap.add_argument('gobuster', nargs='*', help='zero or more gobuster/ffuf outputs')
    ap.add_argument('--xml', help='optional nmap XML (-oX) to parse for richer details')
    ap.add_argument('--outdir', default='.', help='output directory')
    args = ap.parse_args()

    host, ips, ports, os_info = parse_nmap_text(args.nmap)
    if args.xml:
        h2, ips2, ports2 = parse_nmap_xml(args.xml)
        # prefer XML details if present (merge)
        if ips2: ips = list(dict.fromkeys(ips + ips2))
        if ports2:
            # merge ports by (proto,port) preferring xml details
            bykey = {(p['proto'],p['port']):p for p in ports}
            for p in ports2:
                bykey[(p['proto'],p['port'])]=p
            ports = list(bykey.values())

    # gather endpoints from gobuster/ffuf files
    endpoints=[]
    for g in args.gobuster:
        endpoints += parse_gobuster_text(g)
    endpoints = sorted(set(endpoints))

    target_id = (ips[0] if ips else (host or 'unknown')).replace('/','_')
    pathlib.Path(args.outdir).mkdir(parents=True,exist_ok=True)
    txt = os.path.join(args.outdir,f'{target_id}_recon.txt')
    md  = os.path.join(args.outdir,f'{target_id}_recon.md')
    csvp= os.path.join(args.outdir,f'{target_id}_recon.csv')

    write_txt(txt, target_id, ips, ports, os_info, endpoints)
    write_md(md, target_id, ips, ports, os_info, endpoints)
    write_csv(csvp, ports)

    print(f'[+] Wrote: {txt}')
    print(f'[+] Wrote: {md}')
    print(f'[+] Wrote: {csvp}')

if __name__ == '__main__':
    main()
