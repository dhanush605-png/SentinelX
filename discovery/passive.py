from __future__ import annotations
import requests
from urllib.parse import urlparse

def discover_passive_subdomains(domain:str, timeout=10):
    # Passive certificate-transparency lookup; no active DNS brute force.
    r=requests.get('https://crt.sh/',params={'q':f'%.{domain}','output':'json'},timeout=timeout)
    r.raise_for_status(); names=set()
    for row in r.json():
        for name in row.get('name_value','').splitlines():
            name=name.strip().lower().lstrip('*.')
            if name==domain or name.endswith('.'+domain): names.add(name)
    return sorted(names)
