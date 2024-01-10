import argparse
import copy
from dataclasses import dataclass
import dataclasses
import datetime
import fnmatch
import functools
import json
import sys
from typing import Dict, Iterable, List, Optional, Union
import urllib.request
from json import JSONEncoder as _JSONEncoder

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

_MULTIPLE_PRODUCTS = 'Multiple Products'
_MULTIPLE_FIREWALLS = 'Multiple Firewalls'
_MULTIPLE_NAS_DEVICES = 'Multiple Network-Attached Storage (NAS) Devices'
_MULTIPLE_ARCHER_DEVICES = 'Multiple Archer Devices'
_MULTIPLE_CHIPSETS = 'Multiple Chipsets'
_MULTIPLE_DEVICES = 'Multiple Devices'
_MULTIPLE_VIGOR_ROUTERS = 'Multiple Vigor Routers'

_MULTIPLE_KEYS = {
    _MULTIPLE_PRODUCTS,
    _MULTIPLE_FIREWALLS,
    _MULTIPLE_NAS_DEVICES,
    _MULTIPLE_ARCHER_DEVICES,
    _MULTIPLE_CHIPSETS,
    _MULTIPLE_DEVICES,
    _MULTIPLE_VIGOR_ROUTERS
}


@dataclass()
class Vulnerability:
    cve_id: str
    vendor: str
    product: str
    name: str
    description: str
    date_added: datetime.date
    due_date: datetime.date
    required_action: str
    known_ransomware_campaign_use: bool
    notes: str

    @property
    def product_full_name(self) -> str:
        v = self.vendor
        p = self.product
        if p.lower().startswith(f'{v.lower()} '):
            p = p
        else:
            p = f'{v} {p}'
        
        # Remove any leading or trailing whitespace.
        return p.strip()

    def applies_to_multiple_products(self) -> bool:
        p = self.product
        for k in _MULTIPLE_KEYS:
            if k in p:
                return True
        return False


@dataclass()
class Filter:
    cve_ids: Iterable[str] = dataclasses.field(default_factory=list)
    vendors: Iterable[str] = dataclasses.field(default_factory=list)
    products: Iterable[str] = dataclasses.field(default_factory=list)
    min_date_added: Optional[datetime.date] = None
    max_date_added: Optional[datetime.date] = None
    min_due_date: Optional[datetime.date] = None
    max_due_date: Optional[datetime.date] = None
    known_ransomware_campaign_use: Optional[bool] = None
    overdue: Optional[bool] = None

    def matches(self, vulnerability: Vulnerability) -> bool:
        if self.known_ransomware_campaign_use is not None and self.known_ransomware_campaign_use != vulnerability.known_ransomware_campaign_use:
            return False

        if self.cve_ids and not str_matches_any(vulnerability.cve_id, self.cve_ids):
            return False
        
        if self.vendors and not str_matches_any(vulnerability.vendor, self.vendors):
            return False
        
        if self.products and not str_matches_any(vulnerability.product, self.products):
            return False
        
        if self.min_date_added and vulnerability.date_added < self.min_date_added:
            return False
        
        if self.max_date_added and vulnerability.date_added > self.max_date_added:
            return False
        
        if self.min_due_date and vulnerability.due_date < self.min_due_date:
            return False
        
        if self.max_due_date and vulnerability.due_date > self.max_due_date:
            return False
        
        if self.overdue is not None:
            now = datetime.datetime.now().date()
            if self.overdue and vulnerability.due_date > now:
                return False

        return True
    
    def empty(self) -> bool:
        return not any([
            self.cve_ids,
            self.vendors,
            self.products,
            self.min_date_added,
            self.max_date_added,
            self.min_due_date,
            self.max_due_date,
            self.known_ransomware_campaign_use,
            self.overdue
        ])

    def __bool__(self) -> bool:
        return self.empty() is False


@dataclass()
class Catalog:
    version: str
    time_released: datetime.datetime
    vulnerabilities: List[Vulnerability]

    @property
    def date_released(self) -> datetime.date:
        return self.time_released.date()
    
    @property
    def age(self) -> datetime.timedelta:
        return datetime.datetime.now() - self.time_released

    @property
    def total(self) -> int:
        return len(self.vulnerabilities)

    @property
    def cve_ids(self) -> List[str]:
        return sorted({e.cve_id for e in self.vulnerabilities}, reverse=True)
    
    @property
    def vendors(self) -> List[str]:
        return sorted({e.vendor for e in self.vulnerabilities})

    @property
    def products(self) -> List[str]:
        return sorted({e.product for e in self.vulnerabilities})
    
    @property
    def product_full_names(self) -> List[str]:
        return sorted({e.product_full_name for e in self.vulnerabilities})

    @property
    def min_due_date(self) -> datetime.date:
        return min([e.due_date for e in self.vulnerabilities])
    
    @property
    def max_due_date(self) -> datetime.date:
        return max([e.due_date for e in self.vulnerabilities])
    
    @property
    def min_date_added(self) -> datetime.date:
        return min([e.date_added for e in self.vulnerabilities])
    
    @property
    def max_date_added(self) -> datetime.date:
        return max([e.date_added for e in self.vulnerabilities])

    @property
    def cve_ids(self) -> List[str]:
        return sorted({e.cve_id for e in self.vulnerabilities})
    
    @property
    def cve_ids_related_to_ransomware(self) -> List[str]:
        return sorted({e.cve_id for e in self.vulnerabilities if e.known_ransomware_campaign_use})

    @property
    def dates_added(self) -> Dict[str, datetime.date]:
        entries = sorted(self.vulnerabilities, key=lambda e: e.cve_id)
        return {e.cve_id: e.date_added for e in entries}
    
    @property
    def due_dates(self) -> Dict[str, datetime.date]:
        entries = sorted(self.vulnerabilities, key=lambda e: e.cve_id)
        return {e.cve_id: e.due_date for e in entries}
    
    def is_up_to_date(self, url: str = KEV_URL) -> bool:
        catalog = download_latest(url=url)
        return catalog['catalogVersion'] == self.version
    
    def update(self, url: str = KEV_URL) -> "Catalog":
        return download_latest(url=url)
    
    def __len__(self) -> int:
        return self.total
    
    def __iter__(self) -> Vulnerability:
        yield from self.vulnerabilities

    def filter(self, f: Union[dict, Filter]) -> "Catalog":
        if isinstance(f, dict):
            f = Filter(**f)

        vulnerabilities = filter(f.matches, self.vulnerabilities)
        return Catalog(
            version=self.version,
            time_released=self.time_released,
            vulnerabilities=list(vulnerabilities)
        )


def download_latest(url: str = KEV_URL) -> Catalog:
    response = urllib.request.urlopen(url)
    catalog = json.loads(response.read())
    catalog = parse_catalog(catalog)
    return catalog


def parse_catalog(o: dict) -> Catalog:
    for f in [_parse_raw_catalog, _parse_processed_catalog]:
        try:
            return f(o)
        except (TypeError, KeyError):
            continue
    else:
        raise ValueError('Failed to parse catalog')


def _parse_raw_catalog(o: dict) -> Catalog:
    vulnerabilities = [_parse_raw_vulnerability(v) for v in o['vulnerabilities']]
    return Catalog(
        version=o['catalogVersion'],
        time_released=datetime.datetime.fromisoformat(o['dateReleased']),
        vulnerabilities=vulnerabilities
    )


def _parse_processed_catalog(o: dict) -> Catalog:
    vulnerabilities = [_parse_processed_vulnerability(v) for v in o['vulnerabilities']]
    return Catalog(
        version=o['version'],
        time_released=datetime.datetime.fromisoformat(o['time_released']),
        vulnerabilities=vulnerabilities
    )


def parse_vulnerability(o: dict) -> Vulnerability:
    for f in [_parse_raw_vulnerability, _parse_processed_vulnerability]:
        try:
            return f(o)
        except (TypeError, KeyError):
            continue
    else:
        raise ValueError('Failed to parse vulnerability')


def _parse_raw_vulnerability(o: dict) -> Vulnerability:
    return Vulnerability(
        cve_id=o['cveID'],
        vendor=o['vendorProject'],
        product=o['product'],
        name=o['vulnerabilityName'],
        description=o['shortDescription'],
        date_added=datetime.date.fromisoformat(o['dateAdded']),
        due_date=datetime.date.fromisoformat(o['dueDate']),
        required_action=o['requiredAction'],
        known_ransomware_campaign_use=o['knownRansomwareCampaignUse'] == 'Known',
        notes=o['notes']
    )


def _parse_processed_vulnerability(o: dict) -> Vulnerability:
    return Vulnerability(**o)


def filter_vulnerabilities(vulnerabilities: Iterable[Vulnerability], known_ransomware_campaign_use: Optional[bool] = None) -> Vulnerability:
    for v in vulnerabilities:
        if known_ransomware_campaign_use is not None and v.known_ransomware_campaign_use != known_ransomware_campaign_use:
            continue
        yield v


class JSONEncoder(_JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        elif isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        else:
            return super().default(o)


def read_catalog(path: Optional[str] = None, fallback_url: str = KEV_URL) -> Union[dict, Catalog]:
    if not path:
        return download_latest(url=fallback_url)

    try:
        data = read_json_file(path)
    except FileNotFoundError:
        return download_latest(url=fallback_url)
    else:
        data = parse_catalog(data)
        return data
    

def filter_catalog(catalog: Union[dict, Catalog], f: Union[dict, Filter]) -> Union[dict, Catalog]:
    if isinstance(f, dict):
        f = Filter(**f)
    
    if isinstance(catalog, dict):
        catalog = parse_catalog(catalog)

    return catalog.filter(f)


def read_json_file(path: str) -> dict:
    with open(path, 'r') as file:
        return json.load(file)


def str_matches_any(value: str, patterns: Iterable[str], case_sensitive: bool = False) -> bool:
    value = value if case_sensitive else value.lower()
    for pattern in patterns:
        pattern = pattern if case_sensitive else pattern.lower()
        if str_matches(value, pattern, case_sensitive=True):
            return True
    return False


def str_matches(value: str, pattern: str, case_sensitive: bool = False) -> bool:
    if not case_sensitive:
        value = value.lower()
        pattern = pattern.lower()

    if '*' in pattern:
        return fnmatch.fnmatch(value, pattern)
    else:
        return value == pattern


def _cli():
    parser = argparse.ArgumentParser(description='CISA Known Exploited Vulnerabilities (KEV) Catalog')
    parser.add_argument('--cve-id', dest='cve_ids', action='append', help='Show vulnerabilities by CVE ID')
    parser.add_argument('--vendor', dest='vendors', action='append', help='Show vulnerabilities by vendor name')
    parser.add_argument('--product', dest='products', action='append', help='Show vulnerabilities by product name')
    parser.add_argument('--ransomware', action='store_true', default=None, help='Show vulnerabilities related to ransomware campaigns')
    parser.add_argument('--overdue', action='store_true', default=None, help='Show vulnerabilities that are overdue for patching')
    parser.add_argument('--not-overdue', action='store_false', dest='overdue', help='Hide vulnerabilities that are overdue for patching')
    parser.add_argument('--input-file', '-i', help='Input file (JSON)')
    parser.add_argument('--fallback-url', '-u', default=KEV_URL, help='Fallback URL')
    parser.add_argument('--output-file', '-o', help='Output file')
    parser.add_argument('--output-type', '-t', choices=['full', 'cve_ids', 'dates', 'date_added', 'due_date'], default='full', help='Output type (i.e. what to output)')
    parser.add_argument('--output-format', '-f', choices=['json', 'jsonl'], default='json', help='Output format (i.e. how to output)')
    parser.add_argument('--indent', type=int, default=4, help='Indentation level')

    args = vars(parser.parse_args())
    
    input_file = args['input_file']
    fallback_url = args['fallback_url']
    output_file = args['output_file']
    output_type = args['output_type']
    output_format = args['output_format']
    indent = args['indent']

    vulnerability_filter = Filter(
        cve_ids=args['cve_ids'],
        vendors=args['vendors'],
        products=args['products'],
        known_ransomware_campaign_use=args['ransomware'],
        overdue=args['overdue'],
    )
    catalog = read_catalog(path=input_file, fallback_url=fallback_url)
    if vulnerability_filter:
        catalog = catalog.filter(vulnerability_filter)

    if output_format == 'json':
        s = functools.partial(json.dumps, indent=indent, cls=JSONEncoder)
        if output_type == 'full':
            data = catalog
        else:
            if output_type == 'cve_ids':
                data = catalog.cve_ids
            elif output_type == 'date_added':
                data = catalog.dates_added
            elif output_type == 'due_date':
                data = catalog.due_dates
            elif output_type == 'dates':
                data = [{'cve_id': v.cve_id, 'date_added': v.date_added, 'due_date': v.due_date} for v in catalog.vulnerabilities]
            else:
                raise ValueError(f'Invalid output type: {output_type}')
            
        blob = s(data)
        if output_file:
            with open(output_file, 'w') as file:
                file.write(blob)
        else:
            print(blob)

    elif output_format == 'jsonl':
        s = functools.partial(json.dumps, cls=JSONEncoder)

        if output_type == 'full':
            rows = sorted(catalog.vulnerabilities, key=lambda o: o.cve_id)
        else:
            if output_type == 'cve_ids':
                rows = [{'cve_id': cve_id} for cve_id in catalog.cve_ids]
            elif output_type == 'date_added':
                rows = [{'cve_id': cve_id, 'date_added': date_added} for (cve_id, date_added) in catalog.dates_added.items()]
            elif output_type == 'due_date':
                rows = [{'cve_id': cve_id, 'due_dates': due_date} for (cve_id, due_date) in catalog.due_dates.items()]
            elif output_type == 'dates':
                rows = [{'cve_id': v.cve_id, 'date_added': v.date_added, 'due_date': v.due_date} for v in catalog.vulnerabilities]
            else:
                raise ValueError(f'Invalid output type: {output_type}')
        
        if output_file:
            with open(output_file, 'w') as file:
                for row in rows:
                    file.write(s(row) + '\n')
        else:
            for row in rows:
                print(s(row))
    else:
        raise ValueError(f'Invalid output format: {output_format}')


if __name__ == '__main__':
    _cli()
