from dataclasses import dataclass
import dataclasses
import datetime
from cisa_kev import util
import json
from typing import Dict, Iterable, List, Optional, Union
import requests
import tempfile
import logging
import os
import polars as pl
import pandas as pd

logger = logging.getLogger(__name__)


# Used to create a unique cache location if a cache location is not explicitly provided.
PRODUCT_UUID = 'f70af4e5-602d-4b6f-a6cd-01be603ae2bb'

DOWNLOAD_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
DOWNLOAD_PATH = os.path.join(tempfile.gettempdir(), PRODUCT_UUID, f'known_exploited_vulnerabilities.json')

# JSON indent used when downloading and printing JSON objects.
JSON_INDENT = 4


@dataclass()
class Vulnerability:
    """
    A vulnerability from the CISA Known Exploited Vulnerabilities (KEV) catalog.
    """
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

    def is_overdue(self) -> bool:
        return (datetime.datetime.now() - self.due_date).total_seconds() < 0
    
    def is_related_to_ransomware(self) -> bool:
        return self.known_ransomware_campaign_use


@dataclass()
class Query:
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

        if self.cve_ids and not util.str_matches_any(vulnerability.cve_id, self.cve_ids):
            return False
        
        if self.vendors and not util.str_matches_any(vulnerability.vendor, self.vendors):
            return False
        
        if self.products and not util.str_matches_any(vulnerability.product, self.products):
            return False
        
        if self.min_date_added and vulnerability.date_added < self.min_date_added:
            return False
        
        if self.max_date_added and vulnerability.date_added > self.max_date_added:
            return False
        
        if self.min_due_date and vulnerability.due_date < self.min_due_date:
            return False
        
        if self.max_due_date and vulnerability.due_date > self.max_due_date:
            return False
        
        if self.overdue is not None and vulnerability.is_overdue() != self.overdue:
            return False

        return True


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
        return datetime.datetime.now(datetime.timezone.utc) - self.time_released

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

    def __len__(self) -> int:
        return self.total
    
    def __iter__(self) -> Vulnerability:
        yield from self.vulnerabilities

    def filter(self, f: Union[dict, Query]) -> "Catalog":
        if isinstance(f, dict):
            f = Query(**f)

        vulnerabilities = filter(f.matches, self.vulnerabilities)
        return Catalog(
            version=self.version,
            time_released=self.time_released,
            vulnerabilities=list(vulnerabilities)
        )


@dataclass()
class Client:
    path: str = DOWNLOAD_PATH
    url: str = DOWNLOAD_URL
    auto_update: bool = True
    verify_tls: bool = True

    def get_catalog(self, query: Optional[Query] = None) -> Catalog:
        catalog = self._get_catalog()
        if query:
            catalog = catalog.filter(query)
        return catalog
    
    def get_catalog_as_polars_dataframe(self, query: Optional[Query] = None) -> pl.DataFrame:
        o = [dataclasses.asdict(v) for v in self.get_catalog(query)]
        df = pl.DataFrame(o)
        return df
    
    def get_catalog_as_pandas_dataframe(self, query: Optional[Query] = None) -> pd.DataFrame:
        o = [dataclasses.asdict(v) for v in self.get_catalog(query)]
        df = pd.DataFrame(o)
        return df

    def _get_catalog(self) -> Catalog:
        if self.auto_update:
            self.download_catalog()

        with open(self.path, 'rb') as fp:
            o = json.load(fp=fp)
            return parse_catalog(o)

    def download_catalog(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

        with requests.get(self.url, verify=self.verify_tls) as response:
            with open(self.path, 'w') as fp:
                logger.info('Writing %s to %s', self.url, self.path)
                json.dump(response.json(), fp=fp, indent=JSON_INDENT, sort_keys=True)


def parse_catalog(o: dict) -> Catalog:
    vulnerabilities = [parse_vulnerability(v) for v in o['vulnerabilities']]
    return Catalog(
        version=o['catalogVersion'],
        time_released=datetime.datetime.fromisoformat(o['dateReleased']),
        vulnerabilities=vulnerabilities
    )


def parse_vulnerability(o: dict) -> Vulnerability:
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
