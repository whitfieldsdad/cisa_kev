import dataclasses
import datetime
import io
import itertools
import json
import sys
from typing import Iterable, Optional, Set
import click
import polars as pl
from cisa_kev.client import DOWNLOAD_PATH, DOWNLOAD_URL, JSON_INDENT, Catalog, Client, Query
from cisa_kev.util import CSV, FILE_FORMATS, JSON, JSONL, PARQUET, JSONEncoder
from cisa_kev import util
import logging
import requests.packages
from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger(__name__)


@click.group()
@click.option('--download-path', default=DOWNLOAD_PATH, show_default=True)
@click.option('--download-url', default=DOWNLOAD_URL, show_default=True)
@click.option('--verify-tls/--no-verify-tls', default=True, show_default=True)
@click.pass_context
def main(ctx: click.Context, download_path: str, download_url: str, verify_tls: bool):
    """
    CISA Known Exploited Vulnerabilities (KEV) Catalog
    """
    ctx.obj = Client(
        path=download_path,
        url=download_url,
        verify_tls=verify_tls,
    )
    logging.basicConfig(level=logging.INFO)
    if not verify_tls:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


@main.command()
@click.pass_context
def download(ctx: click.Context):
    """
    Download the latest version of the catalog.
    """
    client: Client = ctx.obj
    client.download_catalog()


@main.command()
@click.option('--cve-id', 'cve_ids', multiple=True)
@click.option('--cve-id-file', 'cve_id_files', multiple=True)
@click.option('--vendor', 'vendors', multiple=True)
@click.option('--product', 'products', multiple=True)
@click.option('--ransomware-related/--not-ransomware-related', 'known_ransomware_campaign_use', default=None, show_default=True)
@click.option('--overdue/--not-overdue', default=None, show_default=True)
@click.option('--min-date-added', type=util.parse_date)
@click.option('--max-date-added', type=util.parse_date)
@click.option('--min-due-date', type=util.parse_date)
@click.option('--max-due-date', type=util.parse_date)
@click.option('--output-file', '-o')
@click.option('--output-format', type=click.Choice(FILE_FORMATS), default=JSON, show_default=True)
@click.pass_context
def query(
    ctx: click.Context,
    cve_ids: Iterable[str], 
    cve_id_files: Iterable[str],
    vendors: Iterable[str],
    products: Iterable[str],
    known_ransomware_campaign_use: Optional[bool],
    overdue: Optional[bool],
    min_date_added: Optional[datetime.date],
    max_date_added: Optional[datetime.date],
    min_due_date: Optional[datetime.date],
    max_due_date: Optional[datetime.date],
    output_file: Optional[str],
    output_format: Optional[str]):
    """
    Query the catalog.
    """
    client: Client = ctx.obj

    if cve_ids:
        cve_ids = set(cve_ids)
    else:
        cve_ids = set(itertools.chain.from_iterable([read_cve_id_file(f) for f in cve_id_files]))

    query = Query(
        cve_ids=cve_ids,
        vendors=vendors,
        products=products,
        known_ransomware_campaign_use=known_ransomware_campaign_use,
        overdue=overdue,
        min_date_added=min_date_added,
        max_date_added=max_date_added,
        min_due_date=min_due_date,
        max_due_date=max_due_date,
    )
    catalog = client.get_catalog(query=query)
    write_catalog(catalog=catalog, output_file=output_file, output_format=output_format)


def read_cve_id_file(path: str) -> Set[str]:
    with open(path) as file:
        return set(filter(bool, map(str.strip, file.readlines())))


def write_catalog(catalog: Catalog, output_file: Optional[str], output_format: str):
    if output_file is None:
        file = io.BytesIO()
    else:
        file = open(output_file, 'wb')
    
    if output_file:
        output_format = util.get_file_format_from_path(output_file)

    if output_format == JSON:
        blob = json.dumps(catalog, cls=JSONEncoder, indent=JSON_INDENT, sort_keys=True)
        file.write(blob.encode('utf-8'))

    elif output_format in [CSV, JSONL, PARQUET]:
        rows = [dataclasses.asdict(v) for v in catalog.vulnerabilities]
        df = pl.DataFrame(rows, nan_to_null=True)
        
        if output_format == CSV:
            df.write_csv(file)
        elif output_format == JSONL:
            df.write_ndjson(file)
        elif output_format == PARQUET:
            df.write_parquet(file)
        
    else:
        raise ValueError(f"Unhandled output format: {output_format}")

    if isinstance(file, io.BytesIO):
        file.seek(0)
        sys.stdout.buffer.write(file.read())


if __name__ == "__main__":
    main()
