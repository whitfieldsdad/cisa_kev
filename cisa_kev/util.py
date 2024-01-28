import dataclasses
import fnmatch
import json
from typing import Any, Iterable, Optional, Union
import datetime
from json import JSONEncoder as _JSONEncoder

import polars as pl
import logging
import os

logger = logging.getLogger(__name__)

TIME = Union[datetime.date, datetime.datetime, str, int, float]

# File formats
CSV = 'csv'
JSON = 'json'
JSONL = 'jsonl'
PARQUET = 'parquet'

FILE_FORMATS = [CSV, JSON, JSONL, PARQUET]
DEFAULT_FILE_FORMAT = PARQUET


class JSONEncoder(_JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        elif isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        else:
            return super().default(o)


def to_json(o: Any) -> str:
    return json.dumps(o, cls=JSONEncoder)


def read_json_file(path: str) -> dict:
    with open(path, 'r') as file:
        return json.load(file)
    

def write_json_file(data: Any, path: str):
    with open(path, 'w') as fp:
        json.dump(data, fp=fp, cls=JSONEncoder)


def write_jsonl_file(rows: Iterable[Any], path: str):
    with open(path, 'w') as fp:
        for row in rows:
            line = to_json(row)
            fp.write(line + os.linesep)


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


def read_dataframe(path: str, file_format: Optional[str] = None) -> pl.DataFrame:
    if not file_format:
        file_format = get_file_format_from_path(path)

    logger.debug(f'Reading {path}')
    if file_format in [CSV]:
        df = pl.read_csv(path)
    elif file_format in [JSON]:
        df = pl.read_json(path)
    elif file_format in [JSONL]:
        df = pl.read_ndjson(path)
    elif file_format in [PARQUET]:
        df = pl.read_parquet(path)
    else:
        raise ValueError(f"Unsupported file format: {file_format}")

    logger.debug('Read %d x %d dataframe from %s (columns: %s)', len(df), len(df.columns), path, tuple(df.columns))
    return df


def write_dataframe(df: pl.DataFrame, path: str, file_format: Optional[str] = None):
    path = realpath(path)
    if not file_format:
        file_format = get_file_format_from_path(path)

    logger.debug('Writing %d x %d dataframe to %s (columns: %s)', len(df), len(df.columns), path, tuple(df.columns))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if file_format in [CSV]:
        df.write_csv(path)

    elif file_format in [JSON]:
        df.write_json(path, row_oriented=True)
    elif file_format in [JSONL]:
        df.write_ndjson(path)
    elif file_format in [PARQUET]:
        df.write_parquet(path)
    else:
        raise ValueError(f"Unsupported output format: {file_format}")
    
    logger.debug('Wrote dataframe to %s', path)


def get_file_format_from_path(path: str) -> str:
    for output_format in sorted(FILE_FORMATS, key=len, reverse=True):
        ext = f'.{output_format}'
        if path.endswith(ext):
            return output_format
    raise ValueError(f"Could not determine output format from path: {path}")


def realpath(path: str) -> str:
    for f in [os.path.expandvars, os.path.expanduser, os.path.realpath]:
        path = f(path)
    return path


def parse_date(d: Optional[TIME]) -> Optional[datetime.date]:
    if d is not None:
        if isinstance(d, datetime.datetime):
            return d.date()
        elif isinstance(d, datetime.date):
            return d
        elif isinstance(d, str):
            return datetime.datetime.strptime(d, "%Y-%m-%d").date()
        elif isinstance(d, (int, float)):
            return datetime.datetime.fromtimestamp(d).date()
        else:
            raise ValueError(f"Unsupported data format: {d}")


def parse_datetime(t: Optional[TIME]) -> datetime.datetime:
    if t is not None:
        if isinstance(t, datetime.datetime):
            return t
        elif isinstance(t, datetime.date):
            return datetime.datetime.combine(t, datetime.time())
        elif isinstance(t, str):
            return datetime.datetime.fromisoformat(t)
        elif isinstance(t, (int, float)):
            return datetime.datetime.fromtimestamp(t)
        else:
            raise ValueError(f"Unsupported data format: {t}")
