# CISA Known Exploited Vulnerabilities (KEV) Catalog client

A dependency-free Python 3 client for the [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Features

- A simple command line interface that can be used to query a [local](data/known_exploited_vulnerabilities.json) or [remote](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) copy of the KEV catalog in JSON format

## Usage

### Command line interface

The command line interface only has a single command and allows you to query a local or remote copy of the KEV catalog (i.e. using a local file or a URL).

```bash
python3 cisa_kev/kev.py --help
```

```text
usage: kev.py [-h] [--raw] [--input-file INPUT_FILE] [--fallback-url FALLBACK_URL] [--output-file OUTPUT_FILE]
              [--output-type {full,cve_ids,dates,date_added,due_date}] [--output-format {json,jsonl}] [--indent INDENT]

CISA Known Exploited Vulnerabilities (KEV) Catalog

options:
  -h, --help            show this help message and exit
  --raw                 Don't parse the catalog
  --input-file INPUT_FILE, -i INPUT_FILE
                        Input file (JSON)
  --fallback-url FALLBACK_URL, -u FALLBACK_URL
                        Fallback URL
  --output-file OUTPUT_FILE, -o OUTPUT_FILE
                        Output file
  --output-type {full,cve_ids,dates,date_added,due_date}, -t {full,cve_ids,dates,date_added,due_date}
                        Output type (i.e. what to output)
  --output-format {json,jsonl}, -f {json,jsonl}
                        Output format (i.e. how to output)
  --indent INDENT       Indentation level
```

Throughout this guide, the following commands are equivalent:

```bash
python3 cisa_kev/kev.py
```

```bash
python3 -m cisa_kev
```

```bash
poetry run kev
```

```bash
curl https://raw.githubusercontent.com/whitfieldsdad/cisa_kev/main/cisa_kev/kev.py -s | python3 -
```

```bash
wget -qO- https://raw.githubusercontent.com/whitfieldsdad/cisa_kev/main/cisa_kev/kev.py | python3 -
```

```bash
powershell -command "& { Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/whitfieldsdad/cisa_kev/main/cisa_kev/kev.py' -UseBasicParsing | Invoke-Expression }"
```

#### Downloading the catalog

The catalog is available in [CSV](https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv) or [JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) format, but at this time, only the [JSON format](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json) is supported by this client.

The following command will download the catalog in JSON format, parse it, and save it to a local file:

```bash
python3 cisa_kev/kev.py -o data/known_exploited_vulnerabilities.json
```

To keep the file in its original format, use the `--raw` option:

```bash
python3 cisa_kev/kev.py --raw -o data/known_exploited_vulnerabilities.json
```

Or, you could simply use `curl`:

```bash
curl https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o data/known_exploited_vulnerabilities.json
```

Or, `wget`:

```bash
wget -qO- https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -O data/known_exploited_vulnerabilities.json
```
