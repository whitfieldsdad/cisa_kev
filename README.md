# CISA Known Exploited Vulnerabilities (KEV) Catalog client

A dependency-free Python 3 client for the [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Features

- [Download the latest copy of the catalog](#downloading-the-catalog) in [JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) [format](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json) or work with a [local copy](data/known_exploited_vulnerabilities.json)
- [Query the catalog via the command line](#query-the-catalog-via-the-command-line)

## Installation

To install using `pip`:

```bash
python3 -m pip install cisa_kev
```

To add to a [Poetry](https://python-poetry.org/) project:

```bash
poetry add cisa_kev
```

To install from source:

```bash
poetry install
```

## Usage

### Command line interface

The command line interface only has a single command and allows you to query a local or remote copy of the catalog (i.e. using a local file or a URL).

```bash
python3 -m cisa_kev --help
```

```text
usage: kev.py [-h] [--vendor VENDOR] [--product PRODUCT] [--ransomware] [--overdue] [--not-overdue]
              [--input-file INPUT_FILE] [--fallback-url FALLBACK_URL] [--output-file OUTPUT_FILE]
              [--output-type {full,cve_ids,dates,date_added,due_date}] [--output-format {json,jsonl}] [--indent INDENT]

CISA Known Exploited Vulnerabilities (KEV) Catalog

options:
  -h, --help            show this help message and exit
  --vendor VENDOR       Show vulnerabilities by vendor name
  --product PRODUCT     Show vulnerabilities by product name
  --ransomware          Show vulnerabilities related to ransomware campaigns
  --overdue             Show vulnerabilities that are overdue for patching
  --not-overdue         Hide vulnerabilities that are overdue for patching
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

> ℹ️ Glob patterns are supported and all pattern matching is performed case insensitively (i.e. you could use `--vendor microsoft` or `--vendor Microsoft` interchangeably).

#### Downloading the catalog

The catalog is available in [CSV](https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv) or [JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) format, but at this time, only the [JSON format](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json) is supported by this client.

The following command will download the catalog in JSON format, transform it, and save it to a local file:

```bash
python3 cisa_kev/kev.py -o data/known_exploited_vulnerabilities.json
```

The structure of the file will be as follows:

```json
{
  "version": "2024.01.08",
  "time_released": "2024-01-08T15:01:52.959100+00:00",
  "vulnerabilities": [
    {
      "cve_id": "CVE-2021-34527",
      "vendor": "Microsoft",
      "product": "Windows",
      "name": "Microsoft Windows Print Spooler Remote Code Execution Vulnerability",
      "description": "Microsoft Windows Print Spooler contains an unspecified vulnerability due to the Windows Print Spooler service improperly performing privileged file operations. Successful exploitation allows an attacker to perform remote code execution with SYSTEM privileges. The vulnerability is also known under the moniker of PrintNightmare.",
      "date_added": "2021-11-03",
      "due_date": "2021-07-20",
      "required_action": "Apply updates per vendor instructions.",
      "known_ransomware_campaign_use": true,
      "notes": "Reference CISA's ED 21-04 (https://www.cisa.gov/emergency-directive-21-04) for further guidance and requirements."
    },
    ...
  ]
}
```

To download the catalog without modifying it you could use `curl`:

```bash
curl https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o data/known_exploited_vulnerabilities.json
```

Or, `wget`:

```bash
wget -qO- https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -O data/known_exploited_vulnerabilities.json
```

The structure of the catalog will be as follows and is described in a [JSON schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json) maintained by CISA.

```json
{
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2024.01.08",
    "dateReleased": "2024-01-08T15:01:52.9591Z",
    "count": 1061,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-34527",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "vulnerabilityName": "Microsoft Windows Print Spooler Remote Code Execution Vulnerability",
            "dateAdded": "2021-11-03",
            "shortDescription": "Microsoft Windows Print Spooler contains an unspecified vulnerability due to the Windows Print Spooler service improperly performing privileged file operations. Successful exploitation allows an attacker to perform remote code execution with SYSTEM privileges. The vulnerability is also known under the moniker of PrintNightmare.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-07-20",
            "knownRansomwareCampaignUse": "Known",
            "notes": "Reference CISA's ED 21-04 (https:\/\/www.cisa.gov\/emergency-directive-21-04) for further guidance and requirements."
        },
        ...
    ]
}
```

#### Query the catalog via the command line

To search for vulnerabilities by vendor name, use the `--vendor` option:

```bash
python3 cisa_kev/kev.py -i data/known_exploited_vulnerabilities.json --vendor microsoft --output-format=jsonl | jq -r '.cve_id'
```

```text
...
CVE-2023-36884
CVE-2023-38180
CVE-2023-41763
```

To search for vulnerabilities by product name, use the `--product` option:

```bash
python3 cisa_kev/kev.py -i data/known_exploited_vulnerabilities.json --vendor apache --product 'log4j*' --output-format=jsonl | jq -r '.cve_id'
```

```text
...
CVE-2021-44228
CVE-2021-45046
```

To search for vulnerabilities related to ransomware campaigns, use the `--ransomware` option:

```bash
python3 cisa_kev/kev.py -i data/known_exploited_vulnerabilities.json --ransomware --output-format=jsonl | jq -r '.cve_id'
```

```text
...
CVE-2023-42793
CVE-2023-46604
CVE-2023-4966
```

To search for vulnerabilities that are overdue for patching, use the `--overdue` option:

```bash
python3 cisa_kev/kev.py -i data/known_exploited_vulnerabilities.json --overdue --output-format=jsonl | jq -r '.cve_id'
```

```text
CVE-2023-5631
CVE-2023-6345
CVE-2023-6448
...
```

To see when the vulnerabilities are due, you can either list the entire entries:

```bash
python3 cisa_kev/kev.py -i data/known_exploited_vulnerabilities.json --overdue --output-format=jsonl | jq
```

```json
...
{
  "cve_id": "CVE-2023-32049",
  "vendor": "Microsoft",
  "product": "Windows",
  "name": "Microsoft Windows Defender SmartScreen Security Feature Bypass Vulnerability",
  "description": "Microsoft Windows Defender SmartScreen contains a security feature bypass vulnerability that allows an attacker to bypass the Open File - Security Warning prompt.",
  "date_added": "2023-07-11",
  "due_date": "2023-08-01",
  "required_action": "Apply updates per vendor instructions or discontinue use of the product if updates are unavailable.",
  "known_ransomware_campaign_use": false,
  "notes": "https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-32049"
}
...
```

Or, just the dates:

```bash
python3 cisa_kev/kev.py -i data/known_exploited_vulnerabilities.json --overdue --output-format=jsonl --output-type dates | jq -c
```

```json
...
{"cve_id":"CVE-2023-41266","date_added":"2023-12-07","due_date":"2023-12-28"}
{"cve_id":"CVE-2023-41265","date_added":"2023-12-07","due_date":"2023-12-28"}
{"cve_id":"CVE-2023-6448","date_added":"2023-12-11","due_date":"2023-12-18"}
```

To lookup a specific vulnerability, use the `--cve-id` option:

```bash
python3 cisa_kev/kev.py -i data/known_exploited_vulnerabilities.json --cve-id CVE-2020-0796 --output-format=jsonl --output-ty
pe dates | jq -c
```

```json
{"cve_id":"CVE-2020-0796","date_added":"2022-02-10","due_date":"2022-08-10"}
```
