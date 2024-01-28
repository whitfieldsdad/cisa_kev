# CISA Known Exploited Vulnerabilities (KEV) Catalog client

A wildly opinionated Python 3 client for the [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Features

- Automatically download the latest version of the CISA KEV catalog;
- Query the catalog using dataclasses, Pandas, or Polars;
- Query the catalog from the command line and return the results in JSON, JSONL, CSV, or Parquet format; and
- Optionally disable the use of TLS certificate verification (i.e. for users operating within a network where TLS MitM is being performed, and [cisa.gov](https://cisa.gov) has not been allowlisted)

> ℹ️ The CISA KEV catalog will be downloaded to a file named `f70af4e5-602d-4b6f-a6cd-01be603ae2bb/known_exploited_vulnerabilities.json` in the system's temporary directory by default

> ℹ️ The download location can be customized through both the library and command line

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

- [Command line](#command-line)

### Command line

The following commands are equivalent:

```bash
poetry run cisa_kev
poetry run kev
poetry run tool
python3 cisa_kev/cli.py
```

#### Getting help from the command line

To view the usage guide:

```bash
poetry run cisa_kev --help
```

```text
Usage: cisa_kev [OPTIONS] COMMAND [ARGS]...

  CISA Known Exploited Vulnerabilities (KEV) Catalog

Options:
  --download-path TEXT            [default: /var/folders/ps/c0fn47n54sg08wck9_
                                  x9qncr0000gp/T/f70af4e5-602d-4b6f-a6cd-01be6
                                  03ae2bb/known_exploited_vulnerabilities.json
                                  ]
  --download-url TEXT             [default: https://www.cisa.gov/sites/default
                                  /files/feeds/known_exploited_vulnerabilities
                                  .json]
  --verify-tls / --no-verify-tls  [default: verify-tls]
  --help                          Show this message and exit.

Commands:
  download  Download the latest version of the catalog.
  query     Query the catalog.
```

#### Downloading the CISA KEV catalog from the command line

To download the latest version of the CISA KEV catalog:

```bash
poetry run cisa_kev download
```

```text
INFO:cisa_kev.client:Writing https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json to /var/folders/ps/c0fn47n54sg08wck9_x9qncr0000gp/T/f70af4e5-602d-4b6f-a6cd-01be603ae2bb/known_exploited_vulnerabilities.json
```

To disable TLS certificate validation:

```bash
poetry run cisa_kev --no-verify-tls download
```

To customize where the catalog will be downloaded to:

```bash
poetry run cisa_kev --download-path data/known_exploited_vulnerabilities.json download
```

> ℹ️ The output directory will be automatically created if it does not already exist.

#### Querying the CISA KEV catalog from the command line

The following options are available when querying the catalog via the command line:

```bash
poetry run cisa_kev query --help
```

```text
Usage: cisa_kev query [OPTIONS]

  Query the catalog.

Options:
  --cve-id TEXT
  --vendor TEXT
  --product TEXT
  --ransomware-related / --not-ransomware-related
  --overdue / --not-overdue
  --min-date-added PARSE_DATE
  --max-date-added PARSE_DATE
  --min-due-date PARSE_DATE
  --max-due-date PARSE_DATE
  -o, --output-file TEXT
  --output-format [csv|json|jsonl|parquet]
                                  [default: json]
  --help                          Show this message and exit.
```

To search for vulnerabilities known to be used in ransomware campaigns in the wild:

```bash
poetry run cisa_kev query --ransomware-related --output-format=jsonl | jq
```

```json
...
{
  "cve_id": "CVE-2023-34362",
  "vendor": "Progress",
  "product": "MOVEit Transfer",
  "name": "Progress MOVEit Transfer SQL Injection Vulnerability",
  "description": "Progress MOVEit Transfer contains a SQL injection vulnerability that could allow an unauthenticated attacker to gain unauthorized access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database in addition to executing SQL statements that alter or delete database elements.",
  "date_added": "2023-06-02",
  "due_date": "2023-06-23",
  "required_action": "Apply updates per vendor instructions.",
  "known_ransomware_campaign_use": true,
  "notes": "This CVE has a CISA AA located here: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a. Please see the AA for associated IOCs. Additional information is available at: https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023."
}
...
```

To search for vulnerabilities by CVE ID:

```bash
poetry run kev query --cve-id=CVE-2023-34362 --cve-id=CVE-2014-0160 --output-format=jsonl | jq
```

```json
{
  "cve_id": "CVE-2014-0160",
  "vendor": "OpenSSL",
  "product": "OpenSSL",
  "name": "OpenSSL Information Disclosure Vulnerability",
  "description": "The TLS and DTLS implementations in OpenSSL do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information.",
  "date_added": "2022-05-04",
  "due_date": "2022-05-25",
  "required_action": "Apply updates per vendor instructions.",
  "known_ransomware_campaign_use": false,
  "notes": ""
}
{
  "cve_id": "CVE-2023-34362",
  "vendor": "Progress",
  "product": "MOVEit Transfer",
  "name": "Progress MOVEit Transfer SQL Injection Vulnerability",
  "description": "Progress MOVEit Transfer contains a SQL injection vulnerability that could allow an unauthenticated attacker to gain unauthorized access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database in addition to executing SQL statements that alter or delete database elements.",
  "date_added": "2023-06-02",
  "due_date": "2023-06-23",
  "required_action": "Apply updates per vendor instructions.",
  "known_ransomware_campaign_use": true,
  "notes": "This CVE has a CISA AA located here: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a. Please see the AA for associated IOCs. Additional information is available at: https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023."
}
```

To search for vulnerabilities by vendor:

```bash
poetry run cisa_kev query --vendor=microsoft --output-format=jsonl | jq -c
```

```json
...
{"cve_id":"CVE-2023-36036","vendor":"Microsoft","product":"Windows","name":"Microsoft Windows Cloud Files Mini Filter Driver Privilege Escalation Vulnerability","description":"Microsoft Windows Cloud Files Mini Filter Driver contains a privilege escalation vulnerability that could allow an attacker to gain SYSTEM privileges.","date_added":"2023-11-14","due_date":"2023-12-05","required_action":"Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.","known_ransomware_campaign_use":false,"notes":"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-36036"}
{"cve_id":"CVE-2023-36584","vendor":"Microsoft","product":"Windows","name":"Microsoft Windows Mark of the Web (MOTW) Security Feature Bypass Vulnerability","description":"Microsoft Windows Mark of the Web (MOTW) contains a security feature bypass vulnerability resulting in a limited loss of integrity and availability of security features.","date_added":"2023-11-16","due_date":"2023-12-07","required_action":"Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.","known_ransomware_campaign_use":false,"notes":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36584"}
{"cve_id":"CVE-2023-29357","vendor":"Microsoft","product":"SharePoint Server","name":"Microsoft SharePoint Server Privilege Escalation Vulnerability","description":"Microsoft SharePoint Server contains an unspecified vulnerability that allows an unauthenticated attacker, who has gained access to spoofed JWT authentication tokens, to use them for executing a network attack. This attack bypasses authentication, enabling the attacker to gain administrator privileges.","date_added":"2024-01-10","due_date":"2024-01-31","required_action":"Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.","known_ransomware_campaign_use":false,"notes":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357"}
...
```

To search for vulnerabilities by vendor and list only CVE IDs you could use `jq`:

```bash
poetry run kev query --vendor=microsoft --output-format=jsonl | jq -r '.cve_id' > example-cve-ids.txt
```

To search for vulnerabilities by CVE ID using a line-delimited file of CVE IDs:

```bash
poetry run kev query --cve-id-file example-cve-ids.txt --ransomware-related --output-format=jsonl | jq -r '.cve_id' | sort
```

```text
CVE-2013-0074
CVE-2013-2551
CVE-2015-1701
...
CVE-2023-24880
CVE-2023-28252
CVE-2023-36884
```
