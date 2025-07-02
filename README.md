# Abuse.ch IOC Hunting

## Description

Originally available only via the WebUI at [hunting.abuse.ch](https://hunting.abuse.ch/) (see the [blog](https://abuse.ch/blog/introducing-abuse-ch-hunting-platform/)), Abuse.ch Hunting enables analysts to hunt across multiple threat intelligence feeds from a single interface. 

Since it is currently only available as a WebUI and no useful API endpoints exist, this script is intended to replicate similar functions of the WebUI and additionally enable bulk processing  and custom automation.

In the background, the tool queries the API endpoints of the individual Abuse.ch platforms automatically and IOC-dependently and aggregates the threat intelligence in a machine-readable and standardized way. Results are consolidated into a single JSON report.

It supports:
- File hashes (MD5, SHA256) via MalwareBazaar and Yaraify
- URLs, domains, and IPv4 addresses via URLhaus and ThreatFox


## Notes and Requirements

> [!WARNING]
> Abuse.ch Terms of Use - These should be followed and taken into account during use
> * "[...] Your Query volume per each abuse.ch platform must not exceed volumes reasonably expected in circumstances of not-for-profit related usage [...]"
> * "Use of the abuse.ch platforms by companies, organizations, individuals and networks with requirements likely to breach or exceed the fair use principles set out above, may require a paid subscription service via Spamhaus, which is designed for users with commercial / for-profit requirements."

- **Python 3.6+** is required
- **Dependencies**:
  - Standard library: `argparse`, `logging`, `re`, `json`, `os`, `sys`
  - Third party: `requests`
- **Abuse.ch Auth-Key** is required - register or log in at [auth.abuse.ch](https://auth.abuse.ch/) to obtain one

## Use Cases
Detection Engineers and/or Threat Hunters can benefit from the threat intelligence context provided by the tool.
It can support you in the creation of SIEM, Sigma, IDS/IPS, EDR or YARA signatures and queries:
- Validate if an IOC is already known and flagged as a false positive
- Cluster malware samples and other IOCs, extract patterns for rulecreation
- Contextualize suspicious indicators to form, validate or disprove hypotheses
- Pivot across related IOCs
- and more ...

## Functionality

1. **IOC Detection**: Identifies IOC type (IPv4, domain, URL, MD5, SHA256) via strict regex patterns
2. **Defanging**: Replaces dots with `[.]` in log messages to prevent accidental triggering
3. **Platform Queries**:
   - **URLhaus**: `https://urlhaus-api.abuse.ch/v1/`Used for all types of IOC
   - **ThreatFox**: `https://threatfox-api.abuse.ch/api/v1/`Used for all types of IOC
   - **MalwareBazaar**: `https://mb-api.abuse.ch/api/v1/` Used for SHA256 and MD5 Hashes
   - **Yaraify**: `https://yaraify-api.abuse.ch/api/v1/`Used for SHA256 and MD5 Hashes
4. **Aggregation**: Combines platform responses into a unified JSON structure per IOC

## Usage

Obtain an API token by registering or logging in at [hunting.abuse.ch](https://hunting.abuse.ch/), then generate and copy your key.

The IOC Bulk-file should be placed in the script directory.

> [!NOTE]
> To prevent the token from appearing in the command history, the option to pass it via env var is available

```shell
# Provide API Token via env variable 
set ABUSE_CH_API_TOKEN=YOUR_API_TOKEN or 
export ABUSE_CH_API_TOKEN=YOUR_API_TOKEN
python abusech_hunting.py -f iocs.txt

# Or provide token via parameter
python abusech_hunting.py -f iocs.txt -t YOUR_API_TOKEN

# Single IOC with custom result file
python abusech_hunting.py -i example.com -o report.json
```

**Options**:

- `-f, --file` : Path to a text file containing one IOC per line, mutually exclusive with `-i`
- `-i, --ioc`  : Process a single IOC specified on the command line, mutually exclusive `-f`
- `-t, --token`: Abuse.ch API token (can be provided via `ABUSE_CH_API_TOKEN` environment variable or this parameter)
- `-o, --output`: Destination path for the JSON report (default: `abusech_intel.json`)

## abusech_intel.log

All operational details and errors are logged to `abusech_intel.log` in the script directory. Each entry includes:

- **Timestamp** (`DD.MM.YYYY HH:MM:SS`)
- **Log level** (INFO, WARNING, ERROR)
- **Message** (defanged IOC and action details)


## abusech_intel.json

This file is written to the script directory and contains a structured json representation of the aggregated cross-platform results. \
These results can be viewed manually or fed into other tools such as MISP or SIEM/SOAR. \
This is not the STIX format but a custom JSON aggregation of the API responses
