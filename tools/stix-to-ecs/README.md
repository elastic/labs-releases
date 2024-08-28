<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

# STIX to ECS

Version: `0.3.1`

This project will take a STIX 2.x formatted JSON document and create an ECS version. There are three output options: STDOUT as JSON, an NDJSON file, and/or directly to an Elasticsearch cluster.

## Author
- Cyril Francois ([@cyril-t-f](https://github.com/cyril-t-f))
- RoDerick Hines ([@roderickch01](https://github.com/roderickch01))

## Changelog
### 0.3.1
  - Added additional STIX pattern hash support: `md5` and `sha1`.
  - Enhanced connection methods for exporting to an Elastic cluster:
    - Support for `cloud-id` and `url`.
    - Authentication via `api-key` or `username` and `password`.
  - Added support for insecure connections to an Elastic cluster, allowing certificate verification to be disabled.
  - Various bug fixes and code refactorings.

### 0.2.0
  - Added support for passing a configuration file as a parameter, enabling storage of `cloud-id` and `api-key`.  By doing so, we hope that the script will be easier to integrate into any automation without requiring user input.
  - Various bug fixes and code refactorings.

### 0.1.0
  - Initial release.

## Prerequisites

Python >3.10 and the `stix2`, `elasticsearch`, and `getpass` modules. 

If exporting to Elasticsearch, you will need to know the Elasticsearch host information and authentication credentials. API authentication is not yet implemented.

## Setup

Create a virtual environment and install the required prerequisites.

```bash
python -m venv /path/to/virtual/environments/stix2ecs
source /path/to/virtual/environments/stix2ecs/bin/activate
python -m pip install -r requirements.txt
```

## Operation

The input is a STIX 2.x JSON document (or a folder of JSON documents); the output defaults to STDOUT, with an option to create an NDJSON file and/or send to an Elasticsearch cluster.

```text
usage: .\stix_to_ecs.py [-h] -i INPUT [-o OUTPUT] [-r] [-e] [-p PROVIDER] [-c CONFIGURATION] [--cloud-id CLOUD_ID]
                        [--url URL] [--username USERNAME] [--password PASSWORD] [--index INDEX] [-x]

Convert STIX indicator(s) into ECS indicator(s) - Version 0.3.1

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        STIX input file or directory
  -o OUTPUT, --output OUTPUT
                        ECS output directory
  -r, --recursive       Recursive processing when input is a directory
  -e, --elastic         Use Elastic cloud configuration
  -p PROVIDER, --provider PROVIDER
                        Override ECS provider
  -c CONFIGURATION, --configuration CONFIGURATION
                        Path to the configuration file used to connect to the Elastic cluster, used with --elastic
  --cloud-id CLOUD_ID   The cloud ID of the Elastic cluster, required with --elastic unless configuration file is
                        provided (--configuration), can't be provided along --url
  --url URL             The URL of the Elastic cluster, required with --elastic unless configuration file is provided
                        (--configuration), can't be provided along --cloud-id
  --username USERNAME   The username of the Elastic cluster, required with --elastic unless a configuration file is
                        provided (--configuration)
  --password PASSWORD   The password of the Elastic cluster, required with --elastic unless a configuration file is
                        provided (--configuration)
  --index INDEX         Elastic cluster's index where ECS indicators will be written, required with --elastic unless
                        configuration file is provided (--configuration)
  -x, --insecure        Disable TLS certificate verification when connecting to the Elastic cluster
```


By default, the ECS file is named the same as the STIX file, but with `.ecs.ndjson` appended.

### Examples

There are two sample files located in the `test-inputs/` directory. One is from CISA and one is from OpenCTI.

#### STIX file input to STDOUT

This will output the STIX document to STDOUT in ECS format.

```bash
python stix_to_ecs.py -i test-inputs/cisa_sample_stix.json | jq
[
  {
    "threat": {
      "indicator": {
        "file": {
          "name": "123.ps1",
          "hash": {
            "sha256": "ED5D694D561C97B4D70EFE934936286FE562ADDF7D6836F795B336D9791A5C44"
          }
        },
        "type": "file",
        "description": "Simple indicator of observable {ED5D694D561C97B4D70EFE934936286FE562ADDF7D6836F795B336D9791A5C44}",
        "first_seen": "2023-11-21T18:57:25.000Z",
        "provider": "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01",
        "modified_at": "2023-11-21T18:57:25.000Z",
        "marking": {
          "tlp": "clear"
        }
      }
    }
  },
…
```

#### STIX file input to ECS file output

This will create a folder called `ecs` in the present directory and write the ECS file there.

```bash
python stix_to_ecs.py -i test-inputs/cisa_sample_stix.json -o ecs

cat ecs/cisa_sample_stix.ecs.ndjson | jq
{
  "threat": {
    "indicator": {
      "file": {
        "name": "123.ps1",
        "hash": {
          "sha256": "ED5D694D561C97B4D70EFE934936286FE562ADDF7D6836F795B336D9791A5C44"
        }
      },
      "type": "file",
      "description": "Simple indicator of observable {ED5D694D561C97B4D70EFE934936286FE562ADDF7D6836F795B336D9791A5C44}",
      "first_seen": "2023-11-21T18:57:25.000Z",
      "provider": "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01",
      "modified_at": "2023-11-21T18:57:25.000Z",
      "marking": {
        "tlp": "clear"
      }
    }
  }
}
...
```

#### STIX file input to ECS file output, define the Provider field

The provider field is commonly a GUID in the STIX document. To make it more user-friendly, you can use the `-p` argument to define the `threat.indicator.provider` ECS field.

```bash
python stix_to_ecs.py -i test-inputs/cisa_sample_stix.json -o ecs -p "Elastic Security Labs"

cat ecs/cisa_sample_stix.ecs.ndjson | jq
{
  "threat": {
    "indicator": {
      "file": {
        "name": "123.ps1",
        "hash": {
          "sha256": "ED5D694D561C97B4D70EFE934936286FE562ADDF7D6836F795B336D9791A5C44"
        }
      },
      "type": "file",
      "description": "Simple indicator of observable {ED5D694D561C97B4D70EFE934936286FE562ADDF7D6836F795B336D9791A5C44}",
      "first_seen": "2023-11-21T18:57:25.000Z",
      "provider": "Elastic Security Labs",
      "modified_at": "2023-11-21T18:57:25.000Z",
      "marking": {
        "tlp": "clear"
      }
    }
  }
}
...
```

#### STIX directory input to ECS file outputs

If you have a directory of STIX documents, you can use the `-r` argument to recursively search through the directory and write the ECS documents to the output directory.

```bash
python stix_to_ecs.py -ri test-inputs -o ecs
```

#### STIX file input to Elasticsearch output

To output to Elasticsearch, you can use either Elastic Cloud or a local instance. Local Elasticsearch will use port `9200`, Elastic Cloud will use port `443`. By default, a valid TLS session to Elasticsearch is required.

First, create an index if you don't already have one. In this example, we’re creating an index called `stix2ecs`, but the index name isn’t relevant

```bash
curl -u username -X PUT "https://elasticsearch:port/stix2ecs?pretty"

{
  "acknowledged" : true,
  "shards_acknowledged" : true,
  "index" : "stix2ecs"
}
```

Next, define the Elasticsearch output options.

```bash
python stix_to_ecs.py -i test-inputs/cisa_sample_stix.json -e --cloud-id your-cloud-id --index stix2ecs
```

Or use the configuration file.
```json
// configuration.json
{
    "cloud_id": "your-cloud-id", 
    "url": "",
    "api_key": "your-api-key", 
    "username": "",
    "password": "",
    "index": "stix2ecs"

}
```

```bash
python .\stix_to_ecs.py -i .\test-inputs\cisa_sample_stix.jso -e -c .\configuration.json
```

If you’re storing the data in Elasticsearch for use in another platform, you can view the indicators using cURL.

```bash
curl -u username https://elasticsearch:port/stix2ecs/_search?pretty

{
  "took" : 2,
  "timed_out" : false,
  "_shards" : {
    "total" : 1,
    "successful" : 1,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 3,
      "relation" : "eq"
    },
    "max_score" : 1.0,
    "hits" : [
      {
        "_index" : "stix2ecs",
        "_id" : "n2lt8IwBahlUtp0hzm9i",
        "_score" : 1.0,
        "_source" : {
          "threat" : {
            "indicator" : {
              "file" : {
                "name" : "123.ps1",
                "hash" : {
                  "sha256" : "ED5D694D561C97B4D70EFE934936286FE562ADDF7D6836F795B336D9791A5C44"
                }
              },
              "type" : "file",
              "description" : "Simple indicator of observable {ED5D694D561C97B4D70EFE934936286FE562ADDF7D6836F795B336D9791A5C44}",
              "first_seen" : "2023-11-21T18:57:25.000Z",
              "provider" : "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01",
              "modified_at" : "2023-11-21T18:57:25.000Z",
              "marking" : {
                "tlp" : "clear"
              }
            }
          }
        }
      }
...
```

If you’re using Kibana, you can [create a Data View](https://www.elastic.co/guide/en/kibana/current/data-views.html) for your stix2ecs index to view the ingested indicators.

![image1](https://github.com/elastic/labs-releases/assets/7442091/0a4c1597-4d8d-4ae1-9eb0-f89731304c2f)

Finally, you can use this as an indicator source for [Indicator Match rules](https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-threat-intel-indicator-match.html).

![image2](https://github.com/elastic/labs-releases/assets/7442091/3aa7815a-84a3-4863-ae01-0692ee0b9191)
