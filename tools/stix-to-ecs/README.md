<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

# STIX 2 ECS

Version: `0.2.0`

This project will take a STIX 2.x formatted JSON document and create an ECS version. There are three output options: STDOUT as JSON, an NDJSON file, and/or directly to an Elasticsearch cluster.

## Author
Cyril Francois (@cyril-t-f)

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

```bash
usage: .\stix_to_ecs.py [-h] -i INPUT [-o OUTPUT] [-e] [--index INDEX] [--url URL] [--user USER] [-p PROVIDER] [-r] [-c CONFIGURATION]
```

By default, the ECS file is named the same as the STIX file, but with `.ecs.ndjson` appended.

### Options

The script has several options, the only mandatory options are `-i` for the input and `-o` for the output directory.

| Option              | Description                                                                                                            |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| -h, --help          | displays the help menu                                                                                                 |
| -i, --input         | specifies the input STIX document (mandatory)                                                                          |
| -o, --output        | specifies the output ECS document (mandatory)                                                                          |
| -p, --provider      | defines the ECS provider field (optional)                                                                              |
| -r, --recursive     | recursive mode to convert multiple STIX documents (optional)                                                           |
| -e, --elastic       | specifies the Elasticsearch output mode (optional)                                                                     |
| -c, --configuration | specifies the Json configuration file with the required information to connect to the Elastic cluster `-e` (optionnal) |
| --cloud-id          | defines the Elasticsearch cloud-id, requires `-e` (optional)                                                           |
| --index             | defines the Elasticsearch index, requires `-e` (optional)                                                              |

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
    "api_key": "your-api-key", 
    "index": "stix2ecs"
}
```

```bash
python .\stix_to_ecs.py -i .\test-inputs\cisa_sample_stix.jso -e -c .\configuration.jsonn
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
