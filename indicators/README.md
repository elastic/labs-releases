<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## Elastic Security Labs - threat research indicators

This directory contains configuration extractor tools that can be used to collect atomic indicators from malware binaries, organized by family.

In each directory, you'll find all the components needed to run the configuration extractors.

| Component | Description |
| ------ | ----------- |
| `README.md` | Brief description of the research |
| `ecs-indicators.ndjson` | An ECS-formatted NDJSON file from the research |
| `stix-bundle.json` | A STIX-formatted JSON file from the research |

Depending on the observables source research, these fields may be present:

| Field                                                                                                                                | Description                                                                    |
|--------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| [`threat.indicator.file.hash.md5`](https://www.elastic.co/guide/en/ecs/current/ecs-hash.html#field-hash-md5)                         | MD5 hash of a file observable                                                  |
| [`threat.indicator.file.hash.sha1`](https://www.elastic.co/guide/en/ecs/current/ecs-hash.html#field-hash-sha1)                       | SHA1 hash of a file observable                                                 |
| [`threat.indicator.file.hash.sha256`](https://www.elastic.co/guide/en/ecs/current/ecs-hash.html#field-hash-sha256)                   | SHA256 hash of a file observable                                               |
| [`threat.indicator.email.address`](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html#field-threat-indicator-email-address) | Identifies a threat indicator as an email address (irrespective of direction). |
| [`threat.indicator.ip`](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html#field-threat-indicator-ip)                       | Identifies a threat indicator as an IP address (irrespective of direction).    |
| [`threat.indicator.domain`](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html#field-threat-indicator-domain)               | Identifies a threat indicator as a domain (irrespective of direction).         |
| [`threat.indicator.marking.tlp`](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html#field-threat-indicator-marking-tlp)     | [Traffic Light Protocol](https://www.cisa.gov/tlp) sharing markings.           |
| [`threat.indicator.provider`](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html#field-threat-indicator-provider)           | The name of the indicator's provider.                                          |
| [`threat.indicator.type`](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html#field-threat-indicator-type)                   | Type of indicator as represented by Cyber Observable in STIX 2.0.              |

For more information, check out the [Threat ECS fieldset](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html).

## Ingesting data

All NDJSON documents are structured in ECS format so they can be ingested by Filebeat.

### Filebeat

Instructions below are to upload the NDJSON document using Filebeat.

1. [Install Filebeat](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation-configuration.html)
2. [Enable the Filestream input](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-filebeat-options.html)
3. Add the directory of the `.ndjson` document
4. Add the NDJSON configuration options to `filebeat.yml`

```yaml
...truncated
filebeat.inputs:

# Each - is an input. Most options can be set at the input level, so
# you can use different inputs for various configurations.
# Below are the input specific configurations.

# filestream is an input for collecting log messages from files.
- type: filestream

# Change to true to enable this input configuration
enabled: true

# Paths that should be crawled and fetched. Glob based paths
paths:
  - /path/to/documents/*.ndjson
parsers:
  - ndjson:
      target: ""
      add_error_key: true
...truncated
```

5. Configure the [output](https://www.elastic.co/guide/en/beats/filebeat/current/configuring-output.html)
6. Check your configuration with `filebeat test output` and `filebeat test config`
7. Run the Filebeat setup `filebeat setup`
8. Start Filebeat and check the `filebeat-*` data view in Kibana