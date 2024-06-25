## Analysis of MS Sentinel CTIS Playbook 'AusCtisExportTaggedIndicators'
### HTTP POST stix bundle to TAXII server
`POST {TAXI_SERVER_ROOT_URL}/collections/{COLLECTION_ID}/objects`

Payload JSON BODY
`objects` is a list of indicators, one identity object, marking-definition objects (set of TLP values), grouping(s)?
```json
{
    "type" : "bundle",
    "id" : "bundle--{ORGANIZATION_ID}",
    "objects" : []
}
```
### TLP Marking Definition Object
7.2 - Data Markings: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_95gfoglikdzh

Note that the TLP definitions are static.
Example: TLP WHITE definition
```json
{
  "type": "marking-definition",
  "spec_version": "2.1",
  "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
  "created": "2017-01-20T00:00:00.000Z",
  "definition_type": "tlp",
  "name": "TLP:WHITE",
  "definition": {
    "tlp": "white"
  }
}
```


### Indicators list
Example indicator object.
- TLP is specified via `object_marking_refs`, which references the static TLP marking-definition object
- For the SOAR integration, we could tag the indicator with the generated STIX indicator id, and reuse if we want to resubmit the same indicator
  - possibly use a prefix too, like `stix:indicator--abc123`
```json
{
  "created": "",
  "created_by_ref": "{SOME_IDENTIIY_ID_PARAM}",
  "id": "indicator--{guid()}", 
  "modified": "",
  "pattern": "stix",
  "pattern_type": "stix pattern...",
  "spec_version": "2.1",
  "type": "indicator",
  "valid_from": "",
  "confidence" : 100,
  "description" : "",
  "lang" : "en",
  "name" : "Display name of indicator",
  "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"]
}
```

### Identity Object
Identity object appended to indicators list
https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp
```json
{
  "confidence": 100,
  "created": "...",
  "id": "{SOME_IDENTIIY_ID_PARAM}",
  "identity_class": "organization",
  "modified": "...",
  "name": "CTIS",
  "spec_version": "2.1",
  "type": "identity"
}
```

### Grouping
Sample from '4.4.2 Relationships'
Relates multiple objects together.
This might be a stretch goal, as this is a higher-level abstraction

What is still not clear in the MS playbook, is what criteria is used to group indicators?
```json
{
  "type": "grouping",
  "spec_version": "2.1",
  "id": "grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
  "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
  "created": "2015-12-21T19:59:11.000Z",
  "modified": "2015-12-21T19:59:11.000Z",
  "name": "The Black Vine Cyberespionage Group",
  "description": "A simple collection of Black Vine Cyberespionage Group attributed intel",
  "context": "suspicious-activity",
  "object_refs": [
    "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
    "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
    "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a",
    "file--0203b5c8-f8b6-4ddb-9ad0-527d727f968b"
  ]
}
```
