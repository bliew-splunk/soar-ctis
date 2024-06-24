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
```json
{
  "type": "Compose",
  "inputs": {
    "confidence": "@min(variables('GroupingConfidence'))",
    "context": "suspicious-activity",
    "created": "@formatDateTime(string(utcNow()), 'yyyy-MM-ddTHH:mm:ss.ffffffK')",
    "created_by_ref": "@variables('CreatedByRefObjId')",
    "description": "@first(variables('GroupingDescription'))",
    "id": "grouping--@{guid()}",
    "modified": "@formatDateTime(string(utcNow()), 'yyyy-MM-ddTHH:mm:ss.ffffffK')",
    "object_marking_refs": "@union(variables('GroupingMarkingRefObjs'), variables('GroupingMarkingRefObjs'))",
    "object_refs": "@union(variables('GroupingIndicators'), variables('GroupingIndicators'))",
    "spec_version": "2.1",
    "type": "grouping"
  }
}
```
