## SOAR REST API
### Query an indicator by ID -> List related CEF fields
GET /rest/indicator/{INDICATOR_ID}?_special_fields=true&_special_labels=true&_special_contains=true&_special_severity=true
the `_special_fields` list contains all Artifact CEF fields which mention this indicator.
```json
{
  "tags": [
    "test",
    "indicator--abc123"
  ],
  "id": 3,
  "value": "1.2.3.4",
  "value_hash": "6694f83c9f476da31f5df6bcc520034e7e57d421d247b9d34f49edbfc84a764c",
  "tenant": 0,
  "_special_labels": [
    "events"
  ],
  "_special_contains": [
    "ip"
  ],
  "_special_fields": [
    "destinationAddress",
    "sourceAddress"
  ],
  "earliest_time": "2024-06-19T23:36:03.086489Z",
  "latest_time": "2024-06-25T02:56:39.973750Z",
  "open_events": 2,
  "total_events": 2,
  "severity_counts": [
    {
      "name": "high",
      "count": 0
    },
    {
      "name": "medium",
      "count": 2
    },
    {
      "name": "low",
      "count": 0
    }
  ]
}
```
### Query indicator by value
`GET /rest/indicator?_filter_value="abc"`
Example: `/rest/indicator?_filter_value=%221.2.3.4%22`

### List artifacts related to an indicator
Optionally provide a `timerange` param set to `this_month`, `this_year`, `last_30_days`
Default is last 30 days
`GET /rest/indicator_artifact_timeline?indicator_value=1.2.3.4&timeline_width=1000`
```json
{
  "domain": [
    1716768000,
    1719359999
  ],
  "data": [
    {
      "count": 1,
      "type": "node",
      "containerId": null,
      "eventName": null,
      "time": "2024-05-25T04:48:00.060000Z",
      "unixTime": 1716612480.06,
      "readableTime": "5/25",
      "id": null,
      "severity": null,
      "didInjectThisDataPoint": true
    },
    {
      "count": 1,
      "type": "node",
      "containerId": 2,
      "eventName": "test",
      "time": "2024-06-19T23:36:03.086489Z",
      "unixTime": 1718840163.086489,
      "readableTime": "6/19",
      "id": 2,
      "severity": "low"
    },
    {
      "count": 2,
      "type": "node",
      "containerId": 88,
      "eventName": "file 1",
      "time": "2024-06-25T02:56:39.973750Z",
      "unixTime": 1719284199.97375,
      "readableTime": "6/25",
      "id": 4,
      "severity": "medium"
    },
    {
      "count": 2,
      "type": "node",
      "containerId": null,
      "eventName": null,
      "time": "2024-06-27T19:11:58.940000Z",
      "unixTime": 1719515518.94,
      "readableTime": "6/27",
      "id": null,
      "severity": null,
      "didInjectThisDataPoint": true
    }
  ]
}
```