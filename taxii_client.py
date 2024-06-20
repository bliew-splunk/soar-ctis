import os
from typing import Dict, List
import json
from taxii2client.v21 import ApiRoot
import stix2


def convert_to_dicts(list_of_taxii_objects) -> List[Dict]:
    # TODO: replace with _raw() method in taxii2client Classes
    result = []
    for obj in list_of_taxii_objects:
        as_dict = {k: v for k, v in obj.__dict__.items() if not k.startswith('_')}
        result.append(as_dict)
    return result


class TAXIIClient:
    def __init__(self, api_root_url: str, username: str, password: str, log_function=None):
        self.api_root = ApiRoot(api_root_url, user=username, password=password)
        self.log_function = log_function

    def log(self, message: str):
        if self.log_function:
            self.log_function(message)
        else:
            print(message)

    def test_connection(self):
        self.log(f"Testing connection to {self.api_root.url}")
        # Force client to connect to server to validate connection
        # Throws requests.exceptions.HTTPError if credentials are bad
        _ = self.list_collections()
        self.log(f"Connection to {self.api_root.url} successful")

    def get_collection(self, collection_id: str):
        # TODO: Improve efficiency using a map if we are calling this multiple times
        for collection in self.api_root.collections:
            if collection.id == collection_id:
                return collection
        else:
            raise LookupError(f"Collection {collection_id} not found")

    def list_collection_objects(self, collection_id: str) -> list:
        collection = self.get_collection(collection_id)
        return collection.get_objects()

    def add_object_to_collection(self, collection_id: str, object_: dict):
        assert type(object_) == dict
        envelope = {
            "objects": [object_]
        }
        resp = self.get_collection(collection_id).add_objects(envelope)
        self.log(f"Added object to collection {collection_id}. Response: {vars(resp)}")
        return resp._raw

    def list_collections(self) -> list:
        return self.api_root.collections


if __name__ == '__main__':
    client = TAXIIClient(os.environ['TAXII_API_ROOT_URL'],
                         os.environ['TAXII_USERNAME'],
                         os.environ['TAXII_PASSWORD'])
    objects = client.list_collection_objects(collection_id='365fed99-08fa-fdcd-a1b3-fb247eb41d01')
    # Indicator is an SDO (STIX Domain Object)
    ind1 = stix2.Indicator(
        indicator_types=['malicious-activity'],
        pattern_type="stix",
        pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        valid_from="2017-01-01T12:34:56Z",
    )
    ind1_dict = json.loads(ind1.serialize())
    print(ind1_dict)
    resp = client.add_object_to_collection(collection_id='365fed99-08fa-fdcd-a1b3-fb247eb41d01', object_=ind1_dict)
    print(resp)
