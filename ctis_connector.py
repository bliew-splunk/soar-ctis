#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import json
import traceback
from urllib.parse import urljoin

import phantom.app as phantom
# Usage of the consts file is recommended
# from abc_consts import *
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector, REST_BASE_URL
from phantom.utils import config as phconfig

import cef_to_stix
from taxii_client import TAXIIClient

assert REST_BASE_URL.endswith("/")


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CTISConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CTISConnector, self).__init__()

        self._state = None

        self._base_url = None
        self.username = None
        self.password = None
        self.client = None
        self.export_tag = None

    def _handle_test_connectivity(self, action_result, param):

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress(f"Connecting to TAXII Server at {self._base_url}")

        try:
            self.client.test_connection()
        except requests.exceptions.RequestException as e:
            self.save_progress("Test Connectivity Failed.")
            return action_result.set_status(phantom.APP_ERROR, str(e))

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_object_to_collection(self, action_result, param):
        collection_id = param.get('collection_id')
        object_ = param.get('object')
        self.save_progress(f"Adding object to collection {collection_id}")
        self.save_progress(f"collection_id: {collection_id}, object: {object_}")

        object_dict = json.loads(object_)
        self.save_progress(f"object deserialized: {object_dict}")
        resp = self.client.add_object_to_collection(collection_id, object_dict)
        self.save_progress(f"Response: {resp}")

        action_result.add_data({"response": resp})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_generate_indicator_stix_json(self, action_result, param):
        indicator_id = param['indicator_id']
        self.save_progress(f"Generating STIX JSON for {param}")
        indicator = self.get_indicator(indicator_id=indicator_id)

        # stix_dict = cef_to_stix.build_indicator_stix(normalized_cef_field, value)
        # self.save_progress(f"STIX JSON: {stix_dict}")
        # action_result.add_data({"json": json.dumps(stix_dict)})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, action_result, param):
        self.save_progress(f"ON POLL: export_tag={self.export_tag}")
        self.save_progress(f"ON POLL: {param}")
        return action_result.set_status(phantom.APP_SUCCESS, "ON POLL")

    def handle_action(self, param):
        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        actions = {
            'test_connectivity': self._handle_test_connectivity,
            'add_object_to_collection': self._handle_add_object_to_collection,
            'generate_indicator_stix_json': self._handle_generate_indicator_stix_json,
            'on_poll': self._handle_on_poll
        }
        action_result = self.add_action_result(ActionResult(dict(param)))
        if action_id not in actions:
            return action_result.set_status(phantom.APP_ERROR, f"Unknown action_id: {action_id}")
        try:
            return actions[action_id](action_result, param)
        except (Exception,):
            stack_trace = traceback.format_exc()
            self.save_progress(f"Error in action {action_id}: {stack_trace}")
            return action_result.set_status(phantom.APP_ERROR, stack_trace)

    def get_indicator(self, indicator_id: str) -> dict:
        endpoint = urljoin(REST_BASE_URL, f"indicator/{indicator_id}")
        self.save_progress(f"Getting indicator from {endpoint}")
        response = requests.get(endpoint, params={
            "_special_fields": True,
            "_special_labels": True,
            "_special_contains": True,
            "_special_severity": True
        }, verify=phconfig.platform_strict_tls)
        response.raise_for_status()
        resp_json = response.json()
        self.save_progress(f"Response: {resp_json}")
        raise NotImplementedError

    def get_artifact(self, container_id, artifact_id) -> dict:
        endpoint = urljoin(REST_BASE_URL, f"container/{container_id}/artifacts")
        self.save_progress(f"Getting artifacts from {endpoint}")
        response = requests.get(endpoint, params={"_filter_id": artifact_id}, verify=phconfig.platform_strict_tls)
        response.raise_for_status()
        resp_json = response.json()
        self.save_progress(f"Response: {resp_json}")
        data = resp_json["data"]
        assert type(data) == list
        assert len(data) == 1
        only_artifact = data[0]
        assert "id" in only_artifact
        assert "cef" in only_artifact
        return only_artifact

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config['base_url']
        self.username = config['username']
        self.password = config['password']
        self.client = TAXIIClient(api_root_url=self._base_url, username=self.username, password=self.password,
                                  log_function=self.save_progress)
        self.export_tag = config['export_tag']

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = CTISConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CTISConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
