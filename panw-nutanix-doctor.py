#!/usr/bin/env python3
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#

import os
import os.path
import re
import sys
import json
import requests
import logging
from configparser import ConfigParser
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from flask import Flask, request
from flask_restful import Resource, Api, reqparse

__author__ = 'Mohanad Elamin'

debug = False

CONFIG_FILENAME = "~/panw-nutanix-doctor/.doctor.conf"


app = Flask(__name__)
api = Api(app)

app.logger.setLevel(logging.INFO)

base_url = ""


def request_get(request_url, session):
	response = session.get(request_url, verify=False)
	# parsed = json.loads(response.text)
	return response

def request_post(request_url, session, data):
	response = session.post(request_url, data=data, verify=False)
	return response

def request_put(request_url, session, data):
	response = session.put(request_url, data=data, verify=False)
	return response

def search_vm(obj, ip):
	for nic_obj in obj['status']['resources']['nic_list']:
		if 'ip_endpoint_list' in nic_obj:
			for ip_obj in nic_obj['ip_endpoint_list']:
				if (ip_obj['ip'] == ip):
					return True
	return False
						

def prism_get_vms():
	request_url = base_url + "/vms/list"
	data = { 'kind': 'vm', 'offset': 0, 'length': length}
	return request_post(request_url, session, json.dumps(data))

def prism_get_vm(uuid):
	request_url = base_url + "/vms/" + uuid
	return request_get(request_url, session)

def get_vm_dict_by_ip(ip_address):
	response = prism_get_vms()
	for vm in json.loads(response.text)['entities']:
		if search_vm(vm,ip_address):
			return vm
	return False

def get_uuid(vm):
	return vm['metadata']['uuid']

def assign_tag(response_dict):
	ip_address = response_dict['ip']
	tag_category = response_dict['category']
	tag_value = response_dict['value']
	vm_dict = get_vm_dict_by_ip(ip_address)
	if vm_dict is not False:
		vm_uuid = get_uuid(vm_dict)
		vm_spec = json.loads(prism_get_vm(vm_uuid).text)
		if tag_category in vm_spec['metadata']['categories']:
			return "Tag already assigned"
		else:
			vm_template['spec'] = vm_spec['spec']
			vm_template['metadata'] = vm_spec['metadata']
			new_tag = {tag_category : tag_value}
			vm_template['metadata']['categories'].update(new_tag)

			request_url = base_url + "/vms/" + vm_uuid
			response = request_put(request_url, session, json.dumps(vm_template))
			return response.status_code
	else:
		return "IP not found"


class NutanixDoctor(Resource):
	def get(self):
		response_dict['ip'] = request.args.get('ip')
		response_dict['category'] = request.args.get('category')
		response_dict['value'] = request.args.get('value')
		return response_dict

	def put(self):
		pass
	# do put something

	def delete(self):
		pass
	# do delete something

	def post(self):
		response_dict = request.get_json(force=True)
		response = assign_tag(response_dict)
		return response
				

api.add_resource(NutanixDoctor, '/api/nutanix')

if __name__ == '__main__':
	secureConnection = True
	os.environ["FLASK_ENV"] = "development"
	ip_found = False
	cfgparser = ConfigParser()
	try:
		cfgparser.read(os.path.expanduser(CONFIG_FILENAME))
	except:
		error("Can't parse configuration file {}"
			  "".format(os.path.expanduser(CONFIG_FILENAME)))
		sys.exit(1)
	if ('doctor_config' not in cfgparser):
		error("Configuration file {} doesn't contain 'doctor_config' section"
			"".format(os.path.expanduser(CONFIG_FILENAME)))
		sys.exit(1)
	elif (('user' not in cfgparser['doctor_config']) or
		('pass' not in cfgparser['doctor_config']) or
		('prism' not in cfgparser['doctor_config'])):
		error("Config file doesn't contain (all) required authentication info")
		sys.exit(1)
	elif (('cert_path' not in cfgparser['doctor_config']) or
		('key_path' not in cfgparser['doctor_config']) or
		cfgparser['doctor_config']['cert_path'] == '' or
		cfgparser['doctor_config']['key_path'] == '' ):
		secureConnection = False


	if ('DEBUG' in cfgparser['doctor_config'] and cfgparser['doctor_config']['DEBUG'].lower() == 'yes'):
		debug = True
		app.logger.setLevel(logging.DEBUG)

	config = cfgparser['doctor_config']

	if ('length' in cfgparser['doctor_config']):
		length = config["LENGTH"]
	else:
		length = 100

	username = config["USER"]
	password = config["PASS"]
	prismAddr = config["prism"]

	if secureConnection:
		cert_path = config["CERT_PATH"]
		key_path = config["KEY_PATH"]
	if ('PORT' in cfgparser['doctor_config'] and cfgparser['doctor_config']['PORT'] != ''):
		port = config["PORT"]
	else:
		port = 443 if secureConnection else 80


	base_url = "https://" + prismAddr + ":9440/api/nutanix/v3"

	# Request API session info
	session = requests.Session()
	session.auth = (username, password)
	session.headers.update({'Content-Type': 'application/json; charset=utf-8'})

	# Flask API response dict
	response_dict = {
		'ip': '',
		'category': '',
		'value': '' 
	}

	vm_template = {
		'api_version' : '3.1',
		'spec' : '',
		'metadata' : ''
	}

	try:
		if secureConnection:
			app.logger.debug("Certificate and Key file are found. Starting the app with https! on port %s", port)
			context = (os.path.expanduser(cert_path),os.path.expanduser(key_path))
			app.run(debug=debug, host='0.0.0.0', ssl_context=context, port=port)
		else:
			app.logger.debug("Certificate and Key file are not found. Starting the app with http! %s", port)
			app.run(debug=debug, host='0.0.0.0', port=port)
	except Exception as e:
		print("Could not start Flask APP!.")
		print(e)