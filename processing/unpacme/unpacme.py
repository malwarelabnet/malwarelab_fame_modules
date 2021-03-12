import hashlib
import os
import time
from urllib.parse import urljoin

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError
from fame.core.module import ProcessingModule


class UnpacMe(ProcessingModule):
    name = "unpacme"
    description = "Submit the file to UnpacMe."
    acts_on = ["executable"]
    generates = ["unpacked_executable"]

    config = [
        {
            'name': 'api_endpoint',
            'type': 'str',
            'default': 'https://api.unpac.me/api/v1/private/',
            'description': "URL of UnpacMe's API endpoint."
        },
        {
            'name': 'api_key',
            'type': 'str',
            'description': 'API Key to use to connect to your UnpacMe account.'
        },
        {
            'name': 'web_endpoint',
            'type': 'str',
            'default': 'https://www.unpac.me/results/',
            'description': "URL of UnpacMe's web interface."
        },
        {
            'name': 'wait_timeout',
            'type': 'integer',
            'default': 5400,
            'description': 'Time in seconds that the module will wait for analysis to be over.'
        },
        {
            'name': 'wait_step',
            'type': 'integer',
            'default': 30,
            'description': "Time in seconds between two check of analysis status."
        },
        {
            'name': 'check_existing',
            'type': 'bool',
            'default': True,
            'description': 'Check for existing analysis retrieve most recent report will not re-submit file.',
            'option': True
        },
        {
            'name': 'collect_unpacked',
            'type': 'bool',
            'default': False,
            'description': 'This allows the module to download unpacked executables.',
            'option': True
        }
    ]

    permissions = {
        'unpacme_access': "For users that have access to UnpacMe. Will display a link to UnpacMe's analysis."
    }

    def initialize(self):
        # Check dependencies
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")

    def each_with_type(self, target, file_type):
        try:
            self.unpacme = UnpacMe(self.api_key)

            # Set root URLs
            self.results = dict()

            fp = open(target, 'rb')
            self.sha256sum = hashlib.sha256(fp.read()).hexdigest()
            fp.close()
            self.results['parent'] = self.sha256sum

            # First, submit the file
            if file_type == 'executable':
                if self.check_existing:
                    self.search_file(target)
                else:
                    self.submit_file(target)

            # Wait for analysis to be over
            self.wait_for_analysis()

            # Get report, and tag signatures
            self.process_report()

            # Add report URL to results
            self.results['URL'] = urljoin(self.web_endpoint, "{}".format(self.task_id))

        except Exception as error:
            self.log("debug", "{}".format(error))

        return True

    def search_file(self, filepath):
        API_KEY_STRING = 'Key %s' % self.api_key
        auth_header={'Authorization': API_KEY_STRING}
        r = requests.get(self.api_endpoint + 'search/hash/' + self.sha256sum, headers=auth_header)
        response = r.json()
        try:
            for item in response['results']:
                self.task_id = item['submission_id']
                self.log("debug", "Found existing report.")
        except:
            self.log("debug", "No reports found. Submitting file.")
            self.submit_file(filepath)

    def submit_file(self, filepath):
        basename = os.path.basename(filepath)
        fp = open(filepath, 'rb')
        API_KEY_STRING = 'Key %s' % self.api_key
        auth_header={'Authorization': API_KEY_STRING}
        files = {'file':(basename, fp)}
        r = requests.post(self.api_endpoint + 'upload', files=files, headers=auth_header)
        response = r.json()
        fp.close()
        self.log("debug", response)
        self.task_id = response['id']

    def wait_for_analysis(self):
        waited_time = 0
        while waited_time < self.wait_timeout:
            API_KEY_STRING = 'Key %s' % self.api_key
            auth_header={'Authorization': API_KEY_STRING}
            r = requests.get(self.api_endpoint + 'status/' + self.task_id, headers=auth_header)
            response = r.json()
            status = response['status']
            if status == 'complete':
                break
            time.sleep(self.wait_step)
            waited_time += self.wait_step
        if status != 'complete':
            raise ModuleExecutionError('could not get report before timeout.')

    def process_report(self):
        try:
            API_KEY_STRING = 'Key %s' % self.api_key
            auth_header={'Authorization': API_KEY_STRING}
            r = requests.get(self.api_endpoint + 'results/' + self.task_id, headers=auth_header)
            response = r.json()
            self.extract_info(response)
        except Exception as error:
            raise ModuleExecutionError('Error encountered while processing report:\n{}'.format(error))

    def extract_info(self, report):
        self.results['unpacked_executables'] = []
        if report.get('results'):
            for item in report['results']:
                sig = dict()
                sig['name'] = item['hashes']['sha256']
                sig['malwares'] = []
                sig['detects'] = []
                if item.get('malware_id'):
                    for mal in item['malware_id']:
                        sig['malwares'].append(mal['name'])
                if item.get('detectit'):
                    for detect in item['detectit']:
                        sig['detects'].append(detect['name'])
                self.results['unpacked_executables'].append(sig)

                if self.collect_unpacked:
                    API_KEY_STRING = 'Key %s' % self.api_key
                    auth_header={'Authorization': API_KEY_STRING}
                    r = requests.get(self.api_endpoint + 'download/' + item['hashes']['sha256'], headers=auth_header)
                    sample_data = r.content
                    tmpdir = tempdir()
                    filename = os.path.join(tmpdir, 'unpacme_unpacked_executable')
                    with open(filename, "wb") as f:
                        f.write(sample_data)
                    self.register_files('unpacked_executable', filename)

