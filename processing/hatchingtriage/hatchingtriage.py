import hashlib
import os
import time
from urllib.parse import urljoin
from itertools import chain

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

try:
    from triage import Client
    HAVE_TRIAGE = True
except ImportError:
    HAVE_TRIAGE = False

from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError
from fame.core.module import ProcessingModule


class HatchingTriage(ProcessingModule):
    name = "hatching_triage"
    description = "Submit the file to Hatching Triage."
    acts_on = ["executable", "word", "html", "rtf", "excel", "pdf", "javascript", "jar", "url", "powerpoint", "vbs"]
    generates = ["dropped_file", "memory_dump", "pcap"]

    config = [
        {
            'name': 'api_endpoint',
            'type': 'str',
            'default': 'https://api.tria.ge/',
            'description': "URL of Hatching Triage's API endpoint."
        },
        {
            'name': 'apikey',
            'type': 'str',
            'description': 'API Key to use to connect to your Hatching Triage account.'
        },
        {
            'name': 'web_endpoint',
            'type': 'str',
            'default': 'https://tria.ge/',
            'description': "URL of Hatching Triage's web interface."
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
            'name': 'collect_dropfiles',
            'type': 'bool',
            'default': False,
            'description': 'This allows the module to download dropped files.',
            'option': True
        },
        {
            'name': 'collect_pcaps',
            'type': 'bool',
            'default': False,
            'description': 'This allows the module to download pcaps.',
            'option': True
        },
        {
            'name': 'collect_memdumps',
            'type': 'bool',
            'default': False,
            'description': 'This allows the module to download memdumps.',
            'option': True
        }
    ]

    permissions = {
        'triage_access': "For users that have access to the Hatching Triage. Will display a link to Hatching Triage's analysis."
    }

    def initialize(self):
        # Check dependencies
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")
        if not HAVE_MAGIC:
            raise ModuleInitializationError(self, "Missing dependency: magic")
        if not HAVE_TRIAGE:
            raise ModuleInitializationError(self, "Missing dependency: triage")

    def each_with_type(self, target, file_type):

        try:

            self.hatchingtriage = HatchingTriage(self.apikey)

            # Set root URLs
            self.results = dict()

            # First, submit the file / URL
            if file_type == 'url':
                self.submit_url(target)
            else:
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
        fp = open(filepath, 'rb')
        sha256 = hashlib.sha256(fp.read()).hexdigest()
        fp.close()
        triage_client = Client(self.apikey, root_url=self.api_endpoint)
        response = triage_client.search(sha256, max=1)
        try:
            for item in response:
                self.task_id = item['id']
                self.log("debug", "Found existing report.")
        except:
            self.log("debug", "No reports found. Submitting file.")
            self.submit_file(filepath)

    def submit_url(self, filepath):
        triage_client = Client(self.apikey, root_url=self.api_endpoint)
        response = triage_client.submit_sample_url(filepath)
        self.task_id = response['id']

    def submit_file(self, filepath):
        triage_client = Client(self.apikey, root_url=self.api_endpoint)
        basename = os.path.basename(filepath)
        fp = open(filepath, 'rb')
        response = triage_client.submit_sample_file(basename, fp)
        fp.close()
        self.task_id = response['id']

    def wait_for_analysis(self):
        triage_client = Client(self.apikey, root_url=self.api_endpoint)
        waited_time = 0
        while waited_time < self.wait_timeout:
            response = triage_client.sample_by_id(self.task_id)
            status = response['status']

            if status == 'reported':
                break

            time.sleep(self.wait_step)
            waited_time += self.wait_step

        if status != 'reported':
            raise ModuleExecutionError('could not get report before timeout.')

    def process_report(self):
        try:
            triage_client = Client(self.apikey, root_url=self.api_endpoint)
            response = triage_client.overview_report(self.task_id)
            self.extract_info(response)
        except Exception as error:
            raise ModuleExecutionError('Error encountered while processing report:\n{}'.format(error))

    def extract_info(self, report):
        self.results['score'] = 0
        self.results['signatures'] = []
        probable_name = ""
        if report.get('analysis'):
            if report['analysis'].get('family'):
                probable_name = ",".join(report['analysis']['family'])
                self.add_probable_name(str(probable_name).lower())
                self.add_tag(str(probable_name).lower())

            if report['analysis'].get('score'):
                score = report['analysis']['score']
                self.results['score'] = float(score)

            if report.get('signatures'):
                for item in report['signatures']:
                    signature = dict() 
                    if item.get('name'):
                        signature['name'] = item['name']
                    if item.get('score'):
                        signature['severity'] = item['score']
                    if item.get('desc'):
                        signature['description'] = item['desc']
                    self.results['signatures'].append(signature)

        if report.get('extracted'):
            configuration = dict() 
            for item in report['extracted']:
                if item.get('config'):
                    config = item['config']
                    configuration = dict(chain(config.items(), configuration.items()))
                    if item['config'].get('c2'):
                        for c2 in item['config']['c2']:
                            c2_tags = ['c2']
                            for threatname in probable_name.split(","):
                                c2_tags.append(threatname)
                            self.add_ioc(c2, c2_tags)
                if item.get('credentials'):
                    config = item['credentials']
                    configuration = dict(chain(config.items(), configuration.items()))
                if item.get('dropper'):
                    config = item['dropper']
                    configuration = dict(chain(config.items(), configuration.items()))                                        
            self.add_extraction(f"{probable_name} configuration", configuration)

        if report.get('tasks'):
            for task in report['tasks']:
                if task['status'] == "reported":
                    status = "reported"
                    if task['name'].startswith("behavioral"):
                        triage_client = Client(self.apikey, root_url=self.api_endpoint)
                        taskreport = triage_client.task_report(self.task_id, task['name'])

                        if taskreport.get('network'):
                            if taskreport['network'].get('flows'):
                                for flow in taskreport['network']['flows']:
                                    if flow['proto'] == "tcp":
                                        ip, port = flow['dst'].split(":")
                                        self.add_ioc(ip, ["port:"+port, "tcp"])

                            if taskreport['network'].get('requests'):
                                for item in taskreport['network']['requests']:
                                    if item.get('dns_request'):
                                        dns = item['dns_request']['domains'][0]
                                        self.add_ioc(dns, ["dns_request"])
                                    if item.get('http_request'):
                                        url = item['http_request']['url']
                                        self.add_ioc(url, ["http_request"])

                        if self.collect_dropfiles:
                            if taskreport.get('dumped'):
                                for item in taskreport['dumped']:
                                    if item['kind'] == "martian":
                                        triage_client = Client(self.apikey, root_url=self.api_endpoint)
                                        memdump = triage_client.sample_task_file(self.task_id, task['name'], item['name'])
                                        tmpdir = tempdir()
                                        filename = os.path.join(tmpdir, 'triage_dropped_file')
                                        with open(filename, "wb") as f:
                                            f.write(memdump)
                                        self.register_files('dropped_file', filename)
                                        mime = magic.from_file(filename, mime=True)
                                        if mime == "application/x-dosexec":
                                            self.add_extracted_file(filename)

                        if self.collect_memdumps:
                            if taskreport.get('dumped'):
                                for item in taskreport['dumped']:
                                    if item['kind'] == "mapping" or item['kind'] == "region":
                                        triage_client = Client(self.apikey, root_url=self.api_endpoint)
                                        memdump = triage_client.sample_task_file(self.task_id, task['name'], item['name'])
                                        tmpdir = tempdir()
                                        filename = os.path.join(tmpdir, 'triage_memory_dump')
                                        with open(filename, "wb") as f:
                                            f.write(memdump)
                                        self.register_files('memory_dump', filename)

                        if self.collect_pcaps:
                            triage_client = Client(self.apikey, root_url=self.api_endpoint)
                            pcapdump = triage_client.sample_task_file(self.task_id, task['name'], "dump.pcap")
                            tmpdir = tempdir()
                            filename = os.path.join(tmpdir, 'triage_pcap')
                            with open(filename, "wb") as f:
                                f.write(pcapdump)
                            self.register_files('pcap', filename)
