import logging
import hashlib
import os
import base64

from urlparse import urljoin

log = logging.getLogger(__name__)


class RLAPIQUOTAREACHED(Exception):
    pass


class FileStream(file):
    def next(self):
        pass

    def __init__(self, file_name):
        file.__init__(self, file_name, 'rb')

        sha1 = hashlib.sha1()
        self.size = 0

        while True:
            data = self.read(8192)
            sha1.update(data)

            self.size += len(data)

            if len(data) != 8192:
                break

        self.seek(0)
        self.sha1 = sha1.hexdigest()

    def __len__(self):
        return self.size


class ReversingLabsAnalysisClient(object):

    def __init__(self, session=None, username=None, password=None, base_url=None, log_level=None):

        self.session = session
        self.username = username
        self.password = password

        self.base_url = base_url
        if log_level:
            log.setLevel(logging.DEBUG)
        else:
            log.setLevel(logging.INFO)

    def rescan_hash(self, resource_hash):
        # create request url to rescan sample hash
        analyze_sample_url = '/api/rescan/v1/query/md5/%s' % resource_hash
        request_url = urljoin(self.base_url, analyze_sample_url)

        log.info("rescan_hash: resource_hash = %s" % resource_hash)
        auth = (self.username, self.password)

        # check if hash is not empty
        if not resource_hash:
            raise Exception("No resources provided")

        # create request
        response = self.session.get(request_url, auth=auth, verify=False)

        log.debug("Rescan hash: response = %s" % response)
        if response.status_code == 403:
            raise RLAPIQUOTAREACHED("Status code: {}, Error: Authorization has been provided in the request, but it is not valid.".format(response.status_code))
        elif response.status_code < 200 or response.status_code >= 300:
            raise Exception("Request for %s returned" % request_url)

        return response.json()

    def get_report(self, resource_hash=None):

        # create request url to get feed result from ticloud
        api_url = "/api/databrowser/malware_presence/query/md5/%s" % resource_hash
        request_url = urljoin(self.base_url, api_url)

        log.info("get_report: resource_hash = %s" % resource_hash)

        # auth data and params
        params = {
            'format': 'json',
            'extended': 'true'
        }
        auth = (self.username, self.password)

        if not resource_hash:
            raise Exception("No hash provided")

        response = self.session.get(request_url, params=params, auth=auth, verify=False)

        if response.status_code == 403:
            raise RLAPIQUOTAREACHED("Status code: {}, Error: Authorization has been provided in the request, but it is not valid.".format(response.status_code))
        elif response.status_code >= 300 or response.status_code < 200:
            raise Exception("RL api returned %d for %s" % response.status_code, resource_hash)

        return response.json()

    def submit_file(self, md5sum=None, stream=None):
        log.info("upload_file: md5_hash_value = %s" % md5sum)

        # log.info("submitting file: fs.name: %s" % stream.name)
        filename = os.path.basename(stream.name) if hasattr(stream, "name") else md5sum
        log.info("submitting file: fs.name: %s" % stream.name)
        file_data = FileStream(stream.name)

        # calculate sha1sum
        sha1sum = file_data.sha1

        headers = self.get_upload_file_headers()

        # submit binary file to ticloud service
        upload_file_response = self.upload_file(file_data=file_data, headers=headers)

        if upload_file_response.status_code == 200:
            log.info("Response code: {}. File {} uploaded successfully!".format(upload_file_response.status_code, filename))

            metadata_xml = self.default_metadata_xml(filename=filename)
            metadata_xml_upload_response = self.upload_metadata_xml(
                metadata_xml=metadata_xml,
                sha1sum=sha1sum,
                headers=headers
            )

            if metadata_xml_upload_response.status_code == 200:
                log.info("Response: {}. Metadata xml for file {} uploaded successfully, sha1sum: {}".format(
                    metadata_xml_upload_response.status_code, filename, sha1sum))
                return True
            else:
                log.info("Unable to upload metadata xml for sample: {}, sha1sum: {}".format(filename, sha1sum))
                log.info("Status code: {}".format(metadata_xml_upload_response.status_code))
                log.info("Response: {}".format(metadata_xml_upload_response.text))
                raise False
        else:
            log.info("[-] Unable to upload the file {} to TiCloud, sha1sum: {}".format(filename, sha1sum))
            log.info("[*] Status code: {}".format(upload_file_response.status_code))
            log.info("[*] Response: {}".format(upload_file_response.text))
            return False

    def upload_file(self, file_data, headers):

        api_url = "api/spex/upload/{}".format(file_data.sha1)
        sample_upload_url = urljoin(self.base_url, api_url)

        upload_file_response = self.session.post(sample_upload_url, data=file_data, headers=headers, verify=False)
        if upload_file_response.status_code < 200 or response.status_code >= 300:
            raise Exception("Request for file upload %s returned" % sample_upload_url)

        return upload_file_response

    def upload_metadata_xml(self, metadata_xml, sha1sum, headers):
        # submit binary metadata for uploaded file
        api_url = "api/spex/upload/{}/meta".format(sha1sum)
        upload_metadata_xml_url = urljoin(self.base_url, api_url)

        upload_metadata_xml_response = self.session.post(upload_metadata_xml_url, data=metadata_xml, headers=headers, verify=False)
        if upload_metadata_xml_response.status_code < 200 or response.status_code >= 300:
            raise Exception("Request for metadata upload %s returned" % upload_metadata_xml_url)

        return upload_metadata_xml_response

    def get_upload_file_headers(self):
        # create request auth token and headers
        auth_token = base64.encodestring("{}:{}".format(self.username, self.password))
        headers = {
            "Authorization": "Basic {}".format(auth_token),
            "Content-Type": "application/octet-stream"
        }
        return headers

    @staticmethod
    def default_metadata_xml(filename):
        default_metadata_xml_template = \
            """<?xml version="1.0" encoding="UTF-8"?>
            <rl>
                <properties>
                    <property>
                        <name>file_name</name>
                        <value>{0}</value>
                    </property>
                </properties>
                <domain></domain>
            </rl>"""

        return default_metadata_xml_template.format(filename)
