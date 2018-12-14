from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisInProgress, AnalysisResult,
                                                    AnalysisTemporaryError, AnalysisPermanentError)
from cbint.utils import feed

from cbapi.connection import CbAPISessionAdapter

from rl_apiclient import (ReversingLabsAnalysisClient, RLAPIQUOTAREACHED)

from datetime import (datetime, timedelta)
from requests import Session

import traceback

from urlparse import urljoin

import logging

log = logging.getLogger(__name__)

SEVERITY = {
    0: 0,
    1: 20,
    2: 40,
    3: 60,
    4: 80,
    5: 100
}


class ReversingLabsTiCloudProvider(BinaryAnalysisProvider):

    def __init__(self, name, username=None, password=None, url=None, days_rescan=None, report_visualisation_url=None,
                 log_level=None, submit_full_binaries=None):
        super(ReversingLabsTiCloudProvider, self).__init__(name)

        session = Session()
        tls_adapter = CbAPISessionAdapter(force_tls_1_2=True)
        session.mount("https://", tls_adapter)
        self.base_url = url
        self.rl_analysis = ReversingLabsAnalysisClient(session=session,
                                                       username=username,
                                                       password=password,
                                                       base_url=url,
                                                       log_level=log_level)

        self.submit_full_binaries = submit_full_binaries
        self.report_visualisation_url = report_visualisation_url

        if int(days_rescan) > 0:
            self.days_rescan = int(days_rescan)
        else:
            self.days_rescan = None

    def make_result(self, md5=None, result=None):

        try:
            result = self.rl_analysis.get_report(md5) if not result else result
        except Exception as err:
            log.info(traceback.format_exc())
            raise AnalysisTemporaryError(message="API error: %s" % str(err), retry_in=5 * 60)

        log.info("Result for md5: %s" % md5)
        result_link = "%s/uploads/?q=hash%%3A%s" % (self.report_visualisation_url.rstrip("/"), md5)
        log.info("Result link: %s" % result_link)

        malware_presence = result['rl']['malware_presence']
        status = malware_presence.get("status").upper()
        threat_name = malware_presence.get("threat_name")
        if threat_name is None:
            threat_name = ""

        threat_level = int(malware_presence.get("threat_level"))
        trust_factor = int(malware_presence.get("trust_factor"))

        score = SEVERITY[threat_level]

        if "scanner_count" in malware_presence and "scanner_match" in malware_presence:
            total_scanners = int(malware_presence.get("scanner_count"))
            scanner_match = int(malware_presence.get("scanner_match"))
            malware_result = """ReversingLabs report for md5: %s; 
                                RL Status: %s %s; 
                                RL Trust Factor: %s; 
                                Threat Level: %s; 
                                AV detection number: %s/%s;
                                """ % \
                             (md5, status, threat_name, trust_factor, threat_level, scanner_match, total_scanners)
        else:
            malware_result = """ReversingLabs report for md5: %s; 
                                RL Status: %s %s; 
                                RL Trust factor: %s; 
                                Threat level: %s;
                                """ % \
                             (md5, status, threat_name, trust_factor, threat_level)

        report_string = """Report string (test string)"""

        return AnalysisResult(message=malware_result,
                              title=malware_result,
                              description=report_string,
                              link=result_link,
                              score=score)

    def check_result_for(self, md5sum):

        log.info("Submitting hash %s to RL for analysis" % md5sum)

        try:
            response = self.rl_analysis.get_report(resource_hash=md5sum)
        except RLAPIQUOTAREACHED as rle:
            log.info(traceback.format_exc())
            raise AnalysisTemporaryError(message="Error: {}".format(str(rle)),
                                         retry_in=15 * 60)
        except Exception as err:
            log.info(traceback.format_exc())
            raise AnalysisTemporaryError(message="Error: {}".format(str(err)),
                                         retry_in=15 * 60)

        malware_presence = response["rl"]["malware_presence"]
        status = malware_presence.get("status").upper()

        if 'UNKNOWN' in status:
            return AnalysisInProgress(retry_in=15 * 60)

        # calculate if hash needs rescan
        datetime_now = datetime.utcnow()
        log.info("current time: %s" % datetime_now)
        if self.days_rescan:
            rescan_date = datetime_now - timedelta(days=int(self.days_rescan))
        else:
            rescan_date = None
        log.info("rescan date: %s" % rescan_date)
        last_seen_date_str = malware_presence.get('last_seen')
        log.info("last seen str: %s" % last_seen_date_str)
        last_seen_date = datetime.strptime(last_seen_date_str, "%Y-%m-%dT%H:%M:%S") if last_seen_date_str else None
        log.info("last seen date: %s" % last_seen_date)
        log.info(
            "Binary %s has not been scanned since: %s - timenow: %s. Should do rescan if last seen is older than %s" %
            (md5sum, last_seen_date, datetime_now, rescan_date))

        if self.days_rescan and last_seen_date <= rescan_date:
            log.info("HIT rescan date: Binary %s" % md5sum)
            try:
                self.rl_analysis.rescan_hash(md5sum)
            except RLAPIQUOTAREACHED as rle:
                log.info(traceback.format_exc())
                raise AnalysisTemporaryError(message="Error: {}".format(str(rle)),
                                             retry_in=15 * 60)
            except Exception as err:
                log.info(traceback.format_exc())
                raise AnalysisTemporaryError(message="There was an error. Error: {}".format(str(err)),
                                             retry_in=15 * 60)

            return AnalysisInProgress(message="Rescaning hash {}".format(md5sum), retry_in=60 * 60)
        else:
            return self.make_result(md5=md5sum, result=response)

    def analyze_binary(self, md5sum, binary_file_stream):
        if not self.submit_full_binaries:
            raise AnalysisPermanentError("Submitting full binaries is not enabled")

        log.info("Submitting binary {}".format(md5sum))

        successfull_upload = self.rl_analysis.submit_file(md5sum=md5sum, stream=binary_file_stream)

        if successfull_upload:
            return self.make_result(md5=md5sum)
        else:
            raise AnalysisTemporaryError("Unable to upload file. md5sum: {}".format(md5sum), retry_in=30 * 60)


class ReversingLabsTiCloudConnector(DetonationDaemon):
    @property
    def filter_spec(self):
        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append('orig_mod_len:[1 TO {}]'.format(max_module_len))
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        return " ".join(filters)

    @property
    def integration_name(self):
        return 'Cb ReversingLabs connector 1.0'

    @property
    def num_quick_scan_threads(self):
        return self.get_config_integer("reversinglabs_quick_scan_threads", 2)

    @property
    def num_deep_scan_threads(self):
        return self.get_config_integer("reversinglabs_deep_scan_threads", 2)

    def get_provider(self):
        reversinglabs_provider = ReversingLabsTiCloudProvider(name=self.name,
                                                              username=self.username,
                                                              password=self.password,
                                                              days_rescan=self.days_rescan,
                                                              report_visualisation_url=self.report_visualisation_url,
                                                              submit_full_binaries=self.submit_full_binaries,
                                                              url=self.reversinglabs_api_url,
                                                              log_level=self.log_level)

        return reversinglabs_provider

    def get_metadata(self):
        return feed.generate_feed(self.name,
                                  summary="The ReversingLabs TitaniumCloud File Reputation, part of ReversingLabs Threat Intelligence provides up-to-date file reputation, Anti-Virus scan information and internal analysis information on billions of goodware and malware samples.Malware samples are continually reanalyzed to ensure that the reputation information is relevant at all times.In addition to file reputation and historical AV reputation, additional Threat Intelligence can be obtained from TitaniumCloud via multiple APIs and Feeds, which allow users to search for files by hash or anti-virus detection name. It is also possible to hunt for files from a single malware family, search for functionally similar samples, perform bulk queries, and receive alerts on file reputation changes. ",
                                  tech_data="A ReversingLabs private API key is required to use this feed. There are no requirements to share any data with Carbon Black to use this feed. However, binaries may be shared with ReversingLabs.",
                                  provider_url="https://www.reversinglabs.com/",
                                  icon_path="/usr/share/cb/integrations/reversinglabs-ticloud/cb-titaniumcloud.png",
                                  display_name="ReversingLabs - TitaniumCloud",
                                  category="Connector")

    def validate_config(self):
        super(ReversingLabsTiCloudConnector, self).validate_config()

        # check configuration options
        self.check_required_options(
            ["reversinglabs_api_username", "reversinglabs_api_password", "reversinglabs_api_host"])

        self.username = self.get_config_string("reversinglabs_api_username", None)
        self.password = self.get_config_string("reversinglabs_api_password", None)

        self.reversinglabs_api_url = self.get_config_string("reversinglabs_api_host", None)
        self.report_visualisation_url = self.get_config_string("reversinglabs_a1000_host",
                                                               "https://a1000.reversinglabs.com")
        self.days_rescan = self.get_config_string("days_rescan", None)

        # check submit binaries option
        self.submit_full_binaries = self.get_config_string("submit_full_binaries", '0')
        self.submit_full_binaries = True if self.submit_full_binaries.lower() in ['true', '1'] else False

        # log warning if submit binaries
        if self.submit_full_binaries and self.num_deep_scan_threads > 0:
            log.info("WARNING: This connector is currently configured to sumbit FULL binaries to ReversingLabs")
            log.info("WARNING: If this is not your intention please modify connector.conf")
            log.info("WARNING: Set submit_full_binaries = 0 and reversinglabs_deep_scan_threads = 0")

        # check log level options
        self.log_level = self.get_config_string("debug", 0)
        self.log_level = logging.DEBUG if int(self.log_level) else logging.INFO

        # set log level
        log.setLevel(self.log_level)
        return True


if __name__ == "__main__":
    import os

    my__path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/reversinglabs"

    config_path = os.path.join(my__path, "testing.conf")
    deamon = ReversingLabsTiCloudConnector(name="reversinglabsticloud",
                                           configfile=config_path,
                                           work_directory=temp_directory,
                                           logfile=os.path.join(temp_directory, 'test.log'),
                                           debug=True)

    logging.getLogger().setLevel(logging.DEBUG)

    deamon.start()
