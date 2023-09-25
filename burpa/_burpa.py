#!/usr/bin/env python3
#
# Copyright (C) 2017  Adel "0x4D31" Karimi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from logging import getLogger
import os.path
import sys
import tempfile
import time
import traceback
import json
import csv as csvlib
from time import sleep
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunsplit
from typing import  Any, Dict, List, Optional, Sequence, TextIO, Tuple, Union

import importlib_resources # type: ignore[import]
import fire # type: ignore[import]
from dotenv import load_dotenv, find_dotenv
import attr
import dateutil.parser

from ._burp_rest_api_client import BurpRestApiClient
from ._burp_commander import BurpCommander
from ._error import BurpaError
from ._utils import (get_valid_filename, parse_commas_separated_str, ensure_scheme, 
                     parse_targets, setup_logger, perform, is_timenow_between, strip_tags)
from .__version__ import __version__, __author__

###################################################

ASCII = r"""            __                          
           / /_  __  ___________  ____ _
          / __ \/ / / / ___/ __ \/ __ `/
         / /_/ / /_/ / /  / /_/ / /_/ / 
        /_.___/\__,_/_/  / .___/\__,_/  
                        /_/             
         burpa version %s 
"""%(__version__)

@attr.s(auto_attribs=True)
class ScanRecord:
    """
    Temporary record represents a running scan.
    """
    task_id: str 
    target_url: str 
    date_time: str 
    status: Optional[str] = None
    metrics: Dict[str, Any] = attr.ib(factory=dict)
    report_file_name: Optional[List] = attr.ib(factory=list)

    @property
    def name(self) -> str:
        """
        This name is used as the filename for the file lock.
        """
        return get_valid_filename(f'{self.date_time}.{self.target_url}.{self.task_id}')

SCAN_STATUS_FINISHED = ("paused", "succeeded", "failed")

class Burpa:
    # TODO: api_key
    #        Burp REST API Extension API Key. Environment variable: 'BURP_API_KEY'.
    """
    High level interface for the Burp Suite Security Tool.

    Args
    ----
    api_url
        Burp Suite REST API Extension URL. Environment variable: 'BURP_API_URL'.
    api_port
        Burp REST API Extension Port (default: 8090). Environment variable: 'BURP_API_PORT'.
    new_api_url
        Burp Suite Official REST API URL (default: Same as api_url). Environment variable: 'BURP_NEW_API_URL'.
    new_api_port
        Burp Suite Official REST API Port (default: 1337). Environment variable: 'BURP_NEW_API_PORT'.
    new_api_key
        Burp Suite Official REST API key. Environment variable: 'BURP_NEW_API_KEY'.
    quiet
        Be less verbose, only print on errors.
    verbose
        Be more verbose, prints complete trace on errors.
    no_banner
        Do not print burpa banner.
    """

    def __init__(self, api_url: str = "",
                api_port: str = "8090",
                new_api_url: str = "",
                new_api_port: str = "1337",
                new_api_key: str = "",
                verbose: bool = False,
                quiet: bool = False, 
                no_banner: bool = False):
        
        self._logger = setup_logger('Burpa', verbose=verbose or bool(os.getenv("BURPA_DEBUG")), quiet=quiet)

        if not quiet and not no_banner:
            print(ASCII)
        
        file = find_dotenv()

        if file:
            self._logger.info(f"Loading .env file {file}")
            load_dotenv(file)

        api_url = ensure_scheme(os.getenv('BURP_API_URL') or api_url)
        api_port = os.getenv('BURP_API_PORT') or api_port
        new_api_url = ensure_scheme(os.getenv('BURP_NEW_API_URL') or new_api_url)
        new_api_port = os.getenv('BURP_NEW_API_PORT') or new_api_port
        new_api_key = os.getenv('BURP_NEW_API_KEY') or new_api_key

        if not api_url:
            self._logger.warning("You must configure api_url or 'BURP_API_URL' environment variable to communicate with Burp Suite. ")

        self._api: BurpRestApiClient = BurpRestApiClient(proxy_url=api_url, api_port=api_port, 
                                        logger=setup_logger('BurpRestApiClient', verbose=verbose, quiet=quiet))
        if new_api_url:
            self._newapi = BurpCommander(proxy_url=new_api_url,
                                  api_port=new_api_port,
                                  api_key=new_api_key or None,
                                    logger=setup_logger('BurpCommander', verbose=verbose, quiet=quiet))
            
        else:
            # Create the BurpCommander with the same URL as BurpRestApiClient.
            self._newapi = BurpCommander(proxy_url=api_url,
                            api_port=new_api_port,
                            api_key=new_api_key or None,
                            logger=setup_logger('BurpCommander', verbose=verbose, quiet=quiet))
        
        self._logger.info(f"Running Burp Suite version {'.'.join(str(v) for v in self._api.burp_version)}")

    def _start_scan(self, *targets: str, excluded: str = "", config: str = "", config_file: str = "",
            app_user: str = "", app_pass: str = "",) -> List[ScanRecord]:
        """
        Start a Burp Suite active scan.
        """
        self._test()

        if not targets:
            raise BurpaError("Error: No target(s) specified. ")

        # Parse targets
        parsed_targets = parse_targets(targets)

        # Parse excluded str
        excluded_urls = parse_commas_separated_str(excluded)

        # Parse config str
        config_names = parse_commas_separated_str(config)

        # Parse config file(s)
        config_files = parse_commas_separated_str(config_file)
        config_files_content = []
        for f in config_files:
            config_files_content.append(open(f, 'r', encoding='utf-8').read())

        scan_records = []

        authenticated_scans = app_pass and app_user

        for target_url in parsed_targets:
            base_urls = [target_url]

            if target_url.upper() == "ALL":
                history = self._api.proxy_history()
                if history:
                    scan_records.extend(self._start_scan(*history, 
                            app_user=app_user,
                            app_pass=app_pass,
                            excluded=excluded, 
                            config=config,
                            config_file=config_file))

            else:
                # Add targets to the project scope
                # The targets are included in the BurpCommander.active_scan API call, but 
                # in order to activate the project option "Drop all request outside of the scope", 
                # we need to add them preventively to the project scope before launching the scan. 
                parsed_url = urlparse(target_url)
                self._api.include(urlunsplit(
                        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, None, None)))
                
                # In order to be sure we're correctly scanning the website, we process the URL in order to
                # add its parent path if the URL ends with a filename. This makes sure we're not scanning only one file. 
                path_parts = parsed_url.path.split('/')
                if os.path.splitext(path_parts[-1])[-1]:
                    new_base_url = urlunsplit(
                            (parsed_url.scheme, parsed_url.netloc, '/'.join(path_parts[:-1]), None, None))
                    self._api.include(new_base_url)
                    base_urls.append(new_base_url)

                if authenticated_scans:
                
                    task_id = self._newapi.active_scan(*base_urls, 
                                                    username=app_user, password=app_pass,
                                                    excluded_urls=excluded_urls, 
                                                    config_names=config_names, 
                                                    config_json=config_files_content,)
                    
                else:
                    task_id = self._newapi.active_scan(*base_urls, 
                                                    excluded_urls=excluded_urls,
                                                    config_names=config_names,
                                                    config_json=config_files_content,)
                
                # Create scan record
                record = ScanRecord(task_id=task_id, 
                            target_url=target_url, 
                            date_time=datetime.now().isoformat(timespec='seconds'))

                # Store scan record
                scan_records.append(record)
                
        self._logger.info("Scan started")

        return scan_records

    def _wait_scan(self, *records: ScanRecord) -> None:
        """
        Wait until the end of the scan(s) and set the ScanRecord.status attribute.
        """

        self._test()

        last_status_str = ""
        status_map = {}
        statuses: Sequence[str] = []

        # Get the scan status and wait...
        # An active scan is considered finished when: it's "paused" or "succeeded" or "failed"
        while not statuses or any(status not in SCAN_STATUS_FINISHED for status in statuses):

            for record in records:
                record.status = self._newapi.scan_status(record.task_id)
                status_map[record.task_id] = record.status
            
            statuses = list(status_map.values())

            status_str = f"{', '.join(statuses)}"
            if status_str != last_status_str:
                self._logger.info(f"Scan status: {status_str}")
                last_status_str = status_str

            sleep(2)

        self._logger.info(f"Scan completed")

    def _scan_metrics(self, *records: ScanRecord) -> None:
        """
        Print metrics and set the ScanRecord.metrics attribute.
        """
        for record in records:
            record.metrics = self._newapi.scan_metrics(record.task_id)
            self._logger.info (f"Scan metrics for {record.target_url} :")
            for k,v in record.metrics.items():
                self._logger.info(f'{k.upper()} = {v}')

    def scan(self, *targets: str, report_type: str = "HTML", 
             report_output_dir: str = "", excluded: str = "", 
             config: str = "", config_file: str = "",
             app_user: str = "", 
             app_pass: str = "", 
             issue_severity:Union[str, Tuple[str, ...]]="All", 
             issue_confidence:Union[str, Tuple[str, ...]]="All", csv:bool=False) -> List[ScanRecord]:
        """
        Launch an active scan, wait until the end and report the results.

        It will use the official REST API to launch the scan, and the `burp-rest-api` to get the pretty HTML report. 
        
        Args
        ----
        targets: 
            Target URL(s) or filename to load target URL(s) from.
            Use 'all' keyword to search in the proxy history and 
            load target URLs from there. 
        report_type:
            Burp scan report type (default: HTML). 
            Use 'none' to skip reporting.
        report_output_dir:
            Directory to store the reports. 
            Store report in temp directory if empty.
        excluded:
            Commas separated values of the URLs to exclude from the scope of the scan.
        config:
            Commas separated values of the scan configuration(s) names to apply.
        config_file:
            Commas separated values of the scan configuration(s) JSON file to read and apply.
        app_user: 
            Application username for authenticated scans.
        app_pass: 
            Application password for authenticated scans
        issue_severity:
            Severity of the scan issues to be included in the report. Acceptable values are All, High, Medium, Low and Information. 
            Multiple values are also accepted if they are comma-separated.
        issue_confidence:
            Confidence of the scan issues to be included in the report. Acceptable values are All, Certain, Firm and Tentative. 
            Multiple values are also accepted if they are comma-separated.
        csv:
            Whether to generate a CSV summary with all issues.
        """

        self._test()
        
        if not targets:
            raise BurpaError("Error: No target(s) specified. ")

        records = self._start_scan(*targets, excluded=excluded, config=config, config_file=config_file,
                        app_user=app_user, app_pass=app_pass)
        
        self._wait_scan(*records)

        self._scan_metrics(*records)

        for record in records:
            # Download the scan issues/reports
            if report_type.lower() != 'none':
                record.report_file_name = self.report(record.target_url, report_type=report_type,
                        report_output_dir=report_output_dir, 
                        issue_severity=issue_severity, 
                        issue_confidence=issue_confidence, 
                        csv=csv, )
                        
        # Raise error if a scan failed
        caption = record.metrics['crawl_and_audit_caption']
        if record.status == "paused":
            raise BurpaError(f"Scan aborted - {record.target_url} : {caption}", records= records)
        elif record.status == "failed":
            raise BurpaError(f"Scan failed - {record.target_url} : {caption}", records= records)

        return records

    def _report(self, target: str, report_type: str, 
                report_output_dir: Optional[str] = None, 
                issue_severity:Union[str, Tuple[str, ...]]="All", 
                issue_confidence:Union[str, Tuple[str, ...]]="All", 
                csv:bool=False) -> List[str]:

        report_path_list = []
        issues = self._api.scan_issues(target)
        
        # Use the same datetime string for the CSV report and the HTMl report
        report_file_datetime_string = time.strftime("%Y%m%d-%H%M", time.localtime())
        
        if report_output_dir:
            os.makedirs(report_output_dir, exist_ok=True)

        if issues:

            self._logger.info(f"Scan issues for {target} :")
            uniques_issues = {
                "Issue: {issueName}, Severity: {severity} ({confidence})".format(**issue)
                for issue in issues
            }
            
            for issue in uniques_issues:
                self._logger.info(f"{issue}")
            
            if (issue_confidence!='All' or issue_severity!='All') and self._api.rest_api_version >= (2,2,0):
                filename_template = "burp-report-filtered_{}_{}.{}"
            else:
                filename_template = "burp-report_{}_{}.{}"
            
            # Write the response body (byte array) to file
            report_file_name = get_valid_filename(filename_template.format(
                report_file_datetime_string, target, report_type.lower()))

            csv_file = os.path.join(report_output_dir or tempfile.gettempdir(), report_file_name)
            report_path_list.append(csv_file)
            with open(csv_file, 'w', encoding='utf8') as output_file:
            
                self._api.write_report(
                    report_type=report_type,
                    url_prefix=target,
                    report_io=output_file,
                    issue_severity=issue_severity, 
                    issue_confidence=issue_confidence,
                )
        
        else:
            self._logger.info(f"No issue could be found for the target {target}")
            issues = []
        
        if csv: 
            # Generate a CSV file with issues
            csv_file_name = get_valid_filename("burp-report-summary_{}_{}.csv".format(
                report_file_datetime_string, target))

            csv_file = os.path.join(report_output_dir or tempfile.gettempdir(), csv_file_name)
            report_path_list.append(csv_file)

            with open(csv_file, 'w', encoding='utf8') as output_file:
                generate_csv(output_file, issues, report_datetime=report_file_datetime_string)
                self._logger.info(f'Generated CSV file at {csv_file}')

        return report_path_list
    
    def report(self, *targets: str, report_type: str = "HTML", 
               report_output_dir: str = "", 
               issue_severity: Union[str, Tuple[str, ...]]="All", 
               issue_confidence: Union[str, Tuple[str, ...]]="All", 
               csv: bool=False) -> List[str]:
        """
        Generate the reports for the specified targets URLs.
        If targets is 'all', generate a report that contains all issues for all targets.  
        """
        file_names = []

        self._test()
        for target in targets:
            file_names += self._report(target, report_type, report_output_dir, issue_severity=issue_severity, 
                issue_confidence=issue_confidence, csv=csv)

        return file_names
    
    def proxy_listen_all_interfaces(self, proxy_port: str) -> None:
        """
        Check the Burp proxy configuration to make sure it's running
        and listening on all interfaces and update the Burp proxy configuration 
        if necessary. 

        You might need this if you want to send traffic to the Burp proxy. 

        Args
        ---
        proxy_port:
            Burp Proxy Port.
        """
        self._test()
        if not self._api.check_proxy_listen_all_interfaces():
            self._api.enable_proxy_listen_all_interfaces(proxy_port=proxy_port)

    def _get_running_scans(self) -> List[str]:
        """
        Construct a list of the running scans names from the existing Task IDs in the Burp server.
        """
        
        # Start at ID 3 and load all scan statuses until we get a BurpaError. 

        tasks: Dict[str, str] = {}
        current_task_id = 3
        while True:
            try:
                task_status = self._newapi.scan_status(str(current_task_id))
            except BurpaError as e:
                break
            else:
                tasks[str(current_task_id)] = task_status
                current_task_id += 1
        
        # Then filter finished scans
        running_tasks = []
        for taskid,status in tasks.items():
            if status in SCAN_STATUS_FINISHED:
                continue
            running_tasks.append(taskid)
        
        return running_tasks
                
    def _stop(self) -> None:
        self._logger.info("Shutting down Burp Suite ...")

        self._api.burp_stop()
        
        while True:
            try:
                self._api.request("docs", requestargs=dict(timeout=0.1))
            except BurpaError:
                break
            else:
                sleep(0.01)

    def stop(self, wait: str = '0', force: bool = False) -> None:
        """
        Shut down the Burp Suite. You can use systemctl or supervisord (Linux) or 
        NSSM (Windows) to automatically restart the
        Burp Suite Service when it stopped running. 

        Args
        ----
        wait:
            If other burpa processes running, number of seconds to wait 
            until all the running scans ends.
        force:
            Stop Burp even if scans are running. 
        """
        self._test()

        start = datetime.now()
        wait_delta = timedelta(seconds=int(wait))

        while True:

            running_scans = self._get_running_scans()
            
            if len(running_scans)==0:
                self._stop()
                break
            elif datetime.now() - start < wait_delta:
                sleep(2)
            else:
                if not force:
                    raise BurpaError(f"Cannot stop Burp because {'these scans are' if len(running_scans)>1 else 'this scan is'} "
                        f"still running: {', '.join(running_scans)}. Use --force to stop anyway.")

                self._stop()
                break

    def _test(self) -> None:
        self._api.verify_uri()
        self._newapi.verify_uri()
    
    def test(self, wait: str = '0') -> None:
        """
        Test if burpa can connect to Burp Suite REST APIs.
        
        Args
        ----
        wait:
            Number of seconds to wait until the Burp REST APIs are accessible.
        """
        start = datetime.now()
        wait_delta = timedelta(seconds=int(wait))

        while True:
            try:
                self._test()
            except BurpaError:
                if datetime.now() - start < wait_delta:
                    sleep(2)
                else:
                    raise
            else:
                self._logger.info(f"Successfully connected to Burp REST APIs")
                break

    def schedule(self, *targets: str, 
                report_type: str = "HTML", 
                report_output_dir: str = "", 
                excluded: str = "", 
                config: str = "",
                app_user: str = "", 
                app_pass: str = "",
                begin_time: str = "22:00",
                end_time: str = "05:00",
                workers: int = 1,
                issue_severity:Union[str, Tuple[str, ...]]="All", 
                issue_confidence:Union[str, Tuple[str, ...]]="All", 
                csv:bool=False) -> None:
        """
        Launch Burp Suite scans between certain times only. 

        Args
        ----
        begin_time: str
            At what time to start the scans.
            (Default "22:00")

            Formats should be:
                hh:mm or hh:mm:ss

        end_time: str
            At what time to end the scans.
            Running scans will finish after the end time.
            (Default "05:00")

        workers: int
            How many asynchronous scans to launch.
        

        See 'burpa scan --help' for details on other arguments. 
        """
        self._test()

        parsed_targets = parse_targets(targets)
        

        perform(self._scheduled_scan, parsed_targets, 
                func_args=dict(begin_time=begin_time, 
                            end_time=end_time,
                            report_type=report_type,
                            report_output_dir=report_output_dir,
                            excluded=excluded,
                            config=config,
                            app_user=app_user,
                            app_pass=app_pass,
                            issue_severity=issue_severity,
                            issue_confidence=issue_confidence, 
                            csv=csv), 
                asynch=workers>1, 
                workers=workers)

    def _scheduled_scan(self, target: str, begin_time: str,
                end_time: str, **kwargs: Any) -> None:

        begin_time_parsed = dateutil.parser.parse(begin_time).time()
        end_time_parsed = dateutil.parser.parse(end_time).time()

        if not is_timenow_between(begin_time_parsed, end_time_parsed):
            self._logger.info(f"It's not the time to use Burp Suite, it's {datetime.now().strftime('%H:%M:%S')}. Sleeping until {begin_time_parsed.strftime('%H:%M:%S')}.")

        while not is_timenow_between(begin_time_parsed, end_time_parsed):
            sleep(5)

        self._logger.info(f"Starting scan on target: '{target}' at {datetime.now().isoformat(timespec='seconds')}")
        self.scan(target, **kwargs)
    
    def version(self) -> None:
        """
        Print burpa version and exit.
        """
        print(f"burpa version {__version__}")

def generate_csv(io: TextIO, issues: List[Dict[str, Any]], report_datetime:str) -> None:
    if not issues:
        return
    
    # Add CWE information
    jsondata = json.loads(importlib_resources.read_text('burpa', 'issue_defs.json'))

    for i in issues:
        # Discard request/response data.
        i.pop('httpMessages')

        # Set the CWE references
        try:
            classifications = jsondata[str(i['issueType'])]
        except KeyError:
            i['references'] = ''
        else:
            i['references'] = classifications
        
        # Strip HTML tags from report issues
        for k in i:
            if k in ('remediationBackground', 'remediationDetail', 'issueDetail', 'issueBackground'):
                v = i[k]
                if isinstance(v, str):
                    i[k] = strip_tags(v)
        
        # Add the report datetime
        i['reportDateTime'] = report_datetime
    
    fc = csvlib.DictWriter(io, fieldnames=issues[0].keys(), dialect='excel', quoting=csvlib.QUOTE_ALL)
    fc.writeheader()
    fc.writerows(issues)

def main() -> None:

    # Make Python Fire not use a pager when it prints a help text
    fire.core.Display = lambda lines, out: print(*lines, file=out)
    
    try:
        fire.Fire(Burpa, name='burpa')
    
    except BurpaError as e:

        logger = getLogger('Burpa')

        logger.debug(traceback.format_exc())

        logger.error(e)

        sys.exit(1)

if __name__ == '__main__':
    main()
