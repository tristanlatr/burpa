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


import time
import os
import sys
import traceback
import tempfile
from typing import  Any, Dict, List, Optional
from urllib.parse import urlparse

import fire # type: ignore[import]
from dotenv import load_dotenv, find_dotenv

from ._burp_rest_api_client import BurpRestApiClient
from ._burp_commander import BurpCommander
from ._error import BurpaError
from .__version__ import __version__, __author__


# ################[ configuration ]################
# Slack Report
SLACK_REPORT = False
SLACK_API_TOKEN = ""
SLACK_CHANNEL = "#burpa"
###################################################

ASCII = r"""            __                          
           / /_  __  ___________  ____ _
          / __ \/ / / / ___/ __ \/ __ `/
         / /_/ / /_/ / /  / /_/ / /_/ / 
        /_.___/\__,_/_/  / .___/\__,_/  
                        /_/             
         burpa version %s 
"""%(__version__)

class Burpa:
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
    """
    def __init__(self, api_url: str = "",
                api_port: str = "8090",
                new_api_url: str = "",
                new_api_port: str = "1337",
                new_api_key: str = ""):

        api_url = ensure_scheme(os.getenv('BURP_API_URL') or api_url)
        api_port = os.getenv('BURP_API_PORT') or api_port
        new_api_url = ensure_scheme(os.getenv('BURP_NEW_API_URL') or new_api_url)
        new_api_port = os.getenv('BURP_NEW_API_PORT') or new_api_port
        new_api_key = os.getenv('BURP_NEW_API_KEY') or new_api_key

        if not api_url:
            raise BurpaError("Error: At least --api_url or 'BURP_API_URL' environment variable must be configured. ")

        self._api: BurpRestApiClient = BurpRestApiClient(proxy_url=api_url, api_port=api_port)
        if new_api_url:
            self._newapi = BurpCommander(proxy_url=new_api_url,
                                  api_port=new_api_port,
                                  api_key=new_api_key or None)
            
        else:
            # Create the BurpCommander with the same URL as BurpRestApiClient...
            self._newapi = BurpCommander(proxy_url=api_url,
                            api_port=new_api_port,
                            api_key=new_api_key or None)

    def scan(self, *targets: str, report_type: str = "HTML", 
             report_output_dir: str = "", 
             app_user: str = "", 
             app_pass: str = "", ) -> None:
        """
        Launch an active scan, wait until the end and report the results.

        It will use the official REST API to launch the scan, and the `burp-rest-api` to get the pretty HTML report. 
        
        Args
        ----
        targets: 
            Define spcefic target URL(s) for the scan.
            Use 'all' keyword to search in the proxy history and 
            load target URLs from there. 
        report_type:
            Burp scan report type (default: HTML)
        report_output_dir:
            Directory to store the reports.
        app_user: 
            Application username for authenticated scans.
        app_pass: 
            Application password for authenticated scans
        """

        self.test()
        
        if targets:
            
            scanned_urls_map: Dict[str, Dict[str, Any]] = {}
            authenticated_scans = app_pass and app_user

            # Start the scans

            for target_url in targets:
                
                if target_url.upper() == "ALL":
                    history = self._api.proxy_history()
                    if history:
                        self.scan(*history, 
                                report_type=report_type,
                                report_output_dir=report_output_dir,
                                app_user=app_user,
                                app_pass=app_pass)
                else:
                    
                    if authenticated_scans:
                        
                        task_id = self._newapi.active_scan(target_url, 
                                                username=app_user, 
                                                password=app_pass)
                        
                    else:
                        task_id= self._newapi.active_scan(target_url)
                    
                    # Store scan infos
                    scanned_urls_map[target_url] = {}
                    scanned_urls_map[target_url]['task_id'] = task_id
            
            print("[+] Scan started")

            # Get the scan status and wait...
            # An active scan is considered finished when: it's "paused" or "succeeded"

            last_status_str = ""
            statuses: List[str] = []
            
            while not statuses or any(status not in ("paused", "succeeded") for status in statuses):

                time.sleep(5)
                for url in scanned_urls_map:
                    scanned_urls_map[url]['status'] = self._newapi.scan_status(scanned_urls_map[url]['task_id'])
                
                statuses = [scanned_urls_map[url]['status'] for url in scanned_urls_map]

                status_str = f"{', '.join(statuses)}"
                if status_str != last_status_str:
                    print(f"[-] Scan status: {status_str}")
                    last_status_str = status_str

            print(f"[+] Scan completed")

            for url  in scanned_urls_map:
                
                # Print metrics
                scanned_urls_map[url]['metrics'] = self._newapi.scan_metrics(scanned_urls_map[url]['task_id'])
                print (f'[+] Scan metrics for {url} :')
                print('\n'.join(f'  - {k.upper()} = {v}' for k,v in scanned_urls_map[url]['metrics'].items()))
            
            if scanned_urls_map:

                # Print/download the scan issues/reports
                self.report(*list(scanned_urls_map), report_type=report_type,
                        report_output_dir=report_output_dir)
        
        else:
            raise BurpaError("Error: No target(s) specified. ")

    def _report(self, target: str, report_type: str, report_output_dir: Optional[str] = None,
                slack_report: bool = False, slack_api_token: Optional[str] = None) -> bool:
        
        if self._api.scan_issues(target):
            
            if report_output_dir:
                os.makedirs(report_output_dir, exist_ok=True)
            
            rfile = self._api.scan_report(
                report_type=report_type,
                url_prefix=target,
                report_output_dir=report_output_dir
            )
            
            if slack_report:
                if not slack_api_token:
                    raise BurpaError("Error: '--slack_api_token' must be provided to send reports to Slack.")
                upload_slack_report(api_token=slack_api_token,
                                fname=rfile)
            
            return True
        
        else:
            print(f"[-] No issue could be found for the target {target}")
            return False
    
    def report(self, *targets: str, report_type: str = "HTML", 
               report_output_dir: str = "", slack_report: bool = False, 
               slack_api_token: str = "") -> None:
        """
        Generate the reports for the specified targets. 
        If targets is 'all', generate a report that contains all issues for all targets.  
        """
        self.test()
        for target in targets:
            self._report(target, report_type, report_output_dir, 
                         slack_report, slack_api_token)

    
    def proxy_listen_all_interfaces(self, proxy_port: str) -> None:
        """
        Check the Burp proxy configuration to make sure it's running
        and listening on all interfaces and update the Burp proxy configuration 
        if necessary. 

        You might need this if you want to send traffic to the Burp proxy. 

        Args
        ---
        proxy_port
            Burp Proxy Port
        """
        self.test()
        if not self._api.check_proxy_listen_all_interfaces():
            self._api.enable_proxy_listen_all_interfaces(proxy_port=proxy_port)

    def stop(self, force: bool = False) -> None:
        """
        Shut down the Burp Suite. You can use systemctl or supervisord (Linux) or 
        NSSM (Windows) to automatically restart the
        Burp Suite Service when it stopped running. By default do not stop if scans are still running. 

        Args
        ----
        force:
            Stop the Burp even if scans are running. 
        """
        self.test()
        if self._api.scan_status() != 100:
            if not force:
                raise BurpaError("Error: Not stopping Burp Suite because scans are still running, use --force to stop Burp anyway. ")
            
            print("[!] Shutting down the Burp Suite even if scans are still running ...")
        
        else:
            print("[+] Shutting down the Burp Suite ...")
        
        self._api.burp_stop()

    
    def test(self) -> None:
        """Test if burpa can connect to Burp Suite REST API(s)"""
        self._api.verify_uri()
        # print(f"[+] Successfuly connected to Burp REST API Extension at: {self._api.proxy_url}:{self._api.api_port}")
        self._newapi.verify_uri()
        # print(f"[+] Successfuly connected to Burp official REST API at: {self._newapi.proxy_url}:{self._newapi.api_port}")


def upload_slack_report(api_token: str, fname: str) -> None:
    from slackclient import SlackClient #type: ignore[import]
    file = os.path.join(tempfile.gettempdir(), fname)
    sc = SlackClient(api_token)
    response = sc.api_call(
        'files.upload',
        channels=SLACK_CHANNEL,
        filename=fname,
        file=open(file, 'rb'),
        title="Burp Scan Report"
    )
    if response['ok']:
        print("[+] Burp scan report uploaded to Slack")
    else:
        print(f"[-] Error sending Slack report: {response['error']}")


def ensure_scheme(url: str) -> str:

    if url:
        # Strip URL string
        url = url.strip()
        # Format URL with scheme indication
        p_url = list(urlparse(url))
        if p_url[0] == "":
            url = f"http://{url}"
    return url

def main() -> None:
    print(ASCII)

    # Make Python Fire not use a pager when it prints a help text
    # 
    fire.core.Display = lambda lines, out: print(*lines, file=out)

    file = find_dotenv()

    if file:
        print(f"[+] Loading .env file {file}")
        load_dotenv(file)
    
    try:
        fire.Fire(Burpa, name='burpa')
    
    except BurpaError as e:

        if os.getenv("BURPA_DEBUG"):
            traceback.print_exc()

        print()
        print('--------------- ERROR ---------------')
        print()

        print(e)
        print()
        sys.exit(1)

if __name__ == '__main__':
    main()
