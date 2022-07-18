from logging import Logger
import os
import requests
import tempfile
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
import attr

from string import Template

from ._error import BurpaError
from ._api_base import ApiBase
from ._utils import get_valid_filename, setup_logger


@attr.s(auto_attribs=True)
class BurpRestApiClient(ApiBase):
    """
    Interface for the third party extension `burp-rest-api <https://github.com/vmware/burp-rest-api>`_. 

    Args
    ----
    proxy_url: str
    api_port: str
        Defaults to 8090
    """

    proxy_url: str
    api_port: str = "8090"
    api_key: Optional[str] = None
    _logger: Logger = attr.ib(factory=lambda : setup_logger('BurpRestApiClient'))

    PARAMS = {
        "get_config": (  "get", 
                            "/burp/configuration",
                            None
                         ),

        "enable_proxy_listen_all_interfaces": (  "put", 
                            "/burp/configuration",
                            Template("""
                            {
                                "proxy": {
                                    "request_listeners": [{
                                        "certificate_mode": "per_host",
                                        "listen_mode": "all_interfaces",
                                        "listener_port": $proxy_port,
                                        "running": True,
                                        "support_invisible_proxying": True
                                    }]
                                }
                            }
                            """)
                         ),
        
        "get_proxy_history": (  "get", 
                            "/burp/proxy/history",
                            None
                         ),
        
        "include_scope": (  "put", 
                            Template("/burp/target/scope?url=$url"),
                            None
                         ),
        
        "exclude_scope": (  "delete", 
                            Template("/burp/target/scope?url=$url"),
                            None
                         ),
        
        "is_in_scope": (  "get", 
                            Template("/burp/target/scope?url=$url"),
                            None
                         ),
        
        "active_scan": (  "post", 
                            Template("/burp/scanner/scans/active?baseUrl=$base_url"),
                            None
                         ),
        
        "delete_scan_queue": (  "delete", 
                            "/burp/scanner/scans/active",
                            None
                         ),
        
        "scan_status": (  "get", 
                            "/burp/scanner/status",
                            None
                         ),
        
        "scan_issues": (  "get", 
                            Template("/burp/scanner/issues?urlPrefix=$url_prefix"),
                            None
                         ),

        "all_scans_issues": (  "get", 
                            "/burp/scanner/issues",
                            None
                         ),
        
        "scan_report": (  "get", 
                            Template("/burp/report?urlPrefix=$url_prefix&reportType=$report_type"),
                            None
                         ),
        
        "all_scans_report": (  "get", 
                            Template("/burp/report?reportType=$report_type"),
                            None
                         ),

        "burp_stop": (  "get", 
                         "/burp/stop",
                         None
                         ),
        
        "docs": (  "get", 
                         "/v2/api-docs",
                         None
                         ),
        
        "versions": (  "get", 
                         "/burp/versions",
                         None
                         ),
    }

    @property
    def proxy_uri(self) -> str:
        return f"{self.proxy_url}:{self.api_port}"

    def request(self, request: str, request_args: Optional[Dict[str, Any]] = None, 
                **kwargs: Union[str, List[Any], Tuple[Any, ...], Dict[str, Any]]) -> requests.Response:
        
        # Set API-KEY header if self.api_key is not None.
        if self.api_key is not None:
            request_args = request_args or {}
            headers = request_args.setdefault('headers', {})
            headers['API-KEY'] = self.api_key

        return super().request(request, request_args, **kwargs)

    def check_proxy_listen_all_interfaces(self) -> bool:
        """
        Check the Burp proxy configuration to make sure it's running
        and listening on all interfaces
        """
        # Because of an issue in burp-rest-api
        # (https://github.com/vmware/burp-rest-api/issues/17),
        # we can't load our config when running the Burp (the default
        # config getting set). So we need to set the proxy listen_mode
        # using the API
        self._logger.info("Checking the Burp proxy configuration ...")
        try:
            r = self.request('get_config')
        except BurpaError as e:
            raise BurpaError(f"Error retrieving the Burp configuration: {e}") from e
        else:
            config = r.json()
            running = config['proxy']['request_listeners'][0]['running']
            listen_mode = config['proxy']['request_listeners'][0]['listen_mode']
            if running and listen_mode == "all_interfaces":
                self._logger.info("Proxy configuration is OK")
                return True
            else:
                self._logger.info("Proxy configuration needs to be updated")
                return False


    def enable_proxy_listen_all_interfaces(self, proxy_port: str) -> None:
        """Update the Burp proxy configuration to listen on all interfaces"""
        self._logger.info("Updating the Burp proxy configuration to listen on all interfaces...")
        try:
            self.request('enable_proxy_listen_all_interfaces', proxy_port=proxy_port)
            self._logger.info("Proxy configuration updated")
        except BurpaError as e:
            raise BurpaError(f"Error updating the Burp configuration: {e}") from e


    def proxy_history(self) -> Optional[List[str]]:
        """Retrieve the Burp proxy history"""
        self._logger.info("Retrieving the Burp proxy history ...")
        try:
            r = self.request('get_proxy_history')
        
        except BurpaError as e:
            raise BurpaError(f"Error retrieving the Burp proxy history: {e}") from e
        
        else:
            resp = r.json()
            if resp['messages']:
                # Unique list of URLs
                host_set = {"{protocol}://{host}".format(**i)
                            for i in resp['messages']}
                self._logger.info(f"Found {len(host_set)} unique targets in proxy history")
                return list(host_set)
            else:
                self._logger.info("Proxy history is empty")
                return None

    def include(self, *targets: str) -> None:
        """
        Add a target to the scope. 
        """
        # Update the scope (include/exclude)
        self._update_scope(
            action='include',
            scope=targets
        )

    def exclude(self, *targets: str) -> None:
        """
        Remove a target from the scope.
        """
        # Update the scope (include/exclude)
        self._update_scope(
            action='exclude',
            scope=targets
        )

    def _update_scope(self, action: str, scope: Iterable[str]) -> None:
        """Include in scope / Exclude from scope"""
        if action == "include":
            for i in scope:
                try:
                    self.request('include_scope', url=i)
                    self._logger.info(f"{i} has been included to the scope")
                
                except BurpaError as e:
                    raise BurpaError(f"Error updating the target scope: {e}")

        elif action == "exclude":
            for i in scope:
                try:
                    self.request('exclude_scope', url=i)
                    self._logger.info(f"{i} has been excluded from the scope")
                
                except BurpaError as e:
                    raise BurpaError(f"Error updating the target scope: {e}")


    def is_in_scope(self, url: str) -> bool:
        """Query whether a URL is within the current scope"""
        try:
            r = self.request('is_in_scope', url=url)
        except BurpaError as e:
            raise BurpaError(f"Error checking the target scope: {e}") from e

        else:
            resp = r.json()
            if resp['inScope']:
                self._logger.debug("{} is in the scope".format(url))
                return True
            else:
                return False


    def active_scan(self, base_url: str) -> None:
        """
        Send a URL to Burp to perform active scan. 
        """
        try:
            self.request('active_scan', base_url=base_url)
            self._logger.info(f"{base_url} Added to the scan queue")
        except BurpaError as e:
            raise BurpaError(f"Error adding {base_url} to the scan queue: {e}") from e


    def scan_status(self) -> int:
        """
        Get the percentage completed for the scan queue items
        """
        try:
            r = self.request('scan_status')
        except BurpaError as e:
            raise BurpaError(f"Error getting the scan status: {e}") from e

        else:
            resp = r.json()
            assert isinstance(resp['scanPercentage'], int)
            return resp['scanPercentage']


    def scan_issues(self, url_prefix: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get list of scan issues for URLs
        matching the specified urlPrefix
        """
        try:
            if url_prefix.upper() == "ALL":
                r = self.request('all_scans_issues')
            else:
                r = self.request('scan_issues', url_prefix=url_prefix)

        except BurpaError as e:
            raise BurpaError(f"Error getting {url_prefix} scan issues: {e}") from e

        else:
            resp = r.json()
            issues = resp['issues']
            if issues:
                assert isinstance(issues, list)
                return issues
            else:
                return None


    def scan_report(self, report_type: str, url_prefix: str, 
                    report_output_dir: Optional[str] = None) -> str:
        """
        Downloads the scan report with current Scanner issues for
        URLs matching the specified urlPrefix (HTML/XML). 

        """

        try:
            if url_prefix.upper() == "ALL":
                r = self.request('all_scans_report', report_type=report_type.upper())
            else:
                r = self.request('scan_report', url_prefix=url_prefix, report_type=report_type.upper())

        except BurpaError as e:
            raise BurpaError(f"Error downloading the scan report for target {url_prefix}: {e}") from e

        else:
            self._logger.info(f"Downloading HTML/XML report for {url_prefix}")
            # Write the response body (byte array) to file
            file_name = get_valid_filename("burp-report_{}_{}.{}".format(
                time.strftime("%Y%m%d-%H%M%S", time.localtime()),
                url_prefix,
                report_type.lower()
                )
            )
            file = os.path.join(report_output_dir or tempfile.gettempdir(), file_name)
            with open(file, 'w', encoding='utf-8') as f:
                f.write(r.text)
            self._logger.info(f"Scan report saved to {file}")
            return file


    def burp_stop(self) -> None:
        """Stop the Burp Suite"""
        # Because of an issue in burp-rest-api
        # (https://github.com/vmware/burp-rest-api/issues/15),
        # we can't Reset/Restore the Burp State, so we need to stop
        # the Burp after the scan to reset the state.
        # e.g. You can use a supervisord configuration to restart the
        # Burp when it stopped running:
        #   [program:burp-rest-api]
        #   command=java -jar /opt/burp-rest-api/build/libs/burp-rest-api-1.0.0.jar
        #   directory=/opt/burp-rest-api/build/libs
        #   redirect_stderr=true
        #   stdout_logfile=/var/log/burp-rest-api.log
        #   autorestart=true
        #   user=burpa
        # 2021: The issue is not fixed: https://github.com/vmware/burp-rest-api/issues/82

        try:
            self.request('burp_stop')
            self._logger.info("Burp is stopped")
        except BurpaError as e:
            raise BurpaError(f"Error stopping the Burp Suite: {e}") from e
    
    def verify_uri(self) -> None:
        """
        Raise
        -----
        BurpaError
            If cannot connect to burp-rest-api extension URI.
        """
        try:
            self.request('docs')

        except BurpaError as e:
            raise BurpaError(f"Cannot connect to Burp Suite: {e}") from e


