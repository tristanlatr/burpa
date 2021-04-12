from typing import Any, Dict, Iterable, Optional
import attr
import json
from string import Template

from ._error import BurpaError
from ._api_base import ApiBase

# Ressource: https://laconicwolf.com/2018/08/27/exploring-the-burp-suite-api/

@attr.s(auto_attribs=True)
class BurpCommander(ApiBase):
    """
    Interface for the Burp Suite Official REST API, 
    based on ruby code `burpcommander <https://github.com/pentestgeek/burpcommander>`_. 

    Args
    ----
    proxy_url: str
    api_port: str
        Defaults to 1337
    api_key: Optional[str]
    """
    proxy_url: str
    api_port: str = "1337"
    api_key: Optional[str] = None

    PARAMS = {
        'active_scan': ("post",
                        "/scan",
                        Template("""{ 
                            "urls" : ["$base_url"],
                            "scope": {
                                    "include": [{"rule": "$base_url", "type":"SimpleScopeDef"}],
                                    "exclude": $exclude_rules
                                },
                            "scan_configurations": $scan_configurations
                            }
                            """)
                        ),

        'active_scan_with_auth': ("post",
                        "/scan",
                        Template("""
                            {
                                "urls" : ["$base_url"],
                                "scope": {
                                    "include": [{"rule": "$base_url", "type":"SimpleScopeDef"}],
                                    "exclude": $exclude_rules
                                },
                                "application_logins": [{
                                    "password": "$password",
                                    "username": "$username"
                                    }],
                                "scan_configurations": $scan_configurations
                            }
                            """)
                        ),
        
        'scan_details': ("get",
                        Template("/scan/$task_id"),
                        None),
        
        'docs': ("get",
                 "/",
                 None),
    }

   

    @property
    def proxy_uri(self) -> str:
        return f"{self.proxy_url}:{self.api_port}{'/' if self.api_key else ''}{self.api_key if self.api_key else ''}/v0.1"

    def active_scan(self, base_url: str, username: Optional[str] = None, 
                    password: Optional[str] = None, excluded_urls: Optional[Iterable[str]] = None, 
                    config_names: Optional[Iterable[str]] = None) -> str:
        """
        Send a URL to Burp to perform active scan, the difference with 
        `BurpRestApiClient.active_scan` is that this method accepts username/password for authenticated scans.

        Parameters
        ----------
        base_url
            URL to scan. 
        username
            Username for authenticated scan.
        password
            Password for authenticated scan.
        excluded_urls
            List of urls to exclude from the scope. 
        config_names
            List of configuration names to apply.

        Returns
        -------
        The scan ID if it was successfuly launched
        """

        def get_exclude_rules(urls: Iterable[str]) -> str:
            return json.dumps(list({"rule": url, "type": "SimpleScopeDef"} for url in urls))
        
        def get_scan_configurations(names: Iterable[str]) -> str:
            return json.dumps(list({"name": name, "type": "NamedConfiguration"} for name in names))

        if username and not password:
            raise BurpaError(f"Error: Missing password for authenticated scan against {base_url}.")
        
        elif not username and password:
            raise BurpaError(f"Error: Missing username for authenticated scan against {base_url}.")
        
        try:

            scan_configurations = '[]'
            if config_names:
                print(f"[-] Using scan configuration(s): '{', '.join(config_names)}'")
                scan_configurations = get_scan_configurations(config_names)

            exclude_rules = '[]'
            if excluded_urls:
                print(f"[-] URLs excluded from scope: {', '.join(excluded_urls)}")
                exclude_rules = get_exclude_rules(excluded_urls)
            
            if username and password:
                #craft authenticated response
                r = self.request('active_scan_with_auth', base_url=base_url, 
                            username=username, password=password, 
                            exclude_rules=exclude_rules, scan_configurations=scan_configurations)

            else:
                # craft unauthenticated response
                print("[+] Initiating unauthenticated scan...")
                r = self.request('active_scan', base_url=base_url,
                                exclude_rules=exclude_rules, scan_configurations=scan_configurations)

            task_id = r.headers.get("location", None)
            
            if task_id is None:
                raise BurpaError(f"Error launching scan, cannot retrieve task id, 'location' header is None: {r}")
            
            print(f"[-] {base_url} Added to the scan queue, ID {task_id}")
            return task_id
        
        except BurpaError as e:
            raise BurpaError(f"Error adding {base_url} to the scan queue: {e}") from e


    def verify_uri(self) -> bool:
        """
        Raise
        -----
        BurpaError
            If cannot connect to Burp Official REST API.
        """
        try:
            self.request('docs')
        except BurpaError as e:
            raise BurpaError(f"Error while verifying Burp Official REST API URI: {e}") from e
        else:
            return True
    
    def scan_details(self, task_id: str) -> Dict[str, Any]:
        """Get the scan details: Status, Metrics, Issues etc."""
        try:
            r = self.request('scan_details', task_id=task_id)
        except BurpaError as e:
            raise BurpaError(f"Error getting the scan details: {e}") from e
        else:
            resp = r.json()
            return resp # type: ignore[no-any-return]

    def scan_status(self, task_id: str) -> str:
        """Get the status of a specific scan ID"""
        resp = self.scan_details(task_id)
        scan_status = resp['scan_status']
        assert isinstance(scan_status, str)
        return scan_status
    
    def scan_metrics(self, task_id: str) -> Dict[str, Any]:
        """Get the metrics of a specific scan ID"""
        resp = self.scan_details(task_id)
        scan_metrics = resp['scan_metrics']
        return scan_metrics # type: ignore[no-any-return]
