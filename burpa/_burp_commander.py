from typing import Any, Dict, Optional
import attr
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
                                    "include": [{"rule": "$base_url", "type":"SimpleScopeDef"}]
                                }
                            }
                            """)
                        ),

        'active_scan_with_auth': ("post",
                        "/scan",
                        Template("""
                            {
                                "urls" : ["$base_url"],
                                "scope": {
                                    "include": [{"rule": "$base_url", "type":"SimpleScopeDef"}]
                                },
                                "application_logins": [{
                                    "password": "$password",
                                    "username": "$username"
                                    }]
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
                    password: Optional[str] = None, ) -> str:
        """
        Send a URL to Burp to perform active scan, the difference with 
        `BurpRestApiClient.active_scan` is that this method accepts username/password for authenticated scans.

        Returns
        -------
        The scan ID if it was successfuly launched
        """

        if username and not password:
            raise BurpaError(f"Error: Missing password for authenticated scan against {base_url}.")
        
        elif not username and password:
            raise BurpaError(f"Error: Missing username for authenticated scan against {base_url}.")
        
        try:    
            
            if username and password:
                #craft authenticated response
                print("[+] Initiating authenticated scan...")
                r = self.request('active_scan_with_auth', base_url=base_url, 
                                username=username, password=password)
            else:
                # craft unauthenticated response
                print("[+] Initiating unauthenticated scan...")
                r = self.request('active_scan', base_url=base_url)

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
