from typing import Any, Dict, Optional, Tuple, Union
import requests
import json
import logging
from string import Template

from ._error import BurpaError

class ApiBase:
    """
    Base class for API wrapper classes that works by storing the API calls in templates. 
    """

    PARAMS: Dict[str, Tuple[str, Union[str, Template], Union[str, Template, None]]] = {}

    _logger: logging.Logger

    @property
    def proxy_uri(self) -> str:
        raise NotImplementedError()

    def _api_request(self,
                     http_method: str,
                     url: str,
                     data: Optional[Dict[str, Any]]=None,
                     request_args:  Optional[Dict[str, Any]]=None,
                     ) -> requests.Response:
        r = None
        
        try:

            self._logger.debug(f"Requesting HTTP {http_method.upper()}: {url}, body={data}")

            _request_args: Dict[str, Any] = dict(method=http_method, url=url, json=data)
            if request_args: _request_args.update(request_args)

            r = requests.request(**_request_args)
            
            self._logger.debug(f"Got Response: {r.text}")

            r.raise_for_status()
        
        except requests.exceptions.RequestException as e:
            raise BurpaError(f"HTTP Error: {e}. Response: {r.text if r is not None else 'None'}") from e
        
        else:
            return r

    def request(self, request: str, timeout: float = 10,  **kwargs: str) -> requests.Response:
        """
        Arguments
        ---------
        request: 
            Name keyword corresponding to the request name in `PARAMS` mapping.
        **kwargs:
            Template substitutions. 
        """

        request_template = self.PARAMS[request]

        http_method, url_part, data = request_template

        if data != None:

            if isinstance(data, Template):
                data = data.substitute(**kwargs)
            
            assert isinstance(data, str)

            self._logger.debug(f"Constructing API call from template: {http_method}, {url_part}, {data}")

            built_data = json.loads(data)
        else:
            built_data = None
        
        if isinstance(url_part, Template):
            built_url_part = url_part.substitute(**kwargs)
        elif isinstance(url_part, str):
            built_url_part = url_part
        else:
            raise TypeError(f"Invalid API endpoint value, should be a str or a Template, not: {url_part}")

        assert built_data is None or isinstance(built_data, dict)
        
        response = self._api_request(http_method=http_method, 
                                     url=f"{self.proxy_uri}{built_url_part}", 
                                     data=built_data, request_args=dict(timeout=timeout))

        return response
