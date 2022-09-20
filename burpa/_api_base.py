from typing import Any, Dict, Optional, Tuple, Union, List
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
                     requestargs:  Optional[Dict[str, Any]]=None,
                     ) -> requests.Response:
        r = None
        
        try:

            self._logger.debug(f"Requesting HTTP {http_method.upper()}: {url}, body={data}")

            _request_args: Dict[str, Any] = dict(method=http_method, url=url, json=data)
            if requestargs: _request_args.update(requestargs)

            r = requests.request(**_request_args)
            
            self._logger.debug(f"Got Response: {r.text}")

            r.raise_for_status()
        
        except requests.exceptions.RequestException as e:
            raise BurpaError(f"HTTP Error: {e}. Response: {getattr(e.response, 'text', 'None')}", response=e.response) from e
        
        else:
            return r
    
    def _serialize_request_kwargs(self, kwargs:Dict[str, Union[str, List[Any], Tuple[Any, ...], Dict[str, Any]]]) -> Dict[str, str]:
        serialized = {}
        for k in kwargs:
            if isinstance(kwargs[k], (list, dict)):
                serialized[k] = json.dumps(kwargs[k])
            elif isinstance(kwargs[k], (tuple)):
                serialized[k] = json.dumps(list(kwargs[k]))
            else:
                v = kwargs[k]
                assert isinstance(v, str)
                serialized[k] = v
            
        return serialized

    def request(self, request: str, requestargs:  Optional[Dict[str, Any]]=None, 
                **kwargs: Union[str, List[Any], Tuple[Any, ...], Dict[str, Any]]) -> requests.Response:
        """
        Arguments
        ---------
        request: 
            Name keyword corresponding to the request name in `PARAMS` mapping.
        requestargs:
            Arguments to pass to `requests.request`.
        **kwargs:
            Template substitutions. This can be a string, a dict or a list. 
            If it's a dict or a list or tuple, it will be automatically serialed as JSON before getting 
            interpolated with template place holders.
        """

        request_template = self.PARAMS[request]

        http_method, url_part, data = request_template

        serialized_request_kwargs = self._serialize_request_kwargs(kwargs)

        if data != None:

            if isinstance(data, Template):
                data = data.substitute(**serialized_request_kwargs)
            
            assert isinstance(data, str)

            self._logger.debug(f"Constructing API call from template: {http_method}, {url_part}, {data}")

            built_data = json.loads(data)
        else:
            built_data = None
        
        if isinstance(url_part, Template):
            built_url_part = url_part.substitute(**serialized_request_kwargs)
        elif isinstance(url_part, str):
            built_url_part = url_part
        else:
            raise TypeError(f"Invalid API endpoint value, should be a str or a Template, not: {url_part}")

        assert built_data is None or isinstance(built_data, dict)
        
        response = self._api_request(http_method=http_method, 
                                     url=f"{self.proxy_uri}{built_url_part}", 
                                     data=built_data, requestargs=requestargs)

        return response
