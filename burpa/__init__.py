"""
Welcome to the ``burpa`` API documentation!

Usage
-----
from burpa import Burpa
burp = Burpa(api_url="localhost")
burp.scan('http://mysite.com', report_output_dir='.')


:see: `burpa.Burpa`
"""

from ._burpa import Burpa
from ._error import BurpaError
from ._burp_rest_api_client import BurpRestApiClient
from ._burp_commander import BurpCommander

__all__ = ["Burpa", "BurpRestApiClient", "BurpCommander", "BurpaError"]
