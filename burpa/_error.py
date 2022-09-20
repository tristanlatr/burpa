
from typing import Optional
import requests

class BurpaError(Exception):
    """
    Exception raised when there is an error in a burpa command. 
    """
    def __init__(self, *args: object, response:Optional[requests.Response]=None) -> None:
        super().__init__(*args)
        self.response = response

