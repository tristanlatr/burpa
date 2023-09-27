from typing import TYPE_CHECKING, Optional, List

if TYPE_CHECKING:
    from ._burpa import ScanRecord

class BurpaError(Exception):
    """
    Exception raised when there is an error in a burpa command. 
    """
    def __init__(self, msg: str, records:Optional[List['ScanRecord']]=None) -> None:
        super().__init__(msg)
        self.records = records
        """
        If the burp scan ended in a failed state, this attribute will old 
        a list of scan records. They can still contain some valuable informations.
        """
