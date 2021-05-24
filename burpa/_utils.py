import re
import io
import csv
import sys
import logging
from urllib.parse import urlparse
from pathlib import Path
from typing import Iterable, Iterator, List

def get_valid_filename(s: str) -> str:
    '''Return the given string converted to a string that can be used for a clean filename.  Stolen from Django I think'''
    s = str(s).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w.]', '', s)[:100] # Let's cap the filename lenght to 100 chars.


def parse_commas_separated_str(string: str) -> List[str]:
    r = []
    if string:
        for row in csv.reader(io.StringIO(string)):
            r.extend(row)
    return r

def parse_targets(targets: Iterable[str]) -> Iterator[str]:
    for target in targets:
        
        # Check if arg is a URL or special keyowrd
        if target.lower().startswith(('http', 'all')):
            yield target
        else:
            try:
                path = Path(target)
                # Try to load the URL from the file contents
                if path.is_file():
                    for line in path.read_text().splitlines():
                        line = line.strip()
                        # Ignore lines with comments
                        if line and not line.startswith(('#', ';')):
                            yield line
                else:
                    yield target
            except Exception as e: # any errors that might be raised because of the file reading.
                raise RuntimeError(f"Cannot read target: '{target}'. Targets should be URLs (starting with http:// or https://) or filepaths to load URLs from or 'all' to load URLs from proxy history.") from e

def ensure_scheme(url: str) -> str:
    
    if url:
        # Strip URL string
        url = url.strip()
        # Format URL with scheme indication
        p_url = urlparse(url)
        if not p_url.scheme:
            url = f"http://{url}"
    return url

# Setup stdout logger
def get_logger(
    name: str,
    verbose: bool = False,
    quiet: bool = False,
    ) -> logging.Logger:

    # format_string = "%(asctime)s - %(levelname)s (%(name)s) - %(message)s"
    format_string = "%(levelname)s - %(message)s"

    if verbose:
        verb_level = logging.DEBUG
    elif quiet:
        verb_level = logging.ERROR
    else:
        verb_level = logging.INFO

    log = logging.getLogger(name)

    log.setLevel(verb_level)
    std = logging.StreamHandler(sys.stdout)
    std.setLevel(verb_level)
    std.setFormatter(logging.Formatter(format_string))
    log.handlers = []
    log.addHandler(std)

    return log
