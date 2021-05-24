#! /usr/bin/env python3
"""
schedule - Wrapper to schedule Burp scans to run at certain times only.
"""

import functools
import traceback
import os
import sys
import time
import datetime
import concurrent.futures
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional

import dateutil.parser
from filelock import FileLock
import fire

from burpa import Burpa, BurpaError
from burpa._utils import parse_targets, get_logger
from burpa._burpa import TEMP_DIR

def perform(func: Callable[..., Any], elements: Iterable[Any], 
            func_args:Optional[Dict[str, Any]]=None, asynch: bool=False,  
            workers: Optional[int]=None , ) -> List[Any]:
        """
        Wrapper arround executable and the data list object.
        Will execute the callable on each object of the list.
        Parameters:  
        
        - `func`: callable stateless function. func is going to be called like `func(item, **func_args)` on all items in data.
        - `elements`: Perfom the action on the elements in the list.
        - `func_args`: dict that will be passed by default to func in all calls.
        - `asynch`: execute the task asynchronously
        - `workers`: mandatory if asynch is true.  
        Returns a list of returned results
        """
        if not callable(func) :
            raise ValueError('func must be callable')
        #Setting the arguments on the function
        func = functools.partial(func, **(func_args if func_args is not None else {}))
        #The data returned by function
        returned=[]
        if asynch == True :
            if isinstance(workers, int) :
                returned=list(concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers ).map(
                        func, elements))
                    
            else:
                raise AttributeError('When asynch == True : You must specify a integer value for workers')
        else :
            for index_or_item in elements:
                returned.append(func(index_or_item))
        return returned

def schedule_iterator(targets: Iterable[str], scan_window_start: str,
                scan_window_duration: str) -> Iterator[str]:

    duration: datetime.timedelta = dateutil.parser.parse(scan_window_duration) - dateutil.parser.parse('00:00')

    for target in targets:
        
        start = dateutil.parser.parse(scan_window_start)
        now = datetime.datetime.now()
        time_now = dateutil.parser.parse(now.strftime('%H:%M:%S'))
        
        while time_now - start > duration:
            print(f"It's not the time to use Burp Suite, it's {time_now.strftime('%H:%M:%S')}. Sleeping...")
            time.sleep(1800)

        yield target

def schedule(*targets: str, 
                api_url: str = "",
                api_port: str = "8090",
                new_api_url: str = "",
                new_api_port: str = "1337",
                new_api_key: str = "",
                verbose: bool = False,
                quiet: bool = False, 
                report_type: str = "HTML", 
                report_output_dir: str = "", 
                excluded: str = "", 
                config: str = "",
                app_user: str = "", 
                app_pass: str = "",
                scan_window_start: str = "00:00",
                scan_window_duration: str = "04:00",
                workers: int = 5) -> None:
    """
    Wrapper to schedule Burp scans to run at certain times only. 

    Args
    ----
    scan_window_start: str
        At what time to start the scan. 

        Formats should be:
            hh:mm or hh:mm:ss

    scan_window_duration: str
        How long should the scan period should spend.
    workers: int
        How many asynchronous scans to launch. 
    
    See Burpa() and Burpa.scan() for details on other arguments. 
    """

    parsed_targets = list(parse_targets(targets))

    iterator = schedule_iterator(parsed_targets, scan_window_start=scan_window_start, 
                scan_window_duration=scan_window_duration)
    
    burpa = Burpa(api_url=api_url, 
                  api_port=api_port, 
                  new_api_url=new_api_url, 
                  new_api_port=new_api_port, 
                  new_api_key=new_api_key,
                  verbose=verbose,
                  quiet=quiet)
    
    lock_file_path = TEMP_DIR.joinpath(f'{datetime.datetime.now().isoformat(timespec="seconds")}.scheduled.lock')
    lock_file_path.touch()
    
    with FileLock(str(lock_file_path)):

        perform(burpa.scan, iterator, 
                func_args=dict(report_type=report_type,
                            report_output_dir=report_output_dir,
                            excluded=excluded,
                            config=config,
                            app_user=app_user,
                            app_pass=app_pass), asynch=True, workers=workers)

if __name__ == "__main__":
    # Make Python Fire not use a pager when it prints a help text
    fire.core.Display = lambda lines, out: print(*lines, file=out)

    try:
        fire.Fire(schedule, name='schedule')
    
    except BurpaError as e:

        logger = get_logger('schedule')

        if os.getenv("BURPA_DEBUG"):
            logger.error(traceback.format_exc())

        logger.error(e)

        sys.exit(1)
