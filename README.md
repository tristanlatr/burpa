<img align="left" src="https://github.com/tristanlatr/burpa/blob/main/docs/images/burpa.png" width="90px">

**This is a fork of [0x4D31/burpa](https://github.com/0x4D31/burpa)**. 

The original repo seemed abandonned, but I would be happy to merge back the changes to upstream version!

# burpa: Burp Automator

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A Burp Suite Automation Tool. 

It provides a high level CLI and Python interfaces to Burp Suite scanner and can be used to setup Dynamic Application Security Testing (DAST). 

It will use the official REST API to launch the scan, and the `burp-rest-api` to get the pretty HTML report. 

<img align="center" src="https://github.com/tristanlatr/burpa/blob/main/docs/images/diagram.png" width="650px">

## Requirements
* Burp Suite Professional v2.0 or greater. 
* Install and launch [burp-rest-api](https://github.com/vmware/burp-rest-api) third party extension. 
* Enable the Official Burp Suite Professional REST API. Both the extension and the official REST APIs must be enabled.

  - You can do so by laucnhing the `burp-rest-api` with `--headless=false --unpause-spider-and-scanner` options, enable the REST API under `User Options > Misc > REST API`. Export the config files, both project level (under `Project > Project options > Save`) and user level (under `Burp > User options > Save`), and use them to launch the `burp-rest-api` with options `--config-file` and `--user-config-file`. 

## What changed

- `burpa` is now an actual package that can be installed with `pip install .`.
- Slack support has been removed.
- `burpa` is now callable with `python3 -m burpa`.
- Add static type checking.
- Add support for interfacing with the Burp Official REST API: This allows to run authenticated scans. 
- Use [python-fire](https://github.com/google/python-fire) to generate the CLI. 
- Publish the API documentation. 
- Can load Burp configuration fron environment variables and automatically read `.env` files in the source directory tree with [python-dotenv](https://github.com/theskumar/python-dotenv). 

### Configuration

Burpa must be configured with the Burp Suite URL and related config values. 
You can pass those values as argument with flags `--api-url`, `--api-port`, `--new-api-url`, `--new-api-port` and `--new-api-key` or
by setting the following environment variables:

```
export BURP_API_URL=""
export BURP_API_PORT=""
export BURP_NEW_API_URL=""
export BURP_NEW_API_PORT=""
export BURP_NEW_API_KEY=""
```

### Examples:

- Scan two URLs
  ```
  $ burpa scan http://mysite.com http://mysite2.com --report-output-dir ./burp-reports/
  ```

- Scan URLs from a list
  ```
  $ burpa scan ./mysites.txt --report-output-dir ./burp-reports/
  ```

- Scan with username/password authentication
  ```
  $ burpa scan http://mysite.com --report-output-dir ./burp-reports/ --app-user=user --app-pass=p@assw0rd
  ```

- Shutdown the Burp Suite and wait 60 seconds for the service to restart. 
  ```
  $ burpa stop
  $ burpa test --wait 120
  ```

  You can use `systemctl` or `supervisord` (Linux) or NSSM (Windows) to automatically restart the `burp-rest-api` when it stopped running. 
  This seem to be the only way to reset the scanner to a clean state ([ref](https://github.com/vmware/burp-rest-api/issues/82)). 

### Python library

[API Reference](https://tristanlatr.github.io/burpa/)

### CLI Test

```
$ burpa scan http://10.1.1.1:8080/WebGoat --report-output-dir /tmp/burp-reports/
           __                          
           / /_  __  ___________  ____ _
          / __ \/ / / / ___/ __ \/ __ `/
         / /_/ / /_/ / /  / /_/ / /_/ / 
        /_.___/\__,_/_/  / .___/\__,_/  
                        /_/             
         burpa version 0.3.0.dev 

INFO - Loading .env file /home/runner/.env
INFO - http://10.1.1.1:8080/WebGoat has been included to the scope
INFO - Initiating unauthenticated scan...
INFO - http://10.1.1.1:8080/WebGoat Added to the scan queue, ID 3
INFO - Scan started
INFO - Scan status: crawling
INFO - Scan status: auditing
INFO - Scan status: succeeded
INFO - Scan completed
INFO - Scan metrics for http://10.1.1.1:8080/WebGoat :
INFO - CRAWL_REQUESTS_MADE = 3
INFO - CRAWL_NETWORK_ERRORS = 0
INFO - CRAWL_UNIQUE_LOCATIONS_VISITED = 1
INFO - CRAWL_REQUESTS_QUEUED = 0
INFO - AUDIT_QUEUE_ITEMS_COMPLETED = 2
INFO - AUDIT_QUEUE_ITEMS_WAITING = 0
INFO - AUDIT_REQUESTS_MADE = 644
INFO - AUDIT_NETWORK_ERRORS = 2
INFO - ISSUE_EVENTS = 13
INFO - CRAWL_AND_AUDIT_CAPTION = Audit finished.
INFO - CRAWL_AND_AUDIT_PROGRESS = 100
INFO - Scan issues for http://10.1.1.1:8080/WebGoat :
INFO - Issue: Robots.txt file, Severity: Information
INFO - Issue: Backup file, Severity: Information
INFO - Issue: Cookie without HttpOnly flag set, Severity: Information
INFO - Issue: Strict transport security not enforced, Severity: Low
INFO - Issue: TLS cookie without secure flag set, Severity: Information
INFO - Issue: Cacheable HTTPS response, Severity: Information
INFO - Issue: TLS certificate, Severity: Information
INFO - Downloading HTML/XML report for http://10.1.1.1:8080/WebGoat
INFO - Scan report saved to /tmp/burp-reports/burp-report_20210317-163223_http10.1.1.18080WebGoat.html

```


## Usage

Look at the following command output to get detailed help.

```
$ burpa --help
$ burpa --api-url=localhost --help
$ burpa --api-url=localhost scan --help
```

Look at [python-fire documentation](https://google.github.io/python-fire/guide/) to have a better understanding of how `python-fire` generated CLI works. 


## Related

- https://github.com/laconicwolf/Burp-API-Scripts
- https://github.com/joanbono/Gurp
- https://github.com/pentestgeek/burpcommander
