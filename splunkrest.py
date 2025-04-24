import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
requests.packages.urllib3.disable_warnings() 
class RetVal():
    def __new__(cls, success, http_code=None, exception=None, details=None, response=None):
        status = {'success': success,
                  'http_code': http_code,
                  'exception': exception,
                  'details': details,
                  'response': response}
        return status
    
class SplunkRest:
    def __init__(
        self,
        base_url,
        auth=None,                          # Tuple (user, pass) for Basic Auth
        headers=None,                       # Optional default headers
        timeout=5,                          # Timeout in seconds or (connect, read) tuple
        verify=False,                       # SSL verification (can also be path to cert)
        retries=3,                          # Retry count
        backoff_factor=0.3,                 # Retry backoff
        status_forcelist=(500, 502, 504),   # Retry only on these codes
        proxies=None                        # Optional proxy dict
    ):
        
        self.base_url = base_url.rstrip("/")
        
        # Store session-level request options
        self._default_request_opts = {
            "timeout": timeout,
            "verify": verify,
            "proxies": proxies
        }

        self.session = requests.Session()

        # Auth
        if auth:
            self.session.auth = HTTPBasicAuth(*auth)

        # Headers
        if headers:
            self.session.headers.update(headers)

        # Retry logic
        retry_strategy = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
            allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
    
    def _full_url(self, endpoint):
        return f"{self.base_url}/{endpoint.lstrip('/')}"
    
    def _make_rest_call(self, method='GET', endpoint='/', **kwargs):
        if not self.base_url:
            raise ValueError("Base URL must be provided")
        
        url = self._full_url(endpoint)

        # Merge defaults with per-request overrides
        request_opts = {**self._default_request_opts, **kwargs}
        
        r = None # Initializing r to None in case RequestException is triggered and there is an unbound r due to the specific exception.
        try:
            r = self.session.request(method=method, url=url, **request_opts)
            success = True
            http_code = r.status_code
            try:
                response = r.json()      
            except requests.exceptions.JSONDecodeError as e:
                details = f"Failed to parse JSON. Details: {str(e)}"
                exception = e.__class__.__name__
                response = None
            else:
                details = None
                exception = None
        
        except requests.ConnectionError as e:
            success = False
            http_code = None
            exception = e.__class__.__name__
            details = f"Failed to connect to host. Details: {str(e)}"
            response = None

        except requests.Timeout as e:
            success = False
            http_code = None
            exception = e.__class__.__name__
            details = f"Connection timeout occurred. Details: {str(e)}"
            response = None
        
        except requests.RequestException as e:
            success = False
            http_code = r.status_code if r else None
            exception = e.__class__.__name__
            details = f"Request failed with status code {http_code}. Details: {str(e)}"
            response = None
        
        except Exception as e:
            success = False
            http_code = None
            exception = e.__class__.__name__
            details = f"An unexpected error occurred. Details: {str(e)}"
            response = None  
        
        return RetVal(success=success, http_code=http_code, exception=exception, details=details, response=response)

    def test_connectivty(self):
        params = {'output_mode': 'json'}
        endpoint = '/services/server/info'
        return self._make_rest_call(method='GET', endpoint=endpoint, params=params)

    def shc_status(self):
        params = {'output_mode': 'json'}
        endpoint = '/services/shcluster/status'
        return self._make_rest_call(method='GET', endpoint=endpoint, params=params)
    
    def kv_status(self):
        params = {'output_mode': 'json'}
        endpoint = '/services/kvstore/status'
        return self._make_rest_call(method='GET', endpoint=endpoint, params=params)
    
    def _set_sh_role(self, captain_uri, role):
        if role not in ['member','captain']:
            raise "Role per _set_sh_role should be either member or captain."
        
        params = {'output_mode': 'json'}
        endpoint = '/services/shcluster/config/config'
        data={"mode": role, 'captain_uri': captain_uri, 'election': False}
        return self._make_rest_call(method='POST', endpoint=endpoint, data=data, params=params)

    def set_sh_captain(self, captain_uri):
        return self._set_sh_role(captain_uri=captain_uri, role='captain')

    def set_sh_member(self, captain_uri):
        return self._set_sh_role(captain_uri=captain_uri, role='member')
    
    def set_sh_dynamic_captain(self):
        params = {'output_mode': 'json'}
        endpoint = '/services/shcluster/config/config'
        data = {'mgmt_uri': self.base_url, 'election': True}
        return self._make_rest_call(method='POST', endpoint=endpoint, data=data, params=params)
