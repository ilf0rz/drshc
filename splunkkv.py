from pymongo import MongoClient
from pymongo.read_preferences import SecondaryPreferred
from typing import Dict, Any, Optional, TypedDict, List, Union

class KVRestResponse(TypedDict):
    success: bool
    exception: Optional[str]
    details: Optional[str]
    response: Optional[Dict[str, Any]]

class RetVal():
    def __new__(cls, success: bool, exception: Optional[str] = None, 
                details: Optional[str] = None, 
                response: Optional[Dict[str, Any]] = None) -> KVRestResponse:
        status: KVRestResponse = {
            'success': success,
            'exception': exception,
            'details': details,
            'response': response
        }
        return status
    
class SplunkKV:
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        directConnection: bool = True,              # Allow connecting to secondary instances
        replicaSet: str = "splunkrs",              # Replica set to connect to 
        username: Optional[str] = None,            # Username for MongoDB connection
        password: Optional[str] = None,            # Password for MongoDB connection
        authSource: str = "local",                 # Auth source for MongoDB authentication 
        tls: bool = True,                           # Use TLS 
        tlsAllowInvalidCertificates: bool = True,   # Allow invalid certificates
        tlsCertificateKeyFile: Optional[str] = None,  # Certificate and key file for MongoDB connection for Splunk Ent >= 9.4.0
        tlsCertificateKeyFilePassword: Optional[str] = None,  # Password for the private key contained in tlsCertificateKeyFile
        read_preference: Any = SecondaryPreferred()  # Allows connection to secondary instances
    ) -> None:
        # Common client parameters
        client_params: Dict[str, Any] = {
            'host': host,
            'port': port,
            'directConnection': directConnection,
            'replicaSet': replicaSet,
            'username': username,
            'password': password,
            'authSource': authSource,
            'tls': tls,
            'tlsAllowInvalidCertificates': tlsAllowInvalidCertificates,
            'read_preference': read_preference,
        }
        
        # Only add certificate parameters if both are provided
        if tlsCertificateKeyFile is not None and tlsCertificateKeyFilePassword is not None:
            client_params['tlsCertificateKeyFile'] = tlsCertificateKeyFile
            client_params['tlsCertificateKeyFilePassword'] = tlsCertificateKeyFilePassword

        self.client = MongoClient(**client_params)
    
    def test_connectivty(self) -> KVRestResponse:
        try:
            connectionStatus = self.client.admin.command("connectionStatus")
            auth_users: List[Any] = connectionStatus.get("authInfo", {}).get("authenticatedUsers", [])
        except Exception as e:
            success = False
            exception = e.__class__.__name__
            details = f"An unexpected error occurred. Details: {str(e)}"
            response = None
            return RetVal(success=success, exception=exception, details=details, response=response)

        if auth_users:
            success = True
            exception = None
            details = None
            response = connectionStatus
        else:
            success = False
            exception = None
            details = f"User is not authenticated: {str(connectionStatus)}"
            response = connectionStatus
        
        return RetVal(success=success, exception=exception, details=details, response=response)

    def reconfigure_replicaset(self) -> KVRestResponse:
        try:
            repl_set_status: Dict[str, Any] = self.client.admin.command("replSetGetStatus")
        except Exception as e:
            success = False
            exception = e.__class__.__name__
            details = f"An error occurred while getting the replica set status. Details: {str(e)}"
            response = None
            return RetVal(success=success, exception=exception, details=details, response=response)
        
        healthy_ids: List[int] = [
            member["_id"]
            for member in repl_set_status["members"]
            if member["stateStr"] == "SECONDARY"
        ]
        try:
            config: Dict[str, Any] = self.client.admin.command("replSetGetConfig")["config"]

        except Exception as e:
            success = False
            exception = e.__class__.__name__
            details = f"An error occurred while getting the replica set config. Details: {str(e)}"
            response = None
            return RetVal(success=success, exception=exception, details=details, response=response)

        filtered_members: List[Dict[str, Any]] = [
            member for member in config["members"]
            if member["_id"] in healthy_ids
        ]

        new_config: Dict[str, Any] = config.copy()
        new_config["members"] = filtered_members
        new_config["version"] += 1
        try:
            repl_set_config: Dict[str, Any] = self.client.admin.command("replSetReconfig", new_config, force=True)

        except Exception as e:
            success = False
            exception = e.__class__.__name__
            details = f"An error occurred while setting the NEW replica set config. Details: {str(e)}"
            response = None
            return RetVal(success=success, exception=exception, details=details, response=response)

        success = True
        exception = None
        details = None
        response = repl_set_config
        return RetVal(success=success, exception=exception, details=details, response=response)