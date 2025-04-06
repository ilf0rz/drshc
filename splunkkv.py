from pymongo import MongoClient
from pymongo.read_preferences import SecondaryPreferred

class RetVal():
    def __new__(cls, success, exception=None, details=None, response=None):
        status = {'success': success,
                  'exception': exception,
                  'details': details,
                  'response': response}
        return status
    
class SplunkKV:
    def __init__(
        self,
        host=None,
        port=None,
        directConnection=True,              # Allow connecting to secondary instances
        replicaSet="splunkrs",              # Replica set to connect to 
        username=None,                      # Username for MongoDB connection
        password=None,                      # Password for MongoDB connection
        authSource="local",                 # Auth source for MongoDB authentication 
        tls=True,                           # Use TLS 
        tlsAllowInvalidCertificates=True,   # Allow invalid certificates
        tlsCertificateKeyFile=None,         # Certificate and key file for MongoDB connection for Splunk Ent >= 9.4.0
        tlsCertificateKeyFilePassword=None, # Password for the private key contained in tlsCertificateKeyFile
        read_preference=SecondaryPreferred()# Allows connection to secondary instances
    ):
        # Common client parameters
        client_params = {
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
    
    def test_connectivty(self):
        try:
            connectionStatus = self.client.admin.command("connectionStatus")
            auth_users = connectionStatus.get("authInfo", {}).get("authenticatedUsers", [])
        except Exception as e:
            success = False
            exception = e.__class__.__name__
            details =  f"An unexpected error occurred. Details: {str(e)}"
            response = None
            return RetVal(success=success,  exception=exception, details=details, response=response)

        if auth_users:
            success = True
            exception = None
            details =  None
            response = connectionStatus

        else:
            success = False
            exception = None
            details =  f"User is not authenticated: {str(connectionStatus)}"
            response = connectionStatus
        
        return RetVal(success=success,  exception=exception, details=details, response=response)

    def reconfigure_replicaset(self):
        try:
            repl_set_status = self.client.admin.command("replSetGetStatus")
        except Exception as e:
            success = False
            exception = e.__class__.__name__
            details =  f"An error occurred while getting the replica set status. Details: {str(e)}"
            response = None
            return RetVal(success=success,  exception=exception, details=details, response=response)
        
        healthy_ids = [
            member["_id"]
            for member in repl_set_status["members"]
            if member["stateStr"] == "SECONDARY"
        ]
        try:
            config = self.client.admin.command("replSetGetConfig")["config"]

        except Exception as e:
            success = False
            exception = e.__class__.__name__
            details =  f"An error occurred while getting the replica set config. Details: {str(e)}"
            response = None
            return RetVal(success=success,  exception=exception, details=details, response=response)

        filtered_members = [
            member for member in config["members"]
            if member["_id"] in healthy_ids
        ]

        new_config = config.copy()
        new_config["members"] = filtered_members
        new_config["version"] += 1
        try:
            repl_set_config = self.client.admin.command("replSetReconfig", new_config, force=True)

        except Exception as e:
            success = False
            exception = e.__class__.__name__
            details =  f"An error occurred while setting the NEW replica set config. Details: {str(e)}"
            response = None
            return RetVal(success=success,  exception=exception, details=details, response=response)

        success = True
        exception = None
        details =  None
        response = repl_set_config
        return RetVal(success=success,  exception=exception, details=details, response=response)
