import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Tuple, Optional

def validate_creds(
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None
) -> Tuple[bool, str, Optional[boto3.Session]]:
    """
    Validates credentials AND returns a usable Boto3 session.
    
    Returns:
        Tuple: (success: bool, message: str, session: Optional[boto3.Session])
    """
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
        
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        
        return (
            True,
            f"✅ Valid credentials for account: {identity['Account']}",
            session  
        )
        
    except NoCredentialsError:
        return (False, "❌ No AWS credentials provided", None)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidClientTokenId':
            return (False, "❌ Invalid AWS Access Key ID", None)
        elif error_code == 'SignatureDoesNotMatch':
            return (False, "❌ Invalid AWS Secret Access Key", None)
        elif error_code == 'ExpiredToken':
            return (False, "❌ Expired Session Token", None)
        return (False, f"❌ AWS API Error: {e}", None)
    except Exception as e:
        return (False, f"❌ Unexpected Error: {e}", None)


# If you want to use later call this module and pass credentiels to get a session to test on
# session=validate_creds(**creds)[2]
# then u can use session.client(...)

