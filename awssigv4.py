"""
A module to make AWS SigV4 requests using the requests library.

Based on:
    https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    https://github.com/aws-samples/sigv4-signing-examples/blob/main/no-sdk/python/main.py

:author: Shayne Reese
:requires: requests==2.32.3
"""
import time, json, hmac, hashlib, urllib.parse
from io import StringIO, BytesIO
from http.client import HTTPMessage

import requests


ALGORITHM = 'AWS4-HMAC-SHA256'
SIGNED_HEADERS_BLACKLIST = ('expect', 'user-agent', 'x-amzn-trace-id')
METHODS = ('GET', 'POST', 'HEAD', 'DELETE')


def get_timestamps() -> tuple:
    """
    Create the AWS formatted timestamps.

    :returns: AWS formatted timestamp for signing.
    :rtype: tuple
    """
    now = time.gmtime()
    return time.strftime("%Y%m%dT%H%M%SZ", now), time.strftime("%Y%m%d", now)


def remove_dot_segments(url: str) -> str:
    """
    From `botocore.utils.remove_dot_segments`
    See: https://github.com/boto/botocore/blob/3cafb9f30853938ca419f7175f3f9e25203204b6/botocore/utils.py#L287

    # RFC 3986, section 5.2.4 "Remove Dot Segments"
    # Also, AWS services require consecutive slashes to be removed,
    # so that's done here as well

    :param str url: Url path to normalize.
    :returns: Normalized url path.
    :rtype: str
    """
    if not url:
        return "/"
    input_url = url.split('/')
    output_list: list = []
    for x in input_url:
        if x and x != '.':
            if x == '..':
                if output_list:
                    output_list.pop()
            else:
                output_list.append(x)
    if url[0] == '/':
        first = '/'
    else:
        first = ''
    if url[-1] == '/' and output_list:
        last = '/'
    else:
        last = ''
    path = first + '/'.join(output_list) + last
    return urllib.parse.quote(path, safe='/~')


def validate_headers(headers: dict, host: str) -> HTTPMessage:
    """
    Check headers against a blacklist,
    and verify the host header is included.

    :param dict headers: Headers to sign.
    :param str host: Request host.
    :returns: Validated headers for formatting.
    :rtype: http.client.HTTPMessage
    """
    header_map = HTTPMessage()
    for name, value in headers.items():
        lname = name.lower()
        if lname not in SIGNED_HEADERS_BLACKLIST:
            header_map[lname] = value
    if 'host' not in header_map:
        header_map['host'] = host
    return header_map


def get_signed_headers(signed_headers: HTTPMessage):
    """
    Create the list of Canonical signed headers.
    See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#:~:text=the%20signature%20calculation.-,SignedHeaders,-%E2%80%93%20An%20alphabetically%20sorted
   
    :param http.client.HTTPMessage signed_headers: Request headers to sign.
    :returns: Canonical formatted signed header list.
    :rtype: str
    """
    headers = sorted(
        n.lower().strip() for n in set(signed_headers)
    )
    return ';'.join(headers)


def canonical_headers(headers_to_sign: HTTPMessage) -> str:
    """
    Create Canonical formatted headers.
    See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#:~:text=%22%5Cn%22).-,CanonicalHeaders,-%E2%80%93%20A%20list%20of
    
    :param http.client.HTTPMessage headers_to_sign: Request headers to sign.
    :returns: Canonical formatted header string.
    :rtype: str
    """
    headers: list = []
    sorted_header_names = sorted(set(headers_to_sign))
    for key in sorted_header_names:
        value = ','.join(
            ' '.join(v.split()) for v in headers_to_sign.get_all(key)
        )
        headers.append(f'{key}:{value}')
    return '\n'.join(headers)


def canonical_request(method: str,
                      host: str,
                      path: str,
                      query_string: str,
                      headers: HTTPMessage,
                      signed_headers: str,
                      hashed_payload: str
) -> str:
    """
    Build the Canonical request.
    See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#create-canonical-request

    :param str method: HTTP method.
    :param str host: Hostname.
    :param str path: Request path.
    :param str query_string: Formatted query string eg. '?<param>=<value>&<param2>=<value2>'.
    :param http.client.HTTPMessage headers: Request headers to sign.
    :param str hashedPayload: SHA-256 hash of request payload.
    :returns: Canonical formatted request string.
    :rtype: str
    """
    canonical_request: list = []
    canonical_request.append(method.upper())
    canonical_request.append(remove_dot_segments(path))
    canonical_request.append(query_string)
    canonical_request.append(canonical_headers(headers))
    canonical_request.append("")
    canonical_request.append(signed_headers)
    canonical_request.append(hashed_payload)
    return "\n".join(canonical_request)


def get_payload_hash(payload: str | bytes | dict) -> str:
   """
    Generate a SHA-256 hash of the payload.
    See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#:~:text=x%2Damz%2Ddate-,HashedPayload,-%E2%80%93%20A%20string%20created

   :param str|bytes|dict payload: Payload data to hash.
   :returns: SHA-256 hash of the payload.
   :rtype: str
   """
   if not payload:
        return hashlib.sha256(''.encode('utf-8')).hexdigest()
   if isinstance(payload, dict):
        payload = json.dumps(payload)
   if isinstance(payload, bytes):
        infile = BytesIO(payload)
   else:
        infile = StringIO(payload)
   h = hashlib.sha256()
   while True:
        chunk = infile.read(128)
        if not chunk: break
        h.update(chunk.encode("utf-8"))
   return h.hexdigest()


def sign(key: str, msg: str) -> bytes:
    """
    Sign a message with SHA-256.
    See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#calculate-signature

    :param str key: Key to use for signing.
    :param str msg: Message to be encrypted.
    :returns: Signed message.
    :rtype: bytes
    """
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(secret_key: str,
                      date: str,
                      region: str,
                      service: str
) -> str:
    """
    Create a signing key.
    See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#derive-signing-key

    :param str secret_key: AWS Secret Key Id.
    :param str date: AWS SigV4 formatted date YYYYMMDD.
    :param str region: AWS Region.
    :param str service: AWS Service.
    :returns: Hashed signing key.
    :rtype: str
    """
    key_date = sign(f"AWS4{secret_key}".encode("utf-8"), date)
    key_region = sign(key_date, region)
    key_service = sign(key_region, service)
    return sign(key_service, "aws4_request")


def get_auth_header(access_key: str,
                    credential: str,
                    signed_headers: str,
                    signature: str
) -> str:
    """
    Build the Auth header string.
    See: https://docs.aws.amazon.com/IAM/latest/UserGuide/signing-elements.html#authentication

    :param str access_key: AWS Access Key Id.
    :param str credential: AWS SigV4 formatted credential scope.
    :param str signed_headers: Headers included in request signature.
    :param str signature: Calculated request signature.
    :returns: Authorization header string.
    :rtype: str
    """
    cred = f"{access_key}/{credential}"
    auth = f"{ALGORITHM} Credential={cred}," \
           f"SignedHeaders={signed_headers}," \
           f"Signature={signature}"
    return auth


def aws_sigv4_request(access_key: str,
                      secret_key: str,
                      region: str,
                      service: str,
                      host: str,
                      method: str,
                      path: str = "",
                      query: str = "",
                      content_type: str = None,
                      session_token: str = None,
                      payload: str | bytes | dict = None,
                      verbose: bool = False
) -> requests.Response | None:
    """
    Sign a request with AWS SigV4 Authentication.
    See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html

    :param str access_key: AWS Access Key Id.
    :param str secret_key: AWS Secret Key Id.
    :param str region: AWS Region.
    :param str service: AWS Service.
    :param str host: Request host.
    :param str method: The HTTP method, such as `GET`, `PUT`, `HEAD`, and `DELETE`.
    :param str path: The absolute path component URI, starting with the '/' that follows the domain name and up to the end of the string or to the question mark character.
    :param str query: The URI-encoded query string parameters.
    :param str content_type: The `Content-Type` representation header.
    :param str session_token: The temporary security credentials from the AWS Security Token Service (AWS STS).
    :param str|bytes|dict payload: Request payload.
    :param bool verbose: Print results to the screen for debugging.
    """
    if not all((access_key, secret_key, region, host, method, service)):
        print("Missing Required Parameters for AWS SigV4 Request!")
        return None
    if not isinstance(method, str) or method.upper() not in METHODS:
        print(f"Invalid Request Method; Acceptable Methods=[ {METHODS} ]")
        return None
    
    # format the date for the request
    amz_date, cred_date = get_timestamps()
    
    # build the headers
    headers = {"Host": host, "X-Amz-Date": amz_date}
    if session_token:
        headers["X-Amz-Security-Token" ] = session_token
    if content_type:
        headers["Content-Type"] = content_type
    
    # hash the payload
    if payload is None:
        payload = ''
    payload_hash = get_payload_hash(payload)
    
    # required for s3, need to verify with api gateway
    headers["X-Amz-Content-Sha256"] = payload_hash
    
    # format headers for signing
    headers_to_sign = validate_headers(headers, host)
    signed_headers = get_signed_headers(headers_to_sign)
    
    # build canonical request
    request = canonical_request(method, host, path, query, headers_to_sign, signed_headers, payload_hash)
    
    # hash the request
    # See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#create-canonical-request-hash
    request_hash = hashlib.sha256(request.encode('utf-8')).hexdigest()
    
    # build the credential string
    # See: https://docs.aws.amazon.com/IAM/latest/UserGuide/signing-elements.html#authentication
    credential = f"{cred_date}/{region}/{service}/aws4_request"
    
    # build string, get signing key, and create the signature
    # See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#create-string-to-sign
    string_to_sign = f"{ALGORITHM}\n{amz_date}\n{credential}\n{request_hash}"
    signing_key = get_signature_key(secret_key, cred_date, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    
    # create the auth header
    authorization_header = get_auth_header(access_key, credential, signed_headers, signature)
    headers["Authorization"] = authorization_header
    
    # make the request
    if payload:
        res = requests.request(method, "https://"+host+path+query, headers=headers, data=payload, timeout=5)
    else:
        res = requests.request(method, "https://"+host+path+query, headers=headers, timeout=5)
    
    # debugging
    if verbose:
        print(f"Payload Hash: {payload_hash}\n")
        print(f"Canonical Request:\n---\n{request}\n---\n")
        print(f"Request Hash: {request_hash}\n")
        print(f"Credential: {credential}\n")
        print(f"String to Sign: {string_to_sign}\n")
        print(f"Signature: {signature}\n")
        print(f"Authorization: {authorization_header}\n")
        print(f"Headers: {headers}\n")
        print(f"\n\n")
        print(f"Response: {json.dumps(res.__dict__, default=str)}")
    
    return res
