"""
Service decorator for automatic Google service authentication and injection.

This decorator handles the extraction of credentials from the request context,
builds authenticated Google API service clients, and injects them into tool functions.
"""
import inspect
import logging
import requests
from functools import wraps
from typing import Any, Callable, List, Optional, Union

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.exceptions import RefreshError
from fastmcp.server.dependencies import get_context, get_http_headers

from mcp_google_contacts_server.context import (
    get_injected_oauth_credentials,
    get_user_email,
    set_injected_oauth_credentials,
    set_user_email,
)

logger = logging.getLogger(__name__)


class GoogleAuthenticationError(Exception):
    """Exception raised when Google authentication fails."""
    pass


# Service configuration mapping
SERVICE_CONFIGS = {
    "people": {"service": "people", "version": "v1"},
    "gmail": {"service": "gmail", "version": "v1"},
    "drive": {"service": "drive", "version": "v3"},
    "calendar": {"service": "calendar", "version": "v3"},
    "docs": {"service": "docs", "version": "v1"},
    "sheets": {"service": "sheets", "version": "v4"},
}


# Scope definitions for Google Contacts
CONTACTS_SCOPE = "https://www.googleapis.com/auth/contacts"
DIRECTORY_READONLY_SCOPE = "https://www.googleapis.com/auth/directory.readonly"

SCOPE_GROUPS = {
    "contacts": CONTACTS_SCOPE,
    "contacts_readonly": "https://www.googleapis.com/auth/contacts.readonly",
    "directory_readonly": DIRECTORY_READONLY_SCOPE,
}


def _resolve_scopes(scopes: Union[str, List[str]]) -> List[str]:
    """
    Resolve scope names to actual scope URLs.
    
    Args:
        scopes: Scope name(s) or URL(s)
        
    Returns:
        List of scope URLs
    """
    if isinstance(scopes, str):
        if scopes in SCOPE_GROUPS:
            return [SCOPE_GROUPS[scopes]]
        else:
            return [scopes]

    resolved = []
    for scope in scopes:
        if scope in SCOPE_GROUPS:
            resolved.append(SCOPE_GROUPS[scope])
        else:
            resolved.append(scope)
    return resolved


def _verify_google_token(token: str) -> Optional[dict]:
    """
    Verify a Google OAuth access token and extract user info.
    
    Args:
        token: The access token to verify
        
    Returns:
        Dictionary with user info (email, scopes) or None if invalid
    """
    try:
        response = requests.get(
            'https://www.googleapis.com/oauth2/v3/tokeninfo',
            params={'access_token': token},
            timeout=5
        )
        
        if response.status_code == 200:
            token_info = response.json()
            return {
                'email': token_info.get('email'),
                'scopes': token_info.get('scope', '').split(),
                'expires_in': int(token_info.get('expires_in', 3600)),
                'sub': token_info.get('sub'),
            }
        else:
            logger.warning(f"Token verification failed: {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        return None


def _get_auth_context(tool_name: str) -> tuple[Optional[str], Optional[Any]]:
    """
    Get authentication context from FastMCP or request context.
    If not found, attempts to extract Bearer token from HTTP headers directly.
    
    Args:
        tool_name: Name of the tool being called (for logging)
        
    Returns:
        Tuple of (authenticated_user_email, credentials)
    """
    try:
        # First check the request-scoped context (set by middleware)
        credentials = get_injected_oauth_credentials()
        user_email = get_user_email()
        
        if credentials and user_email:
            logger.debug(f"[{tool_name}] Found credentials in request context for {user_email}")
            return user_email, credentials

        # Fall back to FastMCP context
        ctx = get_context()
        if ctx:
            authenticated_user = ctx.get_state("authenticated_user_email")
            credentials_obj = ctx.get_state("access_token_obj")
            
            if authenticated_user and credentials_obj:
                logger.debug(f"[{tool_name}] Found credentials in FastMCP context for {authenticated_user}")
                return authenticated_user, credentials_obj
        
        # If no credentials found, try to extract from HTTP headers (for stateless/HTTP mode)
        try:
            headers = get_http_headers()
            if headers:
                auth_header = headers.get("authorization", "")
                
                if auth_header.startswith("Bearer "):
                    token_str = auth_header[7:]  # Remove "Bearer " prefix
                    logger.debug(f"[{tool_name}] Found Bearer token in Authorization header")
                    
                    # For Google OAuth tokens (ya29.*), verify them
                    if token_str.startswith("ya29."):
                        logger.debug(f"[{tool_name}] Detected Google OAuth access token format")
                        
                        # Verify the token
                        verified_info = _verify_google_token(token_str)
                        
                        if not verified_info:
                            logger.error(f"[{tool_name}] Failed to verify Google OAuth token")
                            return None, None
                        
                        user_email = verified_info.get('email')
                        if not user_email:
                            logger.error(f"[{tool_name}] No email in verified token")
                            return None, None
                        
                        # Create a Credentials object from the access token
                        credentials = Credentials(
                            token=token_str,
                            scopes=verified_info.get('scopes', [])
                        )
                        
                        # Store in context for future use in this request
                        set_injected_oauth_credentials(credentials)
                        set_user_email(user_email)
                        
                        logger.info(f"[{tool_name}] Authenticated via Bearer token: {user_email}")
                        return user_email, credentials
                    else:
                        logger.debug(f"[{tool_name}] Token format not recognized (not a Google OAuth token)")
        except Exception as e:
            logger.debug(f"[{tool_name}] Could not extract Bearer token from headers: {e}")
        
        logger.debug(f"[{tool_name}] No authentication context found")
        return None, None

    except Exception as e:
        logger.debug(f"[{tool_name}] Could not get auth context: {e}")
        return None, None


def _validate_scopes(credentials: Credentials, required_scopes: List[str], tool_name: str):
    """
    Validate that credentials have the required scopes.
    
    Args:
        credentials: Google OAuth2 Credentials
        required_scopes: List of required scope URLs
        tool_name: Name of the tool (for error messages)
        
    Raises:
        GoogleAuthenticationError: If required scopes are missing
    """
    if not credentials.scopes:
        # If scopes are not set, we can't validate - assume they're correct
        logger.debug(f"[{tool_name}] Credentials have no scope information, skipping validation")
        return

    available_scopes = set(credentials.scopes)
    missing_scopes = set(required_scopes) - available_scopes
    
    if missing_scopes:
        raise GoogleAuthenticationError(
            f"OAuth credentials lack required scopes. "
            f"Missing: {sorted(missing_scopes)}, "
            f"Have: {sorted(available_scopes)}"
        )
    
    logger.debug(f"[{tool_name}] Scope validation passed")


async def _authenticate_service(
    service_name: str,
    service_version: str,
    tool_name: str,
    required_scopes: List[str],
) -> tuple[Any, str]:
    """
    Authenticate and get Google service using credentials from context.
    
    Args:
        service_name: Name of the Google service (e.g., "people")
        service_version: API version (e.g., "v1")
        tool_name: Name of the tool being called
        required_scopes: List of required OAuth scopes
        
    Returns:
        Tuple of (service_client, user_email)
        
    Raises:
        GoogleAuthenticationError: If authentication fails
    """
    user_email, credentials = _get_auth_context(tool_name)
    
    if not user_email or not credentials:
        raise GoogleAuthenticationError(
            "No authentication credentials found. "
            "Please provide a valid Bearer token in the Authorization header."
        )
    
    # Validate scopes
    _validate_scopes(credentials, required_scopes, tool_name)
    
    try:
        # Build the Google API service client
        service = build(service_name, service_version, credentials=credentials)
        logger.info(f"[{tool_name}] Authenticated {service_name} service for {user_email}")
        return service, user_email
        
    except Exception as e:
        logger.error(f"[{tool_name}] Failed to build service: {e}")
        raise GoogleAuthenticationError(f"Failed to build Google service: {str(e)}")


def require_google_service(
    service_type: str,
    scopes: Union[str, List[str]],
    version: Optional[str] = None,
):
    """
    Decorator that automatically handles Google service authentication and injection.
    
    This decorator extracts credentials from the request context, builds an authenticated
    Google API service client, and injects it as the first parameter to the decorated function.
    
    Args:
        service_type: Type of Google service ("people", "gmail", "drive", etc.)
        scopes: Required scopes (can be scope group names or actual URLs)
        version: Service version (defaults to standard version for service type)
    
    Usage:
        @require_google_service("people", "contacts")
        async def list_contacts(service, name_filter: Optional[str] = None):
            # service parameter is automatically injected with authenticated client
            results = service.people().connections().list(...)
            return results
    
    The decorator:
    - Extracts authentication from request context
    - Validates required scopes
    - Builds authenticated service client
    - Injects service as first parameter
    - Handles authentication errors gracefully
    """
    def decorator(func: Callable) -> Callable:
        original_sig = inspect.signature(func)
        params = list(original_sig.parameters.values())

        # The decorated function must have 'service' as its first parameter
        if not params or params[0].name != "service":
            raise TypeError(
                f"Function '{func.__name__}' decorated with @require_google_service "
                "must have 'service' as its first parameter."
            )

        # Create a new signature for the wrapper that excludes the 'service' parameter
        wrapper_sig = original_sig.replace(parameters=params[1:])

        # Get service configuration
        if service_type not in SERVICE_CONFIGS:
            raise ValueError(f"Unknown service type: {service_type}")

        config = SERVICE_CONFIGS[service_type]
        service_name = config["service"]
        service_version = version or config["version"]

        # Resolve scopes
        resolved_scopes = _resolve_scopes(scopes)

        @wraps(func)
        async def wrapper(*args, **kwargs):
            """Wrapper that injects authenticated service."""
            tool_name = func.__name__
            
            try:
                # Authenticate and get service
                service, user_email = await _authenticate_service(
                    service_name,
                    service_version,
                    tool_name,
                    resolved_scopes,
                )
                
                # Call the original function with the service injected as first parameter
                return await func(service, *args, **kwargs)
                
            except GoogleAuthenticationError as e:
                logger.error(f"[{tool_name}] Authentication error: {e}")
                raise
            except RefreshError as e:
                logger.error(f"[{tool_name}] Token refresh error: {e}")
                raise GoogleAuthenticationError(
                    f"Authentication token expired or invalid. Please provide a fresh access token."
                )
            except Exception as e:
                logger.error(f"[{tool_name}] Unexpected error: {e}")
                raise

        # Set the wrapper's signature to exclude 'service' parameter
        wrapper.__signature__ = wrapper_sig
        
        return wrapper

    return decorator


def require_multiple_services(service_configs: List[dict]):
    """
    Decorator for functions that need multiple Google services.
    
    Args:
        service_configs: List of service configurations, each containing:
            - service_type: Type of service
            - scopes: Required scopes
            - param_name: Name to inject service as (e.g., 'people_service', 'drive_service')
            - version: Optional version override
    
    Usage:
        @require_multiple_services([
            {"service_type": "people", "scopes": "contacts", "param_name": "people_service"},
            {"service_type": "drive", "scopes": "drive_readonly", "param_name": "drive_service"}
        ])
        async def sync_contacts(people_service, drive_service, folder_id: str):
            # Both services are automatically injected
            pass
    """
    def decorator(func: Callable) -> Callable:
        original_sig = inspect.signature(func)
        
        service_param_names = {config["param_name"] for config in service_configs}
        params = list(original_sig.parameters.values())
        
        # Remove injected service params from the wrapper signature
        filtered_params = [p for p in params if p.name not in service_param_names]
        wrapper_sig = original_sig.replace(parameters=filtered_params)
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            """Wrapper that injects multiple authenticated services."""
            tool_name = func.__name__
            
            # Authenticate all services
            for config in service_configs:
                service_type = config["service_type"]
                scopes = config["scopes"]
                param_name = config["param_name"]
                version = config.get("version")
                
                if service_type not in SERVICE_CONFIGS:
                    raise ValueError(f"Unknown service type: {service_type}")
                
                service_config = SERVICE_CONFIGS[service_type]
                service_name = service_config["service"]
                service_version = version or service_config["version"]
                resolved_scopes = _resolve_scopes(scopes)
                
                try:
                    # Authenticate service
                    service, _ = await _authenticate_service(
                        service_name,
                        service_version,
                        tool_name,
                        resolved_scopes,
                    )
                    
                    # Inject service with specified parameter name
                    kwargs[param_name] = service
                    
                except GoogleAuthenticationError as e:
                    logger.error(f"[{tool_name}] Auth error for service '{service_type}': {e}")
                    raise
            
            # Call the original function with all services injected
            return await func(*args, **kwargs)
        
        # Set the wrapper's signature
        wrapper.__signature__ = wrapper_sig
        
        return wrapper
    
    return decorator
