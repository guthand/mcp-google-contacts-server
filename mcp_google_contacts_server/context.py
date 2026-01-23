"""
Request context management for storing OAuth credentials per request.

This module uses contextvars to maintain request-scoped credential storage,
allowing stateless authentication where credentials are passed with each request.
"""
import contextvars
from typing import Optional, Any

# Context variable to hold injected OAuth credentials for the life of a single request
_injected_oauth_credentials = contextvars.ContextVar(
    "injected_oauth_credentials", default=None
)

# Context variable to hold the access token for the current request
_access_token = contextvars.ContextVar("access_token", default=None)

# Context variable to hold user email for the current request
_user_email = contextvars.ContextVar("user_email", default=None)


def get_injected_oauth_credentials() -> Optional[Any]:
    """
    Retrieve injected OAuth credentials for the current request context.
    
    This is called by the authentication layer to check for request-scoped credentials.
    
    Returns:
        Google OAuth2 Credentials object or None
    """
    return _injected_oauth_credentials.get()


def set_injected_oauth_credentials(credentials: Optional[Any]):
    """
    Set or clear the injected OAuth credentials for the current request context.
    
    This is called by the service decorator to inject credentials.
    
    Args:
        credentials: Google OAuth2 Credentials object or None to clear
    """
    _injected_oauth_credentials.set(credentials)


def get_access_token() -> Optional[str]:
    """
    Retrieve the access token for the current request context.
    
    Returns:
        Access token string or None
    """
    return _access_token.get()


def set_access_token(token: Optional[str]):
    """
    Set or clear the access token for the current request context.
    
    Args:
        token: Access token string or None to clear
    """
    _access_token.set(token)  # type: ignore[arg-type]


def get_user_email() -> Optional[str]:
    """
    Retrieve the user email for the current request context.
    
    Returns:
        User email string or None
    """
    return _user_email.get()


def set_user_email(email: Optional[str]):
    """
    Set or clear the user email for the current request context.
    
    Args:
        email: User email string or None to clear
    """
    _user_email.set(email)  # type: ignore[arg-type]


def clear_context():
    """Clear all context variables for the current request."""
    set_injected_oauth_credentials(None)
    set_access_token(None)
    set_user_email(None)
