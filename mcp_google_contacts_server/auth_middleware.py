"""
Authentication middleware for extracting and validating OAuth tokens from requests.

This middleware intercepts requests, extracts Bearer tokens from Authorization headers,
verifies them with Google, and stores authentication information in the FastMCP context.
"""
import logging
import time
from typing import Optional
from types import SimpleNamespace

from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
import requests

from mcp_google_contacts_server.context import (
    set_injected_oauth_credentials,
    set_access_token,
    set_user_email,
)

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class ContactsAuthMiddleware(Middleware):
    """
    Middleware to extract authentication information from Bearer tokens
    and populate the FastMCP context state for use in tools.
    """

    def __init__(self):
        super().__init__()
        self.auth_provider_type = "GoogleProvider"

    async def _verify_google_token(self, token: str) -> Optional[dict]:
        """
        Verify a Google OAuth access token and extract user info.
        
        Args:
            token: The access token to verify
            
        Returns:
            Dictionary with user info (email, scopes) or None if invalid
        """
        try:
            # Use Google's tokeninfo endpoint to verify the token
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

    async def _process_request_for_auth(self, context: MiddlewareContext):
        """
        Helper to extract, verify, and store auth info from a request.
        
        Args:
            context: The middleware context containing FastMCP context
        """
        if not context.fastmcp_context:
            logger.debug("No fastmcp_context available")
            return

        # Return early if authentication state is already set
        if context.fastmcp_context.get_state("authenticated_user_email"):
            logger.debug("Authentication state already set")
            return

        try:
            # Get HTTP headers
            headers = get_http_headers()
            if not headers:
                logger.debug("No HTTP headers available (might be using stdio transport)")
                return

            logger.debug("Processing HTTP headers for authentication")

            # Get the Authorization header
            auth_header = headers.get("authorization", "")
            if not auth_header.startswith("Bearer "):
                logger.debug("No Bearer token in Authorization header")
                return

            token_str = auth_header[7:]  # Remove "Bearer " prefix
            logger.debug("Found Bearer token")

            # For Google OAuth tokens (ya29.*), verify them
            if token_str.startswith("ya29."):
                logger.debug("Detected Google OAuth access token format")
                
                # Verify the token
                verified_info = await self._verify_google_token(token_str)
                
                if not verified_info:
                    logger.error("Failed to verify Google OAuth token")
                    raise AuthenticationError("Invalid or expired access token")

                user_email = verified_info.get('email')
                if not user_email:
                    logger.error("No email in verified token")
                    raise AuthenticationError("Token does not contain user email")

                # Calculate expiry time
                expires_at = int(time.time()) + verified_info.get('expires_in', 3600)

                # Create a Credentials object from the access token
                credentials = Credentials(
                    token=token_str,
                    scopes=verified_info.get('scopes', [])
                )

                # Store credentials in context
                set_injected_oauth_credentials(credentials)
                set_access_token(token_str)
                set_user_email(user_email)

                # Create an access token object for compatibility
                access_token_obj = SimpleNamespace(
                    token=token_str,
                    client_id="google",
                    scopes=verified_info.get('scopes', []),
                    session_id=f"google_oauth_{token_str[:8]}",
                    expires_at=expires_at,
                    sub=verified_info.get('sub', user_email),
                    email=user_email,
                )

                # Store in context state - this is the authoritative authentication state
                context.fastmcp_context.set_state("access_token", access_token_obj)
                context.fastmcp_context.set_state("access_token_obj", credentials)
                context.fastmcp_context.set_state("auth_provider_type", self.auth_provider_type)
                context.fastmcp_context.set_state("token_type", "google_oauth")
                context.fastmcp_context.set_state("user_email", user_email)
                context.fastmcp_context.set_state("username", user_email)
                context.fastmcp_context.set_state("authenticated_user_email", user_email)
                context.fastmcp_context.set_state("authenticated_via", "bearer_token")

                logger.info(f"Authenticated via Google OAuth: {user_email}")
            else:
                logger.debug("Token format not recognized, skipping authentication")

        except AuthenticationError:
            # Re-raise authentication errors
            raise
        except Exception as e:
            logger.error(f"Error processing authentication: {e}")
            # Don't fail the request, just log the error
            pass

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Extract auth info from token and set in context state for tool calls."""
        logger.debug("Processing tool call authentication")

        try:
            await self._process_request_for_auth(context)
            result = await call_next(context)
            return result

        except AuthenticationError as e:
            logger.info(f"Authentication check failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Error in on_call_tool middleware: {e}", exc_info=True)
            raise

    async def on_get_prompt(self, context: MiddlewareContext, call_next):
        """Extract auth info for prompt requests too."""
        logger.debug("Processing prompt authentication")

        try:
            await self._process_request_for_auth(context)
            result = await call_next(context)
            return result

        except AuthenticationError as e:
            logger.info(f"Authentication check failed in prompt: {e}")
            raise
        except Exception as e:
            logger.error(f"Error in on_get_prompt middleware: {e}", exc_info=True)
            raise
