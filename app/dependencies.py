import asyncio
import logging
from datetime import datetime, timedelta
from typing import Annotated, Any, Callable, NamedTuple, Optional

import httpx
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ValidationError


# Configuration structure
class AuthConfig(NamedTuple):
    """Configuration for the authentication toolkit."""

    auth_service_url: str
    token_url: str
    introspect_endpoint: str = "/introspect/"
    roles_endpoint: str = "/roles/"
    cache_duration_minutes: int = 10
    request_timeout: float = 5.0
    logger: logging.Logger = None  # type: ignore


# Global configuration
_auth_config: Optional[AuthConfig] = None
_oauth2_scheme: Optional[OAuth2PasswordBearer] = None

# Cache management
_role_cache: dict[int, str] = {}
_cache_expiry: Optional[datetime] = None
_cache_lock = asyncio.Lock()


# Pydantic models
class TokenIntrospect(BaseModel):
    """Token introspection response model."""

    sub: str
    role_id: Optional[int] = None
    role_name: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    active: bool = True

    class Config:
        extra = "allow"


def configure_auth(
    auth_service_url: str,
    token_url: Optional[str] = None,
    introspect_endpoint: str = "/introspect",
    roles_endpoint: str = "/roles",
    cache_duration_minutes: int = 10,
    request_timeout: float = 5.0,
    logger: Optional[logging.Logger] = None,
) -> None:
    """
    Configure the authentication system.

    Args:
        auth_service_url: Base URL of the authentication service
        token_url: Token endpoint URL (defaults to auth_service_url + "/token")
        introspect_endpoint: Token introspection endpoint
        roles_endpoint: Roles listing endpoint
        cache_duration_minutes: Cache duration in minutes
        request_timeout: HTTP request timeout in seconds
        logger: Optional logger instance
    """
    global _auth_config, _oauth2_scheme

    if token_url is None:
        token_url = f"{auth_service_url}/token"

    if logger is None:
        logger = logging.getLogger(__name__)

    _auth_config = AuthConfig(
        auth_service_url=auth_service_url,
        token_url=token_url,
        introspect_endpoint=introspect_endpoint,
        roles_endpoint=roles_endpoint,
        cache_duration_minutes=cache_duration_minutes,
        request_timeout=request_timeout,
        logger=logger,
    )

    # Initialize OAuth2 scheme
    _oauth2_scheme = OAuth2PasswordBearer(tokenUrl=token_url)

    logger.info(f"Auth toolkit configured for {auth_service_url}")


def _get_config() -> AuthConfig:
    """Get the current configuration, raising an error if not configured."""
    if _auth_config is None:
        raise RuntimeError("Auth toolkit not configured. Call configure_auth() first.")
    return _auth_config


def _get_oauth2_scheme() -> OAuth2PasswordBearer:
    """Get the OAuth2 scheme, raising an error if not configured."""
    if _oauth2_scheme is None:
        raise RuntimeError("Auth toolkit not configured. Call configure_auth() first.")
    return _oauth2_scheme


def _create_auth_exception(message: str, status_code: int = 401) -> HTTPException:
    """Create a standardized authentication exception."""
    headers = {"WWW-Authenticate": "Bearer"}
    return HTTPException(
        status_code=status_code,
        detail=message,
        headers=headers,
    )


async def _make_auth_request(
    endpoint: str,
    token: Optional[str] = None,
    method: str = "GET",
    json_data: Optional[dict] = None,
) -> httpx.Response:
    """Make an authenticated request to the auth service."""
    config = _get_config()
    url = f"{config.auth_service_url}{endpoint}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            if method.upper() == "POST":
                return await client.post(
                    url, headers=headers, json=json_data, timeout=config.request_timeout
                )
            else:
                return await client.get(
                    url, headers=headers, timeout=config.request_timeout
                )
    except httpx.RequestError as e:
        config.logger.error(f"Auth service request error: {e}")
        raise HTTPException(status_code=503, detail="Auth service unavailable")


async def fetch_roles_from_api(auth_token: Optional[str] = None) -> dict[int, str]:
    """Fetch roles from the API and return as a dictionary mapping ID to name."""
    config = _get_config()
    resp = await _make_auth_request(config.roles_endpoint, auth_token)

    if resp.status_code == 401:
        config.logger.error("Authentication failed when fetching roles")
        raise HTTPException(
            status_code=503,
            detail="Unable to authenticate with auth service for role lookup",
        )
    elif resp.status_code != 200:
        config.logger.error(f"Failed to fetch roles: HTTP {resp.status_code}")
        raise HTTPException(
            status_code=503, detail="Unable to fetch roles from auth service"
        )

    roles_data = resp.json()
    role_map = {
        role["id"]: role["description"]
        for role in roles_data
        if role.get("id") is not None and role.get("description")
    }

    config.logger.info(f"Fetched {len(role_map)} roles from API: {role_map}")
    return role_map


async def get_role_id_map(auth_token: Optional[str] = None) -> dict[int, str]:
    """Get the role ID map, using cache if available and not expired."""
    global _role_cache, _cache_expiry
    config = _get_config()
    cache_duration = timedelta(minutes=config.cache_duration_minutes)

    async with _cache_lock:
        # Check if cache is valid
        if _cache_expiry and datetime.now() < _cache_expiry and _role_cache:
            config.logger.debug("Using cached role mapping")
            return _role_cache.copy()

        # Fetch fresh data
        config.logger.info("Fetching roles from API (cache expired or empty)")
        try:
            _role_cache = await fetch_roles_from_api(auth_token)
            _cache_expiry = datetime.now() + cache_duration
            return _role_cache.copy()
        except Exception as e:
            # If we have stale cache data, use it as fallback
            if _role_cache:
                config.logger.warning(f"Using stale role cache due to API error: {e}")
                return _role_cache.copy()
            else:
                # No cache and API failed - this is a critical error
                config.logger.error("No role data available and API fetch failed")
                raise


async def _introspect_token(token: str) -> dict[str, Any]:
    """Introspect a token and return the response data."""
    config = _get_config()
    resp = await _make_auth_request(
        config.introspect_endpoint, method="POST", json_data={"token": token}
    )
    data = resp.json()

    if resp.status_code != 200:
        config.logger.warning(
            f"Token introspection failed with status {resp.status_code} and details: \n{data}"
        )
        raise _create_auth_exception("Token introspection failed")

    config.logger.debug(f"Token introspection response: {data}")

    if not data.get("active"):
        error_detail = data.get("error", "Inactive token")
        config.logger.warning(f"Inactive token: {error_detail}")
        raise _create_auth_exception(error_detail)

    return data


async def _create_user_from_payload(
    payload: dict[str, Any], token: str
) -> TokenIntrospect:
    """Create a TokenIntrospect object from token payload with role information."""
    config = _get_config()

    if not payload:
        raise ValueError("Missing payload in token introspection response")

    user_data = TokenIntrospect(**payload)
    role_id = payload.get("role")

    if role_id is not None:
        # Get dynamic role mapping using the current token
        role_map = await get_role_id_map(token)

        # Convert role ID to role name
        role_name = role_map.get(role_id, "unknown")

        # Set role information
        user_data.role_id = role_id
        user_data.role_name = role_name

        config.logger.info(
            f"User {user_data.sub} authenticated with role {role_name} (ID: {role_id})"
        )
    else:
        # Fallback if no role in token
        config.logger.warning(f"No role found in token for user {user_data.sub}")
        user_data.role_name = "unknown"

    return user_data


def get_current_user():
    oauth2_scheme = _get_oauth2_scheme()

    async def get_current_user(
        token: Annotated[str, Depends(oauth2_scheme)],
    ) -> TokenIntrospect:
        """
        Authentication that validates token and returns user information.
        """
        data = await _introspect_token(token)

        try:
            # Create user data from payload
            payload = data.get("payload", {})
            user_data = await _create_user_from_payload(payload, token)
        except (KeyError, ValidationError, ValueError) as e:
            config = _get_config()
            config.logger.error(f"Token validation error: {e}")
            raise _create_auth_exception("Invalid token payload")

        return user_data

    return get_current_user


def _create_role_checker(
    role_validator: Callable[[str, tuple], bool], required_roles: tuple
) -> Callable:
    """Create a role checking dependency function."""
    oauth2_scheme = _get_oauth2_scheme()

    async def check_role(
        token: Annotated[str, Depends(oauth2_scheme)],
    ) -> TokenIntrospect:
        user = await get_current_user()(token)
        user_role = getattr(user, "role_name", "")

        if not role_validator(user_role, required_roles) and user_role != "admin":
            config = _get_config()
            config.logger.warning(
                f"User {user.sub} denied access - has role {user_role}, requires {required_roles}"
            )
            role_desc = (
                required_roles[0]
                if len(required_roles) == 1
                else f"one of {', '.join(required_roles)}"
            )
            raise HTTPException(
                status_code=403, detail=f"Access denied. Required role: {role_desc}"
            )
        return user

    return check_role


def require_role(role_name: str):
    """
    Create a dependency that requires user to have a specific role.

    Usage:
        @app.get("/admin")
        async def admin_endpoint(user: TokenIntrospect = Depends(require_role("admin"))):
            ...
    """
    return _create_role_checker(
        lambda user_role, roles: user_role == roles[0], (role_name,)
    )


def require_any_role(*role_names: str):
    """
    Create a dependency that requires user to have at least one of the specified roles.

    Usage:
        @app.get("/admin")
        async def admin_endpoint(user: TokenIntrospect = Depends(require_any_role("admin", "superadmin"))):
            ...
    """
    return _create_role_checker(lambda user_role, roles: user_role in roles, role_names)
