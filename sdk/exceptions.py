class SDKError(Exception):
  """Base exception for the SDK."""


class AuthenticationError(SDKError):
  """Raised when login or key-swap fails."""


class RefreshError(SDKError):
  """Raised when token refresh fails."""


class RegistrationError(SDKError):
  """Raised when model registration fails."""

class APIError(SDKError):
  """Raised when API error occurs."""