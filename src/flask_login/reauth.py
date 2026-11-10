from enum import Enum

#: The authentication level recorded by a plain username/password login or a
#: call to :func:`~flask_login.confirm_login` without an explicit level. A
#: view that only requires a recent re-authentication (and makes no
#: distinction between authentication methods) can rely on this default.
DEFAULT_AUTH_LEVEL = 0


class ReauthReason(str, Enum):
    """Human-readable reasons for which a view may demand
    re-authentication.

    The values deliberately describe the *policy decision* and never include
    credentials or other secrets, so they are safe to expose to callbacks,
    signals, logs, or clients.
    """

    #: The session is not fresh at all (for example it was restored from a
    #: "remember me" cookie or the freshness proof was removed).
    NOT_FRESH = "not_fresh"

    #: The last fresh authentication happened longer ago than the view allows.
    EXPIRED = "expired"

    #: The method used for the last fresh authentication is weaker than the
    #: view requires.
    WEAK_AUTH_LEVEL = "weak_auth_level"
