from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask import abort
from flask import current_app
from flask import flash
from flask import g
from flask import has_app_context
from flask import redirect
from flask import request
from flask import session

from .config import COOKIE_DURATION
from .config import COOKIE_HTTPONLY
from .config import COOKIE_NAME
from .config import COOKIE_SAMESITE
from .config import COOKIE_SECURE
from .config import ID_ATTRIBUTE
from .config import LOGIN_MESSAGE
from .config import LOGIN_MESSAGE_CATEGORY
from .config import REFRESH_MESSAGE
from .config import REFRESH_MESSAGE_CATEGORY
from .config import SESSION_KEYS
from .config import USE_SESSION_FOR_NEXT
from .mixins import AnonymousUserMixin
from .signals import session_protected
from .signals import user_accessed
from .signals import user_loaded_from_cookie
from .signals import user_loaded_from_request
from .signals import user_needs_refresh
from .signals import user_unauthorized
from .utils import _create_identifier
from .utils import _user_context_processor
from .utils import decode_cookie
from .utils import encode_cookie
from .utils import expand_login_view
from .utils import login_url as make_login_url
from .utils import make_next_param


class _AppLoginConfiguration:
    """Holds the callbacks and the anonymous user factory that belong to a
    single application. Everything stored here is isolated per app, so a
    :class:`LoginManager` shared by several applications never leaks one
    app's authentication state into another.

    Attributes left as ``None`` mean "fall back to the instance default",
    which keeps applications that register callbacks without naming an app
    on the manager itself working exactly as before.
    """

    def __init__(self):
        self.user_callback = None
        self.request_callback = None
        self.anonymous_user = None
        self.unauthorized_callback = None
        self.needs_refresh_callback = None


class LoginManager:
    """This object is used to hold the settings used for logging in. Instances
    of :class:`LoginManager` are *not* bound to specific apps, so you can
    create one in the main body of your code and then bind it to your
    app in a factory function.
    """

    def __init__(self, app=None, add_context_processor=True):
        #: A class or factory function that produces an anonymous user, which
        #: is used when no one is logged in. This is the instance default; an
        #: app registered with :meth:`anonymous_user_loader` uses its own value.
        self._anonymous_user = AnonymousUserMixin

        #: The name of the view to redirect to when the user needs to log in.
        #: (This can be an absolute URL as well, if your authentication
        #: machinery is external to your application.)
        self.login_view = None

        #: Names of views to redirect to when the user needs to log in,
        #: per blueprint. If the key value is set to None the value of
        #: :attr:`login_view` will be used instead.
        self.blueprint_login_views = {}

        #: The message to flash when a user is redirected to the login page.
        self.login_message = LOGIN_MESSAGE

        #: The message category to flash when a user is redirected to the login
        #: page.
        self.login_message_category = LOGIN_MESSAGE_CATEGORY

        #: The name of the view to redirect to when the user needs to
        #: reauthenticate.
        self.refresh_view = None

        #: The message to flash when a user is redirected to the 'needs
        #: refresh' page.
        self.needs_refresh_message = REFRESH_MESSAGE

        #: The message category to flash when a user is redirected to the
        #: 'needs refresh' page.
        self.needs_refresh_message_category = REFRESH_MESSAGE_CATEGORY

        #: The mode to use session protection in. This can be either
        #: ``'basic'`` (the default) or ``'strong'``, or ``None`` to disable
        #: it.
        self.session_protection = "basic"

        #: If present, used to translate flash messages ``self.login_message``
        #: and ``self.needs_refresh_message``
        self.localize_callback = None

        self._unauthorized_callback = None

        self._needs_refresh_callback = None

        self.id_attribute = ID_ATTRIBUTE

        self._user_callback = None

        self._request_callback = None

        self._session_identifier_generator = _create_identifier

        if app is not None:
            self.init_app(app, add_context_processor)

    @property
    def anonymous_user(self):
        """The anonymous user factory for the current app, falling back to
        the instance default when the app has not registered its own."""
        config = self._current_app_config()
        if config is not None and config.anonymous_user is not None:
            return config.anonymous_user
        return self._anonymous_user

    @anonymous_user.setter
    def anonymous_user(self, value):
        self._anonymous_user = value

    @property
    def unauthorized_callback(self):
        config = self._current_app_config()
        if config is not None and config.unauthorized_callback is not None:
            return config.unauthorized_callback
        return self._unauthorized_callback

    @unauthorized_callback.setter
    def unauthorized_callback(self, value):
        self._unauthorized_callback = value

    @property
    def needs_refresh_callback(self):
        config = self._current_app_config()
        if config is not None and config.needs_refresh_callback is not None:
            return config.needs_refresh_callback
        return self._needs_refresh_callback

    @needs_refresh_callback.setter
    def needs_refresh_callback(self, value):
        self._needs_refresh_callback = value

    @property
    def user_callback(self):
        """Gets the user_loader callback set by user_loader decorator."""
        config = self._current_app_config()
        if config is not None and config.user_callback is not None:
            return config.user_callback
        return self._user_callback

    @property
    def request_callback(self):
        """Gets the request_loader callback set by request_loader decorator."""
        config = self._current_app_config()
        if config is not None and config.request_callback is not None:
            return config.request_callback
        return self._request_callback

    def _current_app_config(self):
        """Return the per-app configuration of the current app, or ``None``
        when there is no app context or the app was never initialized."""
        if not has_app_context():
            return None
        return current_app.extensions.get("login_manager")

    @staticmethod
    def _config_for_app(app):
        """Return the app's configuration, creating it on first use so a
        callback can be registered before :meth:`init_app`."""
        return app.extensions.setdefault("login_manager", _AppLoginConfiguration())

    def init_app(self, app, add_context_processor=True):
        """
        Configures an application. This registers an `after_request` call, and
        attaches this `LoginManager` to it as `app.login_manager`.

        :param app: The :class:`flask.Flask` object to configure.
        :type app: :class:`flask.Flask`
        :param add_context_processor: Whether to add a context processor to
            the app that adds a `current_user` variable to the template.
            Defaults to ``True``.
        :type add_context_processor: bool
        """
        app.login_manager = self
        # Keep any configuration already registered for this app so calling
        # init_app more than once never resets the app's authentication state.
        app.extensions.setdefault("login_manager", _AppLoginConfiguration())
        app.after_request(self._update_remember_cookie)

        if add_context_processor:
            app.context_processor(_user_context_processor)

    def unauthorized(self):
        """
        This is called when the user is required to log in. If you register a
        callback with :meth:`LoginManager.unauthorized_handler`, then it will
        be called. Otherwise, it will take the following actions:

            - Flash :attr:`LoginManager.login_message` to the user.

            - If the app is using blueprints find the login view for
              the current blueprint using `blueprint_login_views`. If the app
              is not using blueprints or the login view for the current
              blueprint is not specified use the value of `login_view`.

            - Redirect the user to the login view. (The page they were
              attempting to access will be passed in the ``next`` query
              string variable, so you can redirect there if present instead
              of the homepage. Alternatively, it will be added to the session
              as ``next`` if USE_SESSION_FOR_NEXT is set.)

        If :attr:`LoginManager.login_view` is not defined, then it will simply
        raise a HTTP 401 (Unauthorized) error instead.

        This should be returned from a view or before/after_request function,
        otherwise the redirect will have no effect.
        """
        user_unauthorized.send(current_app._get_current_object())

        if self.unauthorized_callback:
            return self.unauthorized_callback()

        if request.blueprint in self.blueprint_login_views:
            login_view = self.blueprint_login_views[request.blueprint]
        else:
            login_view = self.login_view

        if not login_view:
            abort(401)

        if self.login_message:
            if self.localize_callback is not None:
                flash(
                    self.localize_callback(self.login_message),
                    category=self.login_message_category,
                )
            else:
                flash(self.login_message, category=self.login_message_category)

        config = current_app.config
        if config.get("USE_SESSION_FOR_NEXT", USE_SESSION_FOR_NEXT):
            login_url = expand_login_view(login_view)
            session["_id"] = self._session_identifier_generator()
            session["next"] = make_next_param(login_url, request.url)
            redirect_url = make_login_url(login_view)
        else:
            redirect_url = make_login_url(login_view, next_url=request.url)

        return redirect(redirect_url)

    def user_loader(self, callback=None, app=None):
        """
        This sets the callback for reloading a user from the session. The
        function you set should take a user ID (a ``str``) and return a
        user object, or ``None`` if the user does not exist.

        :param callback: The callback for retrieving a user object.
        :type callback: callable
        :param app: The application this callback belongs to. If ``None`` the
            callback is stored as the instance default, which every app uses
            unless it registers its own. Passing an app keeps the callback
            isolated from the other applications sharing this manager.
        :type app: :class:`flask.Flask`
        """
        if callback is None:
            return lambda cb: self.user_loader(cb, app)
        if app is None:
            self._user_callback = callback
        else:
            self._config_for_app(app).user_callback = callback
        return callback

    def request_loader(self, callback=None, app=None):
        """
        This sets the callback for loading a user from a Flask request.
        The function you set should take Flask request object and
        return a user object, or `None` if the user does not exist.

        :param callback: The callback for retrieving a user object.
        :type callback: callable
        :param app: The application this callback belongs to. If ``None`` the
            callback is stored as the instance default, which every app uses
            unless it registers its own. Passing an app keeps the callback
            isolated from the other applications sharing this manager.
        :type app: :class:`flask.Flask`
        """
        if callback is None:
            return lambda cb: self.request_loader(cb, app)
        if app is None:
            self._request_callback = callback
        else:
            self._config_for_app(app).request_callback = callback
        return callback

    def unauthorized_handler(self, callback=None, app=None):
        """
        This will set the callback for the `unauthorized` method, which among
        other things is used by `login_required`. It takes no arguments, and
        should return a response to be sent to the user instead of their
        normal view.

        :param callback: The callback for unauthorized users.
        :type callback: callable
        :param app: The application this callback belongs to. If ``None`` the
            callback is stored as the instance default, which every app uses
            unless it registers its own. Passing an app keeps the callback
            isolated from the other applications sharing this manager.
        :type app: :class:`flask.Flask`
        """
        if callback is None:
            return lambda cb: self.unauthorized_handler(cb, app)
        if app is None:
            self._unauthorized_callback = callback
        else:
            self._config_for_app(app).unauthorized_callback = callback
        return callback

    def needs_refresh_handler(self, callback=None, app=None):
        """
        This will set the callback for the `needs_refresh` method, which among
        other things is used by `fresh_login_required`. It takes no arguments,
        and should return a response to be sent to the user instead of their
        normal view.

        :param callback: The callback for unauthorized users.
        :type callback: callable
        :param app: The application this callback belongs to. If ``None`` the
            callback is stored as the instance default, which every app uses
            unless it registers its own. Passing an app keeps the callback
            isolated from the other applications sharing this manager.
        :type app: :class:`flask.Flask`
        """
        if callback is None:
            return lambda cb: self.needs_refresh_handler(cb, app)
        if app is None:
            self._needs_refresh_callback = callback
        else:
            self._config_for_app(app).needs_refresh_callback = callback
        return callback

    def anonymous_user_loader(self, anonymous_user=None, app=None):
        """
        This sets the class or factory function that produces an anonymous
        user when no one is logged in.

        :param anonymous_user: A class or factory function producing an
            anonymous user.
        :type anonymous_user: callable
        :param app: The application this anonymous user belongs to. If
            ``None`` it is stored as the instance default, which every app
            uses unless it registers its own. Passing an app keeps it
            isolated from the other applications sharing this manager.
        :type app: :class:`flask.Flask`
        """
        if anonymous_user is None:
            return lambda cb: self.anonymous_user_loader(cb, app)
        if app is None:
            self._anonymous_user = anonymous_user
        else:
            self._config_for_app(app).anonymous_user = anonymous_user
        return anonymous_user

    def needs_refresh(self):
        """
        This is called when the user is logged in, but they need to be
        reauthenticated because their session is stale. If you register a
        callback with `needs_refresh_handler`, then it will be called.
        Otherwise, it will take the following actions:

            - Flash :attr:`LoginManager.needs_refresh_message` to the user.

            - Redirect the user to :attr:`LoginManager.refresh_view`. (The page
              they were attempting to access will be passed in the ``next``
              query string variable, so you can redirect there if present
              instead of the homepage.)

        If :attr:`LoginManager.refresh_view` is not defined, then it will
        simply raise a HTTP 401 (Unauthorized) error instead.

        This should be returned from a view or before/after_request function,
        otherwise the redirect will have no effect.
        """
        user_needs_refresh.send(current_app._get_current_object())

        if self.needs_refresh_callback:
            return self.needs_refresh_callback()

        if not self.refresh_view:
            abort(401)

        if self.needs_refresh_message:
            if self.localize_callback is not None:
                flash(
                    self.localize_callback(self.needs_refresh_message),
                    category=self.needs_refresh_message_category,
                )
            else:
                flash(
                    self.needs_refresh_message,
                    category=self.needs_refresh_message_category,
                )

        config = current_app.config
        if config.get("USE_SESSION_FOR_NEXT", USE_SESSION_FOR_NEXT):
            login_url = expand_login_view(self.refresh_view)
            session["_id"] = self._session_identifier_generator()
            session["next"] = make_next_param(login_url, request.url)
            redirect_url = make_login_url(self.refresh_view)
        else:
            login_url = self.refresh_view
            redirect_url = make_login_url(login_url, next_url=request.url)

        return redirect(redirect_url)

    def _update_request_context_with_user(self, user=None):
        """Store the given user as ctx.user."""

        if user is None:
            user = self.anonymous_user()

        g._login_user = user

    def _load_user(self):
        """Loads user from session or remember_me cookie as applicable"""

        user_callback = self.user_callback
        request_callback = self.request_callback

        if user_callback is None and request_callback is None:
            raise Exception(
                "Missing user_loader or request_loader. Refer to "
                "http://flask-login.readthedocs.io/#how-it-works "
                "for more info."
            )

        user_accessed.send(current_app._get_current_object())

        # Check SESSION_PROTECTION
        if self._session_protection_failed():
            return self._update_request_context_with_user()

        user = None

        # Load user from Flask Session
        user_id = session.get("_user_id")
        if user_id is not None and user_callback is not None:
            user = user_callback(user_id)

        # Load user from Remember Me Cookie or Request Loader
        if user is None:
            config = current_app.config
            cookie_name = config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
            has_cookie = cookie_name in request.cookies and session.get("_remember") != "clear"
            if has_cookie:
                cookie = request.cookies[cookie_name]
                user = self._load_user_from_remember_cookie(cookie)
            elif request_callback:
                user = self._load_user_from_request(request)

        return self._update_request_context_with_user(user)

    def _session_protection_failed(self):
        sess = session._get_current_object()
        ident = self._session_identifier_generator()

        app = current_app._get_current_object()
        mode = app.config.get("SESSION_PROTECTION", self.session_protection)

        if not mode or mode not in ["basic", "strong"]:
            return False

        # if the sess is empty, it's an anonymous user or just logged out
        # so we can skip this
        if sess and ident != sess.get("_id", None):
            if mode == "basic" or sess.permanent:
                if sess.get("_fresh") is not False:
                    sess["_fresh"] = False
                session_protected.send(app)
                return False
            elif mode == "strong":
                for k in SESSION_KEYS:
                    sess.pop(k, None)

                sess["_remember"] = "clear"
                session_protected.send(app)
                return True

        return False

    def _load_user_from_remember_cookie(self, cookie):
        user_id = decode_cookie(cookie)
        if user_id is not None:
            session["_user_id"] = user_id
            session["_fresh"] = False
            user = None
            user_callback = self.user_callback
            if user_callback:
                user = user_callback(user_id)
            if user is not None:
                app = current_app._get_current_object()
                user_loaded_from_cookie.send(app, user=user)
                return user
        return None

    def _load_user_from_request(self, request):
        request_callback = self.request_callback
        if request_callback:
            user = request_callback(request)
            if user is not None:
                app = current_app._get_current_object()
                user_loaded_from_request.send(app, user=user)
                return user
        return None

    def _update_remember_cookie(self, response):
        config = current_app.config
        cookie_name = config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
        has_cookie = cookie_name in request.cookies and session.get("_remember") != "clear"
        refresh = current_app.config.get("REMEMBER_COOKIE_REFRESH_EACH_REQUEST") and has_cookie

        operation = session.pop("_remember", None)
        if not operation and not refresh:
            return response

        if operation == "clear":
            self._clear_cookie(response)

        if operation == "set" or refresh:
            self._set_cookie(response)

        return response

    def _set_cookie(self, response):
        if "_user_id" not in session:
            return

        # cookie settings
        config = current_app.config
        cookie_name = config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
        domain = config.get("REMEMBER_COOKIE_DOMAIN")
        path = config.get("REMEMBER_COOKIE_PATH", "/")

        secure = config.get("REMEMBER_COOKIE_SECURE", COOKIE_SECURE)
        httponly = config.get("REMEMBER_COOKIE_HTTPONLY", COOKIE_HTTPONLY)
        samesite = config.get("REMEMBER_COOKIE_SAMESITE", COOKIE_SAMESITE)

        if "_remember_seconds" in session:
            duration = timedelta(seconds=session["_remember_seconds"])
        else:
            duration = config.get("REMEMBER_COOKIE_DURATION", COOKIE_DURATION)

        # prepare data
        data = encode_cookie(str(session["_user_id"]))

        if isinstance(duration, int):
            duration = timedelta(seconds=duration)

        try:
            expires = datetime.now(timezone.utc) + duration
        except TypeError as e:
            raise Exception(
                f"REMEMBER_COOKIE_DURATION must be a datetime.timedelta, instead got: {duration}"
            ) from e

        # actually set it
        response.set_cookie(
            cookie_name,
            value=data,
            expires=expires,
            domain=domain,
            path=path,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )

    def _clear_cookie(self, response):
        config = current_app.config
        cookie_name = config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
        domain = config.get("REMEMBER_COOKIE_DOMAIN")
        path = config.get("REMEMBER_COOKIE_PATH", "/")
        response.delete_cookie(cookie_name, domain=domain, path=path)
