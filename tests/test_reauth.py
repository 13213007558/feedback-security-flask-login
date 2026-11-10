"""Tests for freshness age and authentication-level requirements.

These tests use a fixed, manually advanced clock and two distinct
authentication methods ("password" at level 1 and "hardware key" at level 2)
to walk through ordinary login, low- and high-level re-confirmation,
freshness timeout, failed re-authentication, "remember me" restoration and
logout without relying on real time or sleeping.
"""

import unittest
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask import Flask
from flask import redirect
from flask import session
from flask import url_for

from flask_login import confirm_login
from flask_login import DEFAULT_AUTH_LEVEL
from flask_login import fresh_auth_level
from flask_login import fresh_login_age
from flask_login import fresh_login_required
from flask_login import login_fresh
from flask_login import login_required
from flask_login import login_user
from flask_login import LoginManager
from flask_login import logout_user
from flask_login import reauthentication_required
from flask_login import reauth_required
from flask_login import ReauthReason
from flask_login import UserMixin

#: Two authentication methods with different strengths.
PASSWORD_LEVEL = 1
HARDWARE_KEY_LEVEL = 2

#: Secrets shared by the fake re-authentication endpoints. They must never
#: appear in any reason, callback argument or signal payload.
PASSWORD_SECRET = "correct horse battery staple"
HARDWARE_KEY_SECRET = "tap-the-usb-key"

START = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)


class Account(UserMixin):
    def __init__(self, user_id, name):
        self.id = user_id
        self.name = name

    def get_id(self):
        return str(self.id)


USER = Account(1, "Notch")
ACCOUNTS = {"1": USER}


class ReauthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["SECRET_KEY"] = "deterministic"
        self.app.config["SESSION_PROTECTION"] = None
        self.app.config["REMEMBER_COOKIE_NAME"] = "remember"
        self.app.response_class.autocorrect_location_header = False

        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)

        # A fixed clock shared with the code under test.
        self.clock = START

        def fixed_clock():
            return self.clock

        self.login_manager._now = fixed_clock

        @self.login_manager.user_loader
        def load_user(user_id):
            return ACCOUNTS.get(str(user_id))

        @self.login_manager.reauth_handler
        def on_reauth(reason):
            # A real application would render a re-authentication form here.
            self.seen_reasons.append(reason)
            return f"reauth required: {reason.value}", 403

        self.seen_reasons = []

        @self.app.route("/login", methods=["POST"])
        def login():
            # The level is chosen by the application based on the verified
            # authentication method; it is never read from request data.
            login_user(USER, auth_level=PASSWORD_LEVEL)
            return "logged in"

        @self.app.route("/login-remember", methods=["POST"])
        def login_remember():
            login_user(USER, remember=True, auth_level=PASSWORD_LEVEL)
            return "logged in and remembered"

        @self.app.route("/login-nonfresh", methods=["POST"])
        def login_nonfresh():
            login_user(USER, fresh=False, auth_level=HARDWARE_KEY_LEVEL)
            return "logged in non-fresh"

        def _verify(method, provided):
            if method == "password":
                return provided == PASSWORD_SECRET, PASSWORD_LEVEL
            if method == "hardware-key":
                return provided == HARDWARE_KEY_SECRET, HARDWARE_KEY_LEVEL
            return False, None

        @self.app.route("/reauth", methods=["POST"])
        def reauth():
            method = session["reauth_method"]
            ok, level = _verify(method, self._provided_secret)
            if not ok:
                # Failed re-authentication must not touch the existing proof.
                return "invalid credentials", 401
            confirm_login(auth_level=level)
            target = session.pop("reauth_next", None)
            return redirect(target or url_for("profile"))

        @self.app.route("/profile")
        @reauth_required(max_age=timedelta(minutes=5))
        def profile():
            return "profile data"

        @self.app.route("/payment-account")
        @reauth_required(max_age=timedelta(minutes=2), min_level=HARDWARE_KEY_LEVEL)
        def payment_account():
            return "payment account changed"

        @self.app.route("/legacy-secret")
        @login_required
        @reauth_required()
        def legacy_secret():
            return "legacy secret"

        @self.app.route("/fresh-only")
        @fresh_login_required
        def fresh_only():
            return "fresh only"

        @self.app.route("/status")
        def status():
            return (
                f"fresh={login_fresh()}"
                f" level={fresh_auth_level()}"
                f" age={fresh_login_age()}"
            )

        @self.app.route("/logout")
        def logout():
            return str(logout_user())

        @self.app.errorhandler(404)
        def handle_404(error):
            raise error

        self._provided_secret = PASSWORD_SECRET

    def _begin_reauth(self, client, method, next_url):
        with client.session_transaction() as sess:
            sess["reauth_method"] = method
            sess["reauth_next"] = next_url

    #
    # Ordinary login writes a timestamp and a method level
    #
    def test_fresh_login_records_proof(self):
        with self.app.test_client() as client:
            response = client.post("/login")
            self.assertEqual(response.status_code, 200)

            response = client.get("/status")
            self.assertEqual(
                response.data.decode(),
                f"fresh=True level={PASSWORD_LEVEL} age=0:00:00",
            )
            self.assertEqual(client.get("/profile").status_code, 200)

    def test_nonfresh_login_writes_no_proof(self):
        with self.app.test_client() as client:
            client.post("/login-nonfresh")

            response = client.get("/status")
            # Even though a high level was passed, no proof is recorded for a
            # non-fresh login.
            self.assertEqual(response.data.decode(), "fresh=False level=None age=None")
            self.assertEqual(client.get("/profile").status_code, 403)
            self.assertEqual(self.seen_reasons, [ReauthReason.NOT_FRESH])

    #
    # Independent view requirements within one shared session
    #
    def test_each_view_judges_its_own_requirements(self):
        with self.app.test_client() as client:
            client.post("/login")

            # Both views accept the fresh password-level proof initially.
            self.assertEqual(client.get("/profile").status_code, 200)
            payment = client.get("/payment-account")
            self.assertEqual(payment.status_code, 403)
            self.assertEqual(self.seen_reasons, [ReauthReason.WEAK_AUTH_LEVEL])

            # The weaker view stays usable: a rejection does not poison the
            # session for views with lower requirements.
            self.assertEqual(client.get("/profile").status_code, 200)

    def test_low_level_confirmation_satisfies_only_low_requirement(self):
        with self.app.test_client() as client:
            client.post("/login")
            self.clock += timedelta(minutes=10)

            # The profile proof has expired; payment also needs a stronger
            # method.
            self.assertEqual(client.get("/profile").status_code, 403)
            self.assertEqual(client.get("/payment-account").status_code, 403)

            # Re-authenticate with the weaker password method.
            self._begin_reauth(client, "password", "/profile")
            self._provided_secret = PASSWORD_SECRET
            response = client.post("/reauth")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/profile")
            self.assertEqual(client.get("/profile").status_code, 200)

            # Payment still rejects: the level requirement is independent.
            response = client.get("/payment-account")
            self.assertEqual(response.status_code, 403)
            self.assertIn(ReauthReason.WEAK_AUTH_LEVEL, self.seen_reasons)

    def test_high_level_confirmation_satisfies_both_views(self):
        with self.app.test_client() as client:
            client.post("/login")
            self.clock += timedelta(minutes=10)

            self._begin_reauth(client, "hardware-key", "/payment-account")
            self._provided_secret = HARDWARE_KEY_SECRET
            response = client.post("/reauth")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/payment-account")

            # Following the stored next URL completes the original restricted
            # operation after successful re-authentication.
            self.assertEqual(client.get("/payment-account").status_code, 200)
            self.assertEqual(client.get("/profile").status_code, 200)

            with client.session_transaction() as sess:
                self.assertEqual(sess["_fresh_level"], HARDWARE_KEY_LEVEL)

    def test_failed_reauthentication_keeps_old_proof(self):
        with self.app.test_client() as client:
            client.post("/login")
            self.clock += timedelta(minutes=10)

            old_proof = self._read_proof(client)

            self._begin_reauth(client, "hardware-key", "/payment-account")
            self._provided_secret = "wrong secret"
            response = client.post("/reauth")
            self.assertEqual(response.status_code, 401)

            # Nothing was refreshed: timestamp and level are unchanged.
            self.assertEqual(self._read_proof(client), old_proof)
            self.assertEqual(client.get("/payment-account").status_code, 403)

    def test_freshness_timeout_uses_fixed_clock(self):
        with self.app.test_client() as client:
            client.post("/login")

            self.clock = START + timedelta(minutes=4, seconds=59)
            self.assertEqual(client.get("/profile").status_code, 200)

            self.clock = START + timedelta(minutes=5, seconds=1)
            response = client.get("/profile")
            self.assertEqual(response.status_code, 403)
            self.assertEqual(self.seen_reasons, [ReauthReason.EXPIRED])

            # Payment also rejects on age, even though its level requirement
            # was already unmet; expiry is reported first.
            response = client.get("/payment-account")
            self.assertEqual(response.status_code, 403)
            self.assertEqual(self.seen_reasons[-1], ReauthReason.EXPIRED)

    #
    # "Remember me" restoration cannot invent freshness or a high level
    #
    def test_remembered_session_has_no_fresh_proof(self):
        with self.app.test_client() as client:
            client.post("/login-remember")
            self.assertTrue(client.get_cookie("remember") is not None)

            # Simulate the browser closing: the session is gone but the
            # remember cookie survives.
            with client.session_transaction() as sess:
                sess.clear()

            self.clock += timedelta(minutes=1)
            response = client.get("/profile")
            self.assertEqual(response.status_code, 403)
            self.assertEqual(self.seen_reasons, [ReauthReason.NOT_FRESH])

            response = client.get("/payment-account")
            self.assertEqual(response.status_code, 403)
            self.assertIn(ReauthReason.NOT_FRESH, self.seen_reasons)

            # A remembered user is still authenticated, so login_required-only
            # views remain available while reauth views stay closed.
            with client.session_transaction() as sess:
                self.assertFalse(sess["_fresh"])
                self.assertNotIn("_fresh_at", sess)
                self.assertNotIn("_fresh_level", sess)

    def test_remembered_user_can_recover_with_real_reauth(self):
        with self.app.test_client() as client:
            client.post("/login-remember")
            with client.session_transaction() as sess:
                sess.clear()
            self.assertEqual(client.get("/profile").status_code, 403)

            self._begin_reauth(client, "password", "/profile")
            response = client.post("/reauth")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(client.get("/profile").status_code, 200)
            self.assertEqual(fresh_auth_level(), PASSWORD_LEVEL)

    #
    # Logout clears every freshness artifact
    #
    def test_logout_clears_freshness_proof(self):
        with self.app.test_client() as client:
            client.post("/login")
            self.assertEqual(client.get("/profile").status_code, 200)

            client.get("/logout")
            with client.session_transaction() as sess:
                self.assertNotIn("_fresh", sess)
                self.assertNotIn("_fresh_at", sess)
                self.assertNotIn("_fresh_level", sess)
                self.assertNotIn("_user_id", sess)

            response = client.get("/profile")
            # No authenticated user: the unauthorized path, not the reauth
            # callback.
            self.assertEqual(response.status_code, 401)
            self.assertEqual(self.seen_reasons, [])

    #
    # Request parameters cannot self-declare the authentication level
    #
    def test_request_cannot_raise_recorded_level(self):
        with self.app.test_client() as client:
            client.post("/login")

            # Even when a query parameter claims a high level, the view only
            # trusts the session proof.
            response = client.get("/payment-account?auth_level=2")
            self.assertEqual(response.status_code, 403)
            self.assertEqual(self.seen_reasons, [ReauthReason.WEAK_AUTH_LEVEL])

    def test_app_must_not_derive_level_from_request(self):
        # The login view writes the level of the verified method; query or
        # form fields claiming a different level cannot change what is stored.
        with self.app.test_client() as client:
            client.post("/login?auth_level=99")
            with client.session_transaction() as sess:
                self.assertEqual(sess["_fresh_level"], PASSWORD_LEVEL)

    def test_lowered_level_in_session_still_rejects_until_reauth(self):
        # Server-side session data is trusted storage, but the only way to
        # regain a high level is a genuine high-level confirmation: merely
        # editing the stored level downward (or upward) cannot substitute for
        # re-authentication. Here a downgrade keeps the view rejecting.
        with self.app.test_client() as client:
            client.post("/login")
            with client.session_transaction() as sess:
                sess["_fresh_level"] = 0
            response = client.get("/payment-account")
            self.assertEqual(response.status_code, 403)
            self.assertEqual(self.seen_reasons, [ReauthReason.WEAK_AUTH_LEVEL])

    #
    # Callback and signal carry an understandable reason without secrets
    #
    def test_reauth_callback_receives_reason_only(self):
        with self.app.test_client() as client:
            client.post("/login")
            self.clock += timedelta(minutes=10)
            response = client.get("/payment-account")
            self.assertEqual(response.status_code, 403)

            body = response.data.decode()
            self.assertIn("reauth required: expired", body)
            self.assertNotIn(PASSWORD_SECRET, body)
            self.assertNotIn(HARDWARE_KEY_SECRET, body)

    def test_signal_carries_reason_without_secrets(self):
        heard = []

        def receiver(sender, reason):
            heard.append(reason)

        reauthentication_required.connect(receiver)
        try:
            with self.app.test_client() as client:
                client.post("/login-remember")
                with client.session_transaction() as sess:
                    sess.clear()

                client.get("/payment-account")
                # A fresh login stamped before the clock advances; moving the
                # clock afterwards makes the same proof expire.
                client.post("/login")
                self.clock += timedelta(minutes=10)
                client.get("/profile")
        finally:
            reauthentication_required.disconnect(receiver)

        self.assertEqual(
            heard,
            [ReauthReason.NOT_FRESH, ReauthReason.EXPIRED],
        )
        for reason in heard:
            self.assertIsInstance(reason, ReauthReason)
            self.assertNotIn(PASSWORD_SECRET, reason.value)
            self.assertNotIn(HARDWARE_KEY_SECRET, reason.value)

    def test_legacy_needs_refresh_signal_is_unchanged(self):
        from flask_login import user_needs_refresh

        heard = []

        def legacy_receiver(sender):
            heard.append(sender)

        user_needs_refresh.connect(legacy_receiver)
        try:
            with self.app.test_client() as client:
                client.post("/login-remember")
                with client.session_transaction() as sess:
                    sess.clear()
                # fresh_login_required keeps using the legacy signal path and
                # the zero-argument needs_refresh handler behavior.
                response = client.get("/fresh-only")
                self.assertEqual(response.status_code, 401)
        finally:
            user_needs_refresh.disconnect(legacy_receiver)

        self.assertEqual(len(heard), 1)
        # The reauth callback is not part of the legacy path.
        self.assertEqual(self.seen_reasons, [])

    #
    # Unauthenticated requests use the unauthorized path, not reauth
    #
    def test_anonymous_request_is_unauthorized(self):
        response = self.app.test_client().get("/payment-account")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.seen_reasons, [])

    def test_falls_back_to_legacy_refresh_handling_without_reauth_handler(self):
        self.login_manager.reauth_callback = None
        self.login_manager.refresh_view = "/refresh-view"

        @self.app.route("/refresh-view")
        def refresh_view():
            return "refresh form"

        with self.app.test_client() as client:
            client.post("/login-remember")
            with client.session_transaction() as sess:
                sess.clear()

            response = client.get("/profile")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/refresh-view?next=%2Fprofile")
            self.assertEqual(self.seen_reasons, [])

    def test_session_protection_revokes_freshness_proof(self):
        # Enable basic session protection (setUp disables it globally).
        self.app.config["SESSION_PROTECTION"] = "basic"

        with self.app.test_client() as client:
            client.post("/login")
            with client.session_transaction() as sess:
                self.assertIn("_fresh_at", sess)

            # A changed browser fingerprint trips basic session protection,
            # which marks the session stale and must remove the proof.
            response = client.get("/profile", headers={"User-Agent": "different"})
            self.assertEqual(response.status_code, 403)
            self.assertEqual(self.seen_reasons, [ReauthReason.NOT_FRESH])
            with client.session_transaction() as sess:
                self.assertFalse(sess["_fresh"])
                self.assertNotIn("_fresh_at", sess)
                self.assertNotIn("_fresh_level", sess)

    #
    # Async views are protected exactly like sync views
    #
    @unittest.skipIf(not hasattr(Flask, "ensure_sync"), "Flask version before async")
    def test_async_view_enforces_same_requirements(self):
        import asyncio

        @self.app.route("/async-payment")
        @reauth_required(max_age=timedelta(minutes=2), min_level=HARDWARE_KEY_LEVEL)
        async def async_payment():
            await asyncio.sleep(0)
            return "async payment ok"

        with self.app.test_client() as client:
            client.post("/login")
            response = client.get("/async-payment")
            self.assertEqual(response.status_code, 403)
            self.assertEqual(self.seen_reasons, [ReauthReason.WEAK_AUTH_LEVEL])

            self._begin_reauth(client, "hardware-key", "/async-payment")
            self._provided_secret = HARDWARE_KEY_SECRET
            client.post("/reauth")
            response = client.get("/async-payment")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "async payment ok")

    #
    # Decorator metadata and argument validation
    #
    def test_decorator_exposes_declared_requirements(self):
        self.assertEqual(
            self.app.view_functions["payment_account"].reauth_max_age,
            timedelta(minutes=2),
        )
        self.assertEqual(
            self.app.view_functions["payment_account"].reauth_min_level,
            HARDWARE_KEY_LEVEL,
        )
        self.assertEqual(
            self.app.view_functions["legacy_secret"].reauth_max_age,
            None,
        )
        self.assertEqual(
            self.app.view_functions["legacy_secret"].reauth_min_level,
            DEFAULT_AUTH_LEVEL,
        )

    def test_invalid_arguments_raise(self):
        with self.assertRaises(TypeError):
            reauth_required(max_age=300)
        with self.assertRaises(TypeError):
            reauth_required(min_level="high")
        with self.assertRaises(ValueError):
            reauth_required(min_level=-1)

        with self.app.test_request_context():
            with self.assertRaises(TypeError):
                login_user(USER, auth_level="strong")
            with self.assertRaises(TypeError):
                confirm_login(auth_level="strong")

    def test_reauth_continues_original_operation_via_next(self):
        with self.app.test_client() as client:
            client.post("/login")
            self.clock += timedelta(minutes=10)

            # Hitting the protected view stores where the user wanted to go;
            # the application's reauth flow here mirrors that with an explicit
            # next URL, then resumes the original operation.
            response = client.get("/payment-account")
            self.assertEqual(response.status_code, 403)

            self._begin_reauth(client, "hardware-key", "/payment-account")
            self._provided_secret = HARDWARE_KEY_SECRET
            response = client.post("/reauth")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/payment-account")
            resumed = client.get(response.location)
            self.assertEqual(resumed.status_code, 200)
            self.assertEqual(resumed.data.decode(), "payment account changed")

    #
    # Helpers
    #
    def _read_proof(self, client):
        with client.session_transaction() as sess:
            return sess.get("_fresh_at"), sess.get("_fresh_level")


if __name__ == "__main__":
    unittest.main()
