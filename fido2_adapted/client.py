# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
from __future__ import absolute_import, unicode_literals, division

from fido2.hid import STATUS
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1, APDU, ApduError
from fido2.ctap2 import CTAP2, PinProtocolV1, AttestationObject, AssertionResponse, Info
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    _StringEnum,
    _DataObject
)
from fido2.cose import ES256
from fido2.rpid import verify_rp_id, verify_app_id
from fido2.utils import sha256, hmac_sha256, websafe_decode, websafe_encode
from fido2.client import _BaseClient, WEBAUTHN_TYPE
from enum import Enum, IntEnum, unique
from threading import Timer, Event

import json
import six
import platform

class PublicKeyCredentialRequestOptions(_DataObject):
    def __init__(
        self,
        challenge,
        timeout=None,
        rp_id=None,
        allow_credentials=None,
        user_verification=None,
        extensions=None,
        user_presence=None,
    ):
        super(PublicKeyCredentialRequestOptions, self).__init__(
            challenge=challenge,
            timeout=timeout,
            rp_id=rp_id,
            allow_credentials=PublicKeyCredentialDescriptor._wrap_list(
                allow_credentials
            ),
            user_verification=UserVerificationRequirement._wrap(user_verification),
            extensions=extensions,
            user_presence=UserPresenceRequirement._wrap(user_presence)
        )

@unique
class UserPresenceRequirement(_StringEnum):
    REQUIRED = "required"
    DISCOURAGED = "discouraged"

class Fido2Client(_BaseClient):
    """WebAuthn-like client implementation.

    The client allows registration and authentication of WebAuthn credentials against
    an Authenticator using CTAP (1 or 2).

    :param device: CtapDevice to use.
    :param str origin: The origin to use.
    :param verify: Function to verify an RP ID for a given origin.
    """

    def __init__(self, device, origin, verify=verify_rp_id):
        super(Fido2Client, self).__init__(origin, verify)

        self.ctap1_poll_delay = 0.25
        try:
            self.ctap2 = CTAP2(device)
            self.info = self.ctap2.get_info()
            if PinProtocolV1.VERSION in self.info.pin_protocols:
                self.pin_protocol = PinProtocolV1(self.ctap2)
            else:
                self.pin_protocol = None
            self._do_make_credential = self._ctap2_make_credential
            self._do_get_assertion = self._ctap2_get_assertion
        except (ValueError, CtapError):
            self.ctap1 = CTAP1(device)
            self.info = _CTAP1_INFO
            self._do_make_credential = self._ctap1_make_credential
            self._do_get_assertion = self._ctap1_get_assertion

    def _get_ctap_uv(self, uv_requirement, pin_provided):
        pin_supported = "clientPin" in self.info.options
        pin_set = self.info.options.get("clientPin", False)

        if pin_provided:
            if not pin_set:
                raise ClientError.ERR.BAD_REQUEST("PIN provided, but not set/supported")
            else:
                return False  # If PIN is provided, internal uv is not used

        uv_supported = "uv" in self.info.options
        uv_set = self.info.options.get("uv", False)

        if uv_requirement == UserVerificationRequirement.REQUIRED:
            if not uv_set:
                raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(
                    "User verification not configured/supported"
                )
            return True
        elif uv_requirement == UserVerificationRequirement.PREFERRED:
            if not uv_set and (uv_supported or pin_supported):
                raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(
                    "User verification supported but not configured"
                )
            return uv_set

        return False

    def _get_ctap_up(self, up_requirement):
        if up_requirement == UserPresenceRequirement.DISCOURAGED:
            return False
        else:
            return True

    def make_credential(self, options, **kwargs):
        """Creates a credential.

        :param options: PublicKeyCredentialCreationOptions data.
        :param pin: (optional) Used if PIN verification is required.
        :param threading.Event event: (optional) Signal to abort the operation.
        :param on_keepalive: (optional) function to call with CTAP status updates.
        """

        options = PublicKeyCredentialCreationOptions._wrap(options)
        pin = kwargs.get("pin")
        event = kwargs.get("event", Event())
        if options.timeout:
            timer = Timer(options.timeout / 1000, event.set)
            timer.daemon = True
            timer.start()

        self._verify_rp_id(options.rp.id)

        client_data = self._build_client_data(
            WEBAUTHN_TYPE.MAKE_CREDENTIAL, options.challenge
        )

        selection = options.authenticator_selection or AuthenticatorSelectionCriteria()
        try:
            return (
                self._do_make_credential(
                    client_data,
                    options.rp,
                    options.user,
                    options.pub_key_cred_params,
                    options.exclude_credentials,
                    options.extensions,
                    selection.require_resident_key,
                    self._get_ctap_uv(selection.user_verification, pin is not None),
                    pin,
                    event,
                    kwargs.get("on_keepalive"),
                ),
                client_data,
            )
        except CtapError as e:
            raise _ctap2client_err(e)
        finally:
            if options.timeout:
                timer.cancel()

    def _ctap2_make_credential(
        self,
        client_data,
        rp,
        user,
        key_params,
        exclude_list,
        extensions,
        rk,
        uv,
        pin,
        event,
        on_keepalive,
    ):
        pin_auth = None
        pin_protocol = None
        if pin:
            pin_protocol = self.pin_protocol.VERSION
            pin_token = self.pin_protocol.get_pin_token(pin)
            pin_auth = hmac_sha256(pin_token, client_data.hash)[:16]
        elif self.info.options.get("clientPin") and not uv:
            raise ClientError.ERR.BAD_REQUEST("PIN required but not provided")

        if not (rk or uv):
            options = None
        else:
            options = {}
            if rk:
                options["rk"] = True
            if uv:
                options["uv"] = True

        if exclude_list:
            # Filter out credential IDs which are too long
            max_len = self.info.max_cred_id_length
            if max_len:
                exclude_list = [e for e in exclude_list if len(e) <= max_len]

            # Reject the request if too many credentials remain.
            max_creds = self.info.max_creds_in_list
            if max_creds and len(exclude_list) > max_creds:
                raise ClientError.ERR.BAD_REQUEST("exclude_list too long")

        return self.ctap2.make_credential(
            client_data.hash,
            rp,
            user,
            key_params,
            exclude_list if exclude_list else None,
            extensions,
            options,
            pin_auth,
            pin_protocol,
            event,
            on_keepalive,
        )

    def _ctap1_make_credential(
        self,
        client_data,
        rp,
        user,
        key_params,
        exclude_list,
        extensions,
        rk,
        uv,
        pin,
        event,
        on_keepalive,
    ):
        if rk or uv or ES256.ALGORITHM not in [p.alg for p in key_params]:
            raise CtapError(CtapError.ERR.UNSUPPORTED_OPTION)

        app_param = sha256(rp["id"].encode())

        dummy_param = b"\0" * 32
        for cred in exclude_list or []:
            key_handle = cred["id"]
            try:
                self.ctap1.authenticate(dummy_param, app_param, key_handle, True)
                raise ClientError.ERR.OTHER_ERROR()  # Shouldn't happen
            except ApduError as e:
                if e.code == APDU.USE_NOT_SATISFIED:
                    _call_polling(
                        self.ctap1_poll_delay,
                        event,
                        on_keepalive,
                        self.ctap1.register,
                        dummy_param,
                        dummy_param,
                    )
                    raise ClientError.ERR.DEVICE_INELIGIBLE()

        return AttestationObject.from_ctap1(
            app_param,
            _call_polling(
                self.ctap1_poll_delay,
                event,
                on_keepalive,
                self.ctap1.register,
                client_data.hash,
                app_param,
            ),
        )

    def get_assertion(self, options, **kwargs):
        """Get an assertion.

        :param options: PublicKeyCredentialRequestOptions data.
        :param pin: (optional) Used if PIN verification is required.
        :param threading.Event event: (optional) Signal to abort the operation.
        :param on_keepalive: (optional) Not implemented.
        """

        options = PublicKeyCredentialRequestOptions._wrap(options)
        pin = kwargs.get("pin")
        event = kwargs.get("event", Event())
        if options.timeout:
            timer = Timer(options.timeout / 1000, event.set)
            timer.daemon = True
            timer.start()

        self._verify_rp_id(options.rp_id)

        client_data = self._build_client_data(
            WEBAUTHN_TYPE.GET_ASSERTION, options.challenge
        )

        try:
            return (
                self._do_get_assertion(
                    client_data,
                    options.rp_id,
                    options.allow_credentials,
                    options.extensions,
                    self._get_ctap_uv(options.user_verification, pin is not None),
                    self._get_ctap_up(options.user_presence),
                    pin,
                    event,
                    kwargs.get("on_keepalive"),
                ),
                client_data,
            )
        except CtapError as e:
            raise _ctap2client_err(e)
        finally:
            if options.timeout:
                timer.cancel()

    def _ctap2_get_assertion(
        self, client_data, rp_id, allow_list, extensions, uv, up, pin, event, on_keepalive
    ):
        pin_auth = None
        pin_protocol = None
        if pin:
            pin_protocol = self.pin_protocol.VERSION
            pin_token = self.pin_protocol.get_pin_token(pin)
            pin_auth = hmac_sha256(pin_token, client_data.hash)[:16]
        elif self.info.options.get("clientPin") and not uv:
            raise ClientError.ERR.BAD_REQUEST("PIN required but not provided")

        if uv:
            options = {"uv": True}
            if not up:
                options = {"uv": True, "up": False}
        else:
            options = None
            if not up:
                options = {"up": False}    


        if allow_list:
            # Filter out credential IDs which are too long
            max_len = self.info.max_cred_id_length
            if max_len:
                allow_list = [e for e in allow_list if len(e) <= max_len]
            if not allow_list:
                raise CtapError(CtapError.ERR.NO_CREDENTIALS)

            # Reject the request if too many credentials remain.
            max_creds = self.info.max_creds_in_list
            if max_creds and len(allow_list) > max_creds:
                raise ClientError.ERR.BAD_REQUEST("allow_list too long")

        return self.ctap2.get_assertions(
            rp_id,
            client_data.hash,
            allow_list if allow_list else None,
            extensions,
            options,
            pin_auth,
            pin_protocol,
            event,
            on_keepalive,
        )

    def _ctap1_get_assertion(
        self, client_data, rp_id, allow_list, extensions, uv, pin, event, on_keepalive
    ):
        if uv or not allow_list:
            raise CtapError(CtapError.ERR.UNSUPPORTED_OPTION)

        app_param = sha256(rp_id.encode())
        client_param = client_data.hash
        for cred in allow_list:
            try:
                auth_resp = _call_polling(
                    self.ctap1_poll_delay,
                    event,
                    on_keepalive,
                    self.ctap1.authenticate,
                    client_param,
                    app_param,
                    cred["id"],
                )
                return [AssertionResponse.from_ctap1(app_param, cred, auth_resp)]
            except ClientError as e:
                if e.code == ClientError.ERR.TIMEOUT:
                    raise  # Other errors are ignored so we move to the next.
        raise ClientError.ERR.DEVICE_INELIGIBLE()


_WIN_INFO = Info.create(["U2F_V2", "FIDO_2_0"])

if platform.system().lower() == "windows":
    try:
        from .win_api import (
            WinAPI,
            WebAuthNAuthenticatorAttachment,
            WebAuthNUserVerificationRequirement,
            WebAuthNAttestationConvoyancePreference,
        )
    except Exception:  # nosec # TODO: Make this less generic
        pass