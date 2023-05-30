import logging

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseServerError
from django.shortcuts import render
from django.urls import reverse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

log = logging.getLogger(__name__)


def init_saml_auth(req):
    settings = {
        "strict": True,
        "debug": True,
        "sp": {
            "entityId": "http://0.0.0.0:8000/metadata/",
            "assertionConsumerService": {
                "url": "http://localhost:8000/saml/acs/",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": "http://0.0.0.0:8000/?sls",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": "",
            "privateKey": "",
        },
        "idp": {
            "entityId": "https://sts.windows.net/2f6cb1a6-ecb8-4578-b680-bf84ded07ff4/",
            "singleSignOnService": {
                "url": "https://login.microsoftonline.com/2f6cb1a6-ecb8-4578-b680-bf84ded07ff4/saml2",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": "https://login.microsoftonline.com/2f6cb1a6-ecb8-4578-b680-bf84ded07ff4/saml2",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": "",
        },
        "security": {
            "nameIdEncrypted": False,
            "authnRequestsSigned": False,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "signMetadata": False,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": False,
            "wantNameId": True,
            "wantNameIdEncrypted": False,
            "wantAssertionsEncrypted": False,
            "allowSingleLabelDomains": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            "rejectDeprecatedAlgorithm": True,
            "wantAttributeStatement": False,
        },
        "contactPerson": {
            "technical": {
                "givenName": "technical_name",
                "emailAddress": "technical@example.com",
            },
            "support": {
                "givenName": "support_name",
                "emailAddress": "support@example.com",
            },
        },
        "organization": {
            "en-US": {
                "name": "sp_test",
                "displayname": "SP test",
                "url": "http://sp.example.com",
            }
        },
    }
    auth = OneLogin_Saml2_Auth(req, old_settings=settings, custom_base_path=None)
    return auth


def prepare_django_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    result = {
        "https": "on" if request.is_secure() else "off",
        "http_host": request.META["HTTP_HOST"],
        "script_name": request.META["PATH_INFO"],
        "get_data": request.GET.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        "post_data": request.POST.copy(),
    }
    return result


def index(request):
    req = prepare_django_request(request)
    auth = init_saml_auth(req)
    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    if "sso" in req["get_data"]:
        return HttpResponseRedirect(auth.login())
        # If AuthNRequest ID need to be stored in order to later validate it, do instead
        # sso_built_url = auth.login()
        # request.session['AuthNRequestID'] = auth.get_last_request_id()
        # return HttpResponseRedirect(sso_built_url)
    elif "sso2" in req["get_data"]:
        return_to = OneLogin_Saml2_Utils.get_self_url(req) + reverse("attrs")
        return HttpResponseRedirect(auth.login(return_to))
    elif "slo" in req["get_data"]:
        name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
        if "samlNameId" in request.session:
            name_id = request.session["samlNameId"]
        if "samlSessionIndex" in request.session:
            session_index = request.session["samlSessionIndex"]
        if "samlNameIdFormat" in request.session:
            name_id_format = request.session["samlNameIdFormat"]
        if "samlNameIdNameQualifier" in request.session:
            name_id_nq = request.session["samlNameIdNameQualifier"]
        if "samlNameIdSPNameQualifier" in request.session:
            name_id_spnq = request.session["samlNameIdSPNameQualifier"]

        return HttpResponseRedirect(
            auth.logout(
                name_id=name_id,
                session_index=session_index,
                nq=name_id_nq,
                name_id_format=name_id_format,
                spnq=name_id_spnq,
            )
        )
        # If LogoutRequest ID need to be stored in order to later validate it, do instead
        # slo_built_url = auth.logout(name_id=name_id, session_index=session_index)
        # request.session['LogoutRequestID'] = auth.get_last_request_id()
        # return HttpResponseRedirect(slo_built_url)
    elif "acs" in req["get_data"]:
        request_id = None
        if "AuthNRequestID" in request.session:
            request_id = request.session["AuthNRequestID"]

        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()

        if not errors:
            if "AuthNRequestID" in request.session:
                del request.session["AuthNRequestID"]
            request.session["samlUserdata"] = auth.get_attributes()
            log.debug("***********")
            log.debug(auth.get_attributes())
            log.debug("***********")
            request.session["samlNameId"] = auth.get_nameid()
            request.session["samlNameIdFormat"] = auth.get_nameid_format()
            request.session["samlNameIdNameQualifier"] = auth.get_nameid_nq()
            request.session["samlNameIdSPNameQualifier"] = auth.get_nameid_spnq()
            request.session["samlSessionIndex"] = auth.get_session_index()
            if (
                "RelayState" in req["post_data"]
                and OneLogin_Saml2_Utils.get_self_url(req)
                != req["post_data"]["RelayState"]
            ):
                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                # the value of the req['post_data']['RelayState'] is a trusted URL.
                return HttpResponseRedirect(
                    auth.redirect_to(req["post_data"]["RelayState"])
                )
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()
    elif "sls" in req["get_data"]:
        request_id = None
        if "LogoutRequestID" in request.session:
            request_id = request.session["LogoutRequestID"]
        dscb = lambda: request.session.flush()
        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                # the value of the url is a trusted URL
                return HttpResponseRedirect(url)
            else:
                success_slo = True
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()

    if "samlUserdata" in request.session:
        paint_logout = True
        if len(request.session["samlUserdata"]) > 0:
            attributes = request.session["samlUserdata"].items()

    return render(
        request,
        "index.html",
        {
            "errors": errors,
            "error_reason": error_reason,
            "not_auth_warn": not_auth_warn,
            "success_slo": success_slo,
            "attributes": attributes,
            "paint_logout": paint_logout,
        },
    )


def attrs(request):
    paint_logout = False
    attributes = False

    if "samlUserdata" in request.session:
        paint_logout = True
        if len(request.session["samlUserdata"]) > 0:
            attributes = request.session["samlUserdata"].items()
    return render(
        request, "attrs.html", {"paint_logout": paint_logout, "attributes": attributes}
    )


def metadata(request):
    # req = prepare_django_request(request)
    # auth = init_saml_auth(req)
    # saml_settings = auth.get_settings()
    saml_settings = OneLogin_Saml2_Settings(
        settings=None, custom_base_path=settings.SAML_FOLDER, sp_validation_only=True
    )
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = HttpResponse(content=metadata, content_type="text/xml")
    else:
        resp = HttpResponseServerError(content=", ".join(errors))
    return resp


def login(request):
    req = prepare_django_request(request)
    auth = init_saml_auth(req)
    sso_built_url = auth.login()
    request.session["AuthNRequestID"] = auth.get_last_request_id()
    return HttpResponseRedirect(sso_built_url)


def acs(request):
    req = prepare_django_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    not_auth_warn = not auth.is_authenticated()
    attributes = False
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    if not errors:
        if "AuthNRequestID" in request.session:
            del request.session["AuthNRequestID"]
        request.session["samlUserdata"] = auth.get_attributes()
        log.debug("***********")
        log.debug(auth.get_attributes())
        log.debug("***********")
        request.session["samlNameId"] = auth.get_nameid()
        request.session["samlNameIdFormat"] = auth.get_nameid_format()
        request.session["samlNameIdNameQualifier"] = auth.get_nameid_nq()
        request.session["samlNameIdSPNameQualifier"] = auth.get_nameid_spnq()
        request.session["samlSessionIndex"] = auth.get_session_index()
        if (
            "RelayState" in req["post_data"]
            and OneLogin_Saml2_Utils.get_self_url(req) != req["post_data"]["RelayState"]
        ):
            # To avoid 'Open Redirect' attacks, before execute the redirection confirm
            # the value of the req['post_data']['RelayState'] is a trusted URL.
            return HttpResponseRedirect(
                auth.redirect_to(req["post_data"]["RelayState"])
            )
    elif auth.get_settings().is_debug_active():
        error_reason = auth.get_last_error_reason()

    if "samlUserdata" in request.session:
        paint_logout = True
        if len(request.session["samlUserdata"]) > 0:
            attributes = request.session["samlUserdata"].items()

    return render(
        request,
        "index.html",
        {
            "errors": errors,
            "error_reason": error_reason,
            "not_auth_warn": not_auth_warn,
            "attributes": attributes,
            "paint_logout": paint_logout,
        },
    )
