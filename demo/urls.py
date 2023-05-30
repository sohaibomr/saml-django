from django.contrib import admin
from django.urls import path, re_path

from .views import acs, attrs, index, login, metadata

admin.autodiscover()

urlpatterns = [
    re_path(r"^$", index, name="index"),
    re_path(r"^attrs/$", attrs, name="attrs"),
    re_path(r"^metadata/$", metadata, name="metadata"),
    path("saml/acs/", acs, name="saml_acs"),
]
