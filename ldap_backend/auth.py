from __future__ import unicode_literals

from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist
import django.dispatch

from ldap_backend.ldap import LdapUser, LdapServer
import logging


logger = logging.getLogger("ldap_backend")

# Export signals
# Allows clients to perform custom user population
populate_use = django.dispatch.Signal(providing_args=["user", "ldap_user"])

# Allows clients to inspect and perform special handleing of LDAPError
ldap_error = django.dispatch.Signal(providing_args=["context", "user", "exception"])


LDAP_SERVER = LdapServer.setup(
    settings.LDAP_PREFIX, settings.LDAP_BASE, settings.LDAP_SERVER
)


class AuthenticationBackend(ModelBackend):
    """
    Custom authentication Backend for login using email,phone,username 
    with password
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        try:
            user = UserModel._default_manager.get_by_natural_key(username)
            logger.info("User: %s", user)
            if user.logon_type == "LOCAL" and user.check_password(password):
                return user
        except UserModel.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a non-existing user (#20760).
            UserModel().set_password(password)
        logger.info("Failed to login: %s", username)


class LdapBackend(object):
    _ldap = None

    def get_user_model(self):
        """ By Default, this will return the model class configured by AUTH_USER_MODEL.
            gclasses may wish to override it and return a proxy model.
        """
        return get_user_model()

    def authenticate(self, request, username=None, password=None, **kwargs):
        if password or self.settings.PERMIT_EMPTY_PASSWORD:
            try:
                user = self.get_user_model().objects.get(email=username)
                if user.logon_type == "LDAP":
                    logger.info("Authenticate with ldap, %s, %s", request, username)
                    user.ldap_user = LdapUser(LDAP_SERVER, username=user.username)
                    user.ldap_user.login(password)
                else:
                    user = None
            except ObjectDoesNotExist:
                logger.error("User does not exist")
                user = None
            except Exception as e:
                logger.error("Error: %s", e)
                user = None
        else:
            logger.info("Rejecting empty password for {}".format(username))
            user = None
        if user:
            logger.info("Completed to login with LDAP: %s", username)
        return user

    def get_user(self, user_id):
        try:
            user = self.get_user_model().objects.get(pk=user_id)
        except ObjectDoesNotExist:
            user = None

        return user
