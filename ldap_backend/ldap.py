import functools
import ldap3
from ldap3 import Connection, Server, ServerPool
from ldap3 import SIMPLE, SUBTREE
from ldap3 import FIRST, RANDOM
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPConstraintViolationResult,
    LDAPInvalidCredentialsResult,
    LDAPUserNameIsMandatoryError,
    LDAPSocketOpenError,
    LDAPExceptionError,
)

import logging
logger = logging.getLogger("ldap_backend")


class LdapRequiredLogin(Exception):
    pass


class LdapLoginFailed(Exception):
    pass


def onetime_connection(func=None, is_var=True):
    if func is None:
        return functools.partial(onetime_connection, is_var=is_var)

    @functools.wraps(func)
    def wrapper_func(self, *args, **kwargs):
        if is_var and getattr(self, "_%s" % func.__name__):
            return getattr(self, "_%s" % func.__name__)
        if not self._conn:
            raise LdapRequiredLogin()
        if not self._conn.bound:
            self._conn.bind()
        ret = func(self, *args, **kwargs)
        self._conn.unbind()
        return ret

    return wrapper_func


def permanent_connection(func=None, is_var=True):
    if func is None:
        return functools.partial(onetime_connection, is_var=is_var)

    @functools.wraps(func)
    def wrapper_func(self, *args, **kwargs):
        if is_var and getattr(self, "_%s" % func.__name__):
            return getattr(self, "_%s" % func.__name__)
        if not self._conn:
            raise LdapRequiredLogin()
        if not self._conn.bound:
            self._conn.bind()
        ret = func(self, *args, **kwargs)
        return ret

    return wrapper_func


class UserAccountControl(object):
    SCRIPT = 1  # 0x0001
    ACCOUNTDISABLE = 2  # 0x0002
    HOMEDIR_REQUIRED = 8  # 0x0008
    LOCKOUT = 16  # 0x0010
    PASSWD_NOTREQD = 32  # 0x0020
    PASSWD_CANT_CHANGE = 64  # 0x0040
    ENCRYPTED_TEXT_PWD_ALLOWD = 128  # 0x0080
    TEMP_DUPLICATE_ACCOUNT = 256  # 0x0100
    NORMAL_ACCOUNT = 512  # 0x0200
    INTERDOMAIN_TRUST_ACCOUNT = 2048  # 0x0800
    WORKSTATION_TRUST_ACCOUNT = 4096  # 0x1000
    SERVER_TRUST_ACCOUNT = 8192  # 0x2000
    DONT_EXPIRE_PASSWORD = 65536  # 0x10000
    MNS_LOGON_ACCOUNT = 131072  # 0x20000
    SMARTCARD_REQUIRED = 262144  # 0x40000
    TRUSTED_FOR_DELEGATION = 524288  # 0x80000
    NOT_DELEGATED = 1048576  # 0x100000
    USE_DES_KEY_ONLY = 2097152  # 0x200000
    DONT_REQ_PREAUTH = 4194304  # 0x400000
    PASSWORD_EXPIRED = 8388608  # 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216  # 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 67108864  # 0x04000000
    controls = (
        ("SCRIPT", 1),  # 0x0001
        ("ACCOUNTDISABLE", 2),  # 0x0002
        ("HOMEDIR_REQUIRED", 8),  # 0x0008
        ("LOCKOUT", 16),  # 0x0010
        ("PASSWD_NOTREQD", 32),  # 0x0020
        ("PASSWD_CANT_CHANGE", 64),  # 0x0040
        ("ENCRYPTED_TEXT_PWD_ALLOWD", 128),  # 0x0080
        ("TEMP_DUPLICATE_ACCOUNT", 256),  # 0x0100
        ("NORMAL_ACCOUNT", 512),  # 0x0200
        ("INTERDOMAIN_TRUST_ACCOUNT", 2048),  # 0x0800
        ("WORKSTATION_TRUST_ACCOUNT", 4096),  # 0x1000
        ("SERVER_TRUST_ACCOUNT", 8192),  # 0x2000
        ("DONT_EXPIRE_PASSWORD", 65536),  # 0x10000
        ("MNS_LOGON_ACCOUNT", 131072),  # 0x20000
        ("SMARTCARD_REQUIRED", 262144),  # 0x40000
        ("TRUSTED_FOR_DELEGATION", 524288),  # 0x80000
        ("NOT_DELEGATED", 1048576),  # 0x100000
        ("USE_DES_KEY_ONLY", 2097152),  # 0x200000
        ("DONT_REQ_PREAUTH", 4194304),  # 0x400000
        ("PASSWORD_EXPIRED", 8388608),  # 0x800000
        ("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216),  # 0x1000000
        ("PARTIAL_SECRETS_ACCOUNT", 67108864),  # 0x04000000
    )

    def __init__(self, control):
        if not isinstance(control, int):
            raise ValueError
        self._values = {name: value for name, value in self.controls if control & value}

    def __repr__(self):
        return ",".join(self.values)

    def __str__(self):
        return self.__repr__()

    @property
    def values(self):
        return self._values.keys()


class LdapServer(object):

    def __init__(self, prefix, base_dn, use_ssl=True, connect_timeout=5):
        self.ldap = ServerPool(None, FIRST)
        self.prefix = None
        self.bind_dn = None
        self.error_msg = None
        self._use_ssl = use_ssl
        self._connect_timeout = connect_timeout
        self.prefix = prefix
        self.base_dn = base_dn

    def __repr__(self):
        return "<%s> %s" % (self.__class__.__name__, self.ldap)

    def __str__(self):
        return self.__repr__()

    def add_server(self, host, port, use_ssl=None):
        logger.info("Add server: %s:%d - %s", host, port, use_ssl)
        server = Server(
            host=host,
            port=port,
            use_ssl=self._use_ssl if use_ssl is None else use_ssl,
            connect_timeout=self._connect_timeout,
        )
        self.ldap.add(server)

    def searchfilter(self, uid):
        return f"(sAMAccountName={uid})"

    @classmethod
    def setup(cls, prefix, base_dn, servers):
        ldap_server = cls(prefix=prefix, base_dn=base_dn)
        for server in servers:
            ldap_server.add_server(**server)
        return ldap_server

    def connect(self, username, password, **kwargs):
        ldap_username = f"{self.prefix}\\{username}"
        conn = Connection(
            self.ldap,
            user=ldap_username,
            password=password,
            raise_exceptions=False,
            **kwargs
        )
        if conn.bind() and conn.result["result"] == 0:
            self.error_msg = conn.result
            conn.unbind()
            return conn
        else:
            return None


class LdapUser(object):

    def __init__(self, ldap_server, username):
        self.ldap_server = ldap_server
        self._username = username
        self._user_dn = None
        self._email = None
        self._conn = None

    def __repr__(self):
        return f"<{self.__class__.__name__}> {self._username}"

    def __str__(self):
        return self.__repr__()

    def login(self, password):
        self._conn = self.ldap_server.connect(self._username, password)
        if not self._conn:
            logger.error("Error: %s, %s", self._username, self.ldap_server.error_msg)
            raise LdapLoginFailed()
        self._user_dn = self.user_dn()
        if self._user_dn is None:
            logger.error("Error: %s, %s", self._username, self.ldap_server.error_msg)
            raise LdapLoginFailed()

    def logout(self):
        if self._conn:
            if self._conn.bound:
                self._conn.unbind()
            self._conn = None

    @onetime_connection(is_var=False)
    def search(self, search_filter, base_dn=None):
        """
        Using generatoer to get entries
        """
        base_dn = base_dn if base_dn else self.ldap_server.base_dn
        self._conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=ldap3.ALL_ATTRIBUTES,
            paged_size=1000)
        cookie = self._conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        entries = self._conn.entries
        while cookie:
            self._conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=ldap3.ALL_ATTRIBUTES,
                paged_size=1000,
                paged_cookie=cookie)
            cookie = self._conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
            entries.extend(self._conn.entries)
        return entries

    @onetime_connection(is_var=False)
    def search_raw(self, search_filter, base_dn=None):
        """
        Using generatoer to get entries
        """
        base_dn = base_dn if base_dn else self.ldap_server.base_dn
        #if self._conn.search(
        entry_generator = self._conn.extend.standard.paged_search(
            base_dn, search_filter, SUBTREE, attributes=ldap3.ALL_ATTRIBUTES
        )
        return [entry for entry in entry_generator]

    @onetime_connection
    def user_dn(self):
        self._conn.search(
            self.ldap_server.base_dn,
            self.ldap_server.searchfilter(self._username),
            SUBTREE,
        )
        userdn = self._conn.response[0]["dn"] if self._conn.response else None
        self._user_dn = userdn
        logger.debug("user_dn: %s, %s", userdn, self._user_dn)
        return self._user_dn

    @onetime_connection
    def email(self):
        self._conn.search(
            self.ldap_server.base_dn,
            self.ldap_server.searchfilter(self._username),
            SUBTREE,
            attributes=ldap3.ALL_ATTRIBUTES,
        )
        mail = self._conn.response[0]["attributes"].get("mail")
        proxy_mail = self._conn.response[0]["attributes"].get("proxyAddresses")
        if proxy_mail:
            proxy_mail = proxy_mail[0].split(":")[-1]
        self._email = mail or proxy_mail
        return self._email

    @onetime_connection(is_var=False)
    def change_password(self, new_pass, old_pass=None):
        user_dn = self.user_dn()
        logger.debug(
            "ad_modify_password: CONN: %s, User: %s, USER_DN: %s",
            self._conn,
            self._username,
            user_dn,
        )
        self._conn.start_tls()
        old_pass = old_pass or self._conn.password
        ret = ldap3.extend.microsoft.modifyPassword.ad_modify_password(
            self._conn, user_dn, new_pass, old_pass, controls=None
        )
        return (ret, self._conn.result)

