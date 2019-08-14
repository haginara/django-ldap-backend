Django-ldap-backend
===================

LDAP authenticating for Django

Install
-------

```
git clone https://github.com/haginara/django-ladp-backend.git
cd django-ldap-backend

pip install . # or
python setup.py install
```


Add `ldap_backend` into INSTALLED_APPS

```
INSTALLED_APPS = [
	...
	'ldap_backend',
]

```

Setting variables
-----------------

- LDAP_PREFIX
- LDAP_BASE
- LDAP_SERVER
- PERMIT_EMPTY_PASSWORD
