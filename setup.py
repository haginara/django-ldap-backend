from setuptools import setup

_locals = {}
with open("ldap_backend/__init__.py") as f:
    exec(f.read(), None, _locals)
version = _locals["__version__"]

description = "LDAP Backend for Django"
long_description = description
install_requires=[
    'django >= 1.2.7',
    'ldap3', 
]

setup(
    name='django-ldap-backend',
    version=version,
    description=description,
    author='Jonghak Choi',
    author_email='haginara@gmail.com',
    long_description=long_description,
    packages=['ldap_backend'],
    install_requires=install_requires,
    classifiers=[
        'Development Status :: 3 - 3.6',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
