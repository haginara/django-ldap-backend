from setuptools import setup
from ldap_backend import __version__

description = "LDAP Backend for Django"
long_description = description
install_requires=[
    'django >= 1.2.7',
    'ldap3', 
]

setup(
    name='django-ldap-backend',
    version=__version__,
    description=description,
    author='Jonghak Choi',
    author_email='jhchoi@neon.net',
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
