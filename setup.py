from setuptools import setup, find_packages

_locals = {}
with open("ldap_backend/__init__.py") as f:
    exec(f.read(), None, _locals)
version = _locals["__version__"]

description = "LDAP Backend for Django"
with open("README.md", "r") as f:
    long_description = f.read()

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
    long_description_content_type='text/markdown',
    packages=find_packages(),
    package_data={
        '': ['README.md', 'LICENSE'],
    },
    install_requires=install_requires,
    classifiers=[
        'License :: OSI Approved :: MIT License',
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Intended Audience :: Developers',
    ],
)
