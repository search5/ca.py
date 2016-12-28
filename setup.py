from distutils.core import setup
setup(
    name = 'CA.py',
    packages = ['ca_py'], # this must be the same as the name above
    version = '1.3',
    description = 'CA.pl Python Fork',
    author = 'Lee Ji-Ho',
    author_email = 'search5@gmail.com',
    url = 'https://github.com/search5/ca.py', # use the URL to the github repo
    download_url = 'https://github.com/search5/ca.py/tarball/1.3', # I'll explain this in a second
    keywords = ['openssl', 'ca', 'cert'], # arbitrary keywords
    classifiers = [
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows :: Windows 7",
        "Operating System :: Microsoft :: Windows :: Windows XP",
        "Programming Language :: Python :: 3.3",
        "Topic :: System :: Networking",
        "Topic :: Security :: Cryptography"
    ],
    scripts=['ca_py/ca.py'],
    license='Apache License 2.0'
)
