from setuptools import setup

setup(
    name = 'CA.py',
    packages = ['certificator'], # this must be the same as the name above
    version = '1.7',
    description = 'CA.pl Python Fork',
    author = 'Lee Ji-Ho',
    author_email = 'search5@gmail.com',
    url = 'https://github.com/search5/ca.py', # use the URL to the github repo
    download_url = 'https://github.com/search5/ca.py/tarball/1.7', # I'll explain this in a second
    keywords = ['openssl', 'ca', 'cert'], # arbitrary keywords
    platforms='any',
    install_requires=[
          'configobj==5.0.6',
          'click'
    ],
    classifiers = [
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows :: Windows 7",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: System :: Networking",
        "Topic :: Security :: Cryptography"
    ],
    scripts=['certificator/ca.py'],
    license='Apache License 2.0'
)
