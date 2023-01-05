from setuptools import setup

setup(
    name='zeek-client',
    version=open('VERSION').read().replace('-', '.dev', 1).strip(),
    description='A CLI for Zeek\'s Management Framework',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    license='3-clause BSD License',
    keywords='zeek management client cluster',
    maintainer='The Zeek Project',
    maintainer_email='info@zeek.org',
    url='https://github.com/zeek/zeek-client',
    scripts=['zeek-client'],
    packages=['zeekclient'],
    install_requires=['websocket-client'],
    python_requires='>=3.7.0',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python :: 3',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Utilities',
    ],
)
