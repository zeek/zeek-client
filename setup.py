from setuptools import setup


def get_readme():
    with open("README.md", encoding="utf-8") as readme:
        return readme.read()


def get_version():
    with open("VERSION", encoding="utf-8") as version:
        return version.read().replace("-", ".dev", 1).strip()


setup(
    name="zeek-client",
    version=get_version(),
    description="A CLI for Zeek's Management Framework",
    long_description=get_readme(),
    long_description_content_type="text/markdown",
    license="3-clause BSD License",
    keywords="zeek management client cluster",
    maintainer="The Zeek Project",
    maintainer_email="info@zeek.org",
    url="https://github.com/zeek/zeek-client",
    scripts=["zeek-client"],
    packages=["zeekclient"],
    install_requires=["websocket-client"],
    python_requires=">=3.7.0",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Utilities",
    ],
)
