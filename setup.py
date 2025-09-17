from setuptools import setup


def get_version() -> str:
    with open("VERSION", encoding="utf-8") as version:
        return version.read().replace("-", ".dev", 1).strip()


setup(
    version=get_version(),
)
