import pathlib
from setuptools import setup, find_packages

BASE_DIR = pathlib.Path(__file__).parent
README = (BASE_DIR / "README.md").read_text()


setup(
    name="tls-tunnel",
    version='0.2',
    description="TLS TCP tunnel for HTTP requests",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/Arteha/tcp-tls-tunnel-py",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    include_package_data=True,
    packages=find_packages(exclude=("tests",)),
)