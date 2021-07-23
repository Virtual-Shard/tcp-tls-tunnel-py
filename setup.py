import pathlib
from setuptools import setup, find_packages

BASE_DIR = pathlib.Path(__file__).parent
README = (BASE_DIR / "README.md").read_text()


setup(
    name="tcp-tls-tunnel",
    version='1.0.0',
    description="TCP TLS tunnel for HTTP requests with HTTP2 support.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/Virtual-Shard/tcp-tls-tunnel-py",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    include_package_data=True,
    packages=find_packages(exclude=("tests",)),
    extras_require={
        "httpx": [
            "h2>=4.0,<5.0",
            "httpx>=0.18.2"
        ],
        "hyper": [
            "h2>=2.6.2,<3.0",
            "hpack>=3.0.0,<4.0",
            "hyper>=0.7.0,<0.8.0"
        ],
    }
)
