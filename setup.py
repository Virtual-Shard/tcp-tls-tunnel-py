import pathlib
from setuptools import setup, find_packages

BASE_DIR = pathlib.Path(__file__).parent
README = (BASE_DIR / "README.md").read_text()


httpx_requirements = [
    "h2>=4.0",
    "httpx>=0.18.2",
]
hyper_requirements = [
    "h2>=2.6.2,<3.0",
]


setup(
    name="tls-tunnel",
    version='0.5.5',
    description="TLS TCP tunnel for HTTP requests",
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
        "httpx": httpx_requirements,
        "hyper": hyper_requirements,
    },
    dependency_links=[
        'hyper@https://github.com/Lukasa/hyper/archive/development.tar.gz'
    ]
)
