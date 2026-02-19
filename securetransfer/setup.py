from setuptools import setup, find_packages

setup(
    name="securetransfer",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "zstandard==0.22.0",
        "cryptography==42.0.5",
        "sqlalchemy==2.0.29",
        "aiosqlite==0.20.0",
        "click==8.1.7",
        "python-dotenv==1.0.1",
        "loguru==0.7.2",
        "rich==13.7.1",
        "tabulate==0.9.0",
    ],
    extras_require={
        "dev": [
            "pytest==8.1.1",
            "pytest-asyncio==0.23.6",
        ]
    },
    entry_points={
        "console_scripts": [
            "securetransfer=securetransfer.cli.main:cli",
        ],
    },
)
