from setuptools import setup, find_packages

setup(
    name="barr-monitor",
    version="1.0.0",
    author="Gavin Barrett",
    author_email="gavinbarrett2001@gmail.com",
    description="A log analyzer CLI tool that will monitor log files for keywords such as [ERROR], [WARNING], [CRITICAL]",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "barr-monitor=src.main:main",  # Ensure `src.main:main` matches your actual file path
        ]
    },
    install_requires=[
        "psutil",
    ],
)
