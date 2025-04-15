"""
Setup script for GrapeQL package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="grapeql",
    version="2.0.0",
    author="Aleksa Zatezalo",
    author_email="aleksa_zatezalo@example.com",  # Replace with actual email
    description="A GraphQL Security Testing Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aleksazatezalo/grapeql",  # Replace with actual repository URL
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "aiohttp>=3.8.0",
        "asyncio>=3.4.3",
    ],
    entry_points={
        "console_scripts": [
            "grapeql=grapeql.cli:run_cli",
        ],
    },
)