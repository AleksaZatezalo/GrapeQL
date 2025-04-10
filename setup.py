from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="grapeql",
    version="2.0.0",
    author="Aleksa Zatezalo",
    author_email="author@example.com",  # Replace with actual email
    description="A GraphQL Security Testing Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/author/grapeql",  # Replace with actual repository URL
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=[
        "aiohttp>=3.7.0",
        "asyncio>=3.4.3",
    ],
    entry_points={
        "console_scripts": [
            "grapeql=grapeql.grapeql:run_cli",
        ],
    },
)