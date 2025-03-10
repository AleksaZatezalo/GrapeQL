from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="grapeql",
    version="0.1.0",
    author="Aleksa Zatezalo",
    author_email="Aleksa.Zatezalo@praetorian.com",
    description="GrapeQL is a comprehensive GraphQL security assessment toolkit designed to help security researchers and developers identify vulnerabilities in GraphQL implementations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AleksaZatezalo/GrapeQL",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "aiohttp>=3.8.5",
        "asyncio>=3.4.3",
        "typing>=3.7.4",
        # Add any other dependencies your package has here
    ],
    entry_points={
        'console_scripts': [
            'grapeql=grapeql.grapeql:run_cli',
        ],
    },
)