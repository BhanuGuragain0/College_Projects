#!/usr/bin/env python3
from setuptools import setup, find_packages
import os

# Read the long description from README.md (if available)
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bugbounty_tool",
    version="0.1.0",
    author="Shadow@Bhanu",
    author_email="shadow@example.com",  # Update with your email if desired
    description="An advanced bug bounty automation tool with integrated scanning, AI analysis, and reporting.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/bugbounty_tool",  # Update if you have a repository URL
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Security Researchers",
        "Topic :: Security :: Vulnerability Assessment",
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click",
        "jinja2",
        "pyyaml",
        "tqdm",
        "openai",
        "requests",
    ],
    extras_require={
        "dev": [
            "pytest",
        ],
    },
    entry_points={
        "console_scripts": [
            "bugbounty=bugbounty_tool.cli:cli",
        ],
    },
)