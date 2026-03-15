from setuptools import setup, find_packages

setup(
    name="403x",
    version="1.0.0",
    description="Advanced 403 Bypass Recon Framework",
    author="Arookiech",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "urllib3>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "403x=forbiddenx.cli:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
