from setuptools import setup, find_packages

setup(
    name="ipatlas",
    version="0.13.0",
    description="Python client for IPAtlas: Ultra-fast Zero-Copy Binary GeoIP & Threat Intelligence",
    author="ulquiorracode",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet",
    ],
)
