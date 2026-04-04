from setuptools import setup, find_packages

setup(
    name="tsp-protocol",
    version="0.1.0",
    author="cnomic-dev",
    description="A minimalist, ternary-based protocol for AI-Human Symbiosis.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/cnomic-dev/tsp-protocol",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.20.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires='>=3.8',
)
