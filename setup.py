from setuptools import setup, find_packages

setup(
  name="covalence-sdk",
  version="0.1.0",
  author="Covalence",
  author_email="ali@covalence.run",
  description="Secure, high-performance Python SDK for Covalence",
  long_description=open("README.md", encoding="utf-8").read(),
  long_description_content_type="text/markdown",
  url="https://github.com/covalence/sdk",
  license="MIT",
  packages=find_packages(),
  python_requires=">=3.7",
  install_requires=[
    "requests>=2.25.1",
    "PyJWT>=2.0.0",
    "pydantic>=1.10.2",
    "urllib3>=1.26.0",
  ],
  classifiers=[
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
  ],
)
