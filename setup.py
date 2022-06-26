import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="virustotal-scrapper",
    version="2.0.0",
    author="Brijesh krishna",
    description="scrapper for virustotal",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Brijeshkrishna/virustotal-scrapper",
    package_dir={"": "vt"},
    packages=setuptools.find_packages(where="vt"),
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    zip_safe=False,
)   
