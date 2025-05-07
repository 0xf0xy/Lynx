from setuptools import setup, find_packages

setup(
    name="Lynx",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "lynx.data": ["common_ports.txt"],
    },
    install_requires=["rich"],
    entry_points={
        "console_scripts": [
            "lynx=lynx.cli:main",
        ],
    },
    description="Stealth TCP port scanner",
    author="0xf0xy",
    license="MIT",
)
