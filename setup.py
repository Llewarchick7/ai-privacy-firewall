from setuptools import setup, find_packages

setup(
    name='ai-privacy-firewall',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'requests',
        'stem',
        'playwright',
        'beautifulsoup4',
        'lxml',
        'httpx',  # For async HTTP requests
    ]
)
