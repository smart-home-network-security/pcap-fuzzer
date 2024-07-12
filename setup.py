from setuptools import setup, find_packages

setup(
    name='pcap_fuzzer',
    version='0.2.0',
    author='François De Keersmaeker',
    author_email='francois.dekeersmaeker@uclouvain.be',
    description='Randomly edit packet fields in a PCAP file.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/smart-home-network-security/pcap-fuzzer',
    license='GPLv3+',
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',
    install_requires=[
        'scapy',
    ],
    #test_suite='tests',
)
