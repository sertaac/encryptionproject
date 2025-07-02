import os  
from setuptools import setup, find_packages

setup(
    name='password-protection-detector',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'magika',
        'msoffcrypto-tool',  
        'PyPDF2',
        'pikepdf',
        'rarfile',
        'py7zr',
        'pypff',             
        'olefile',
        'extract-msg',
    ],
    entry_points={
        'console_scripts': [
            'run-detector=scripts.run_detector:main_cli',
        ],
    },
    author='Sertac Atac & Ramazan Bagis',
    author_email='sertacataac@gmail.com, ramazanbagiss06@gmail.com',
    description='A tool to detect password protection and encryption in various file types.',
    long_description=open('README.md', encoding='utf-8').read() if os.path.exists('README.md') else '',
    long_description_content_type='text/markdown',
    url='https://github.com/sertaac/encryptionproject',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
    python_requires='>=3.8',
)
