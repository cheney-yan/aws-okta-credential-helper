"""OKTA AWS Credential helper
"""

from setuptools import setup
from os import path, listdir
from io import open
import glob
here = path.abspath(path.dirname(__file__))

# executes and sets __version__ in the local namespace
exec(open(path.join(
    here, '', 'okta_aws_cred_helper', '__init__.py')).read())

all_docs = glob.glob(path.join(here, 'docs', '*')) + \
    [path.join(here, 'README.md')]

long_description = ''
for doc in all_docs:
  with open(doc, encoding='utf-8') as f:
    long_description += f.read()
    long_description += "\n\n---\n\n"


def find_package_data_files(dir, package_name):
  result = list()
  files = listdir(dir)
  for entry in files:
    full_path = path.join(dir, entry)
    if path.isdir(full_path):
      result = result + find_package_data_files(full_path, None)
    else:
      result.append(full_path)
  if package_name:
    result = [f.replace('%s/' % package_name, '', 1) for f in result]
  return result


REQUIREMENTS = [
    "boto3",
    "click==7.0",
    "click-log==0.3.2",
    "sh",
    "keyring",
    "python-dateutil",
    "bs4",
    "simplejson",
    "requests[security]",
    "pyyaml",
]

setup(
    name='okta-aws-credential-helper',
    python_requires='>=3.0.0',
    version=__version__,  # noqa pylint: disable=E0602

    description='Okta AWS SAML credential helper',
    install_requires=REQUIREMENTS,

    long_description=long_description,  # Optional

    long_description_content_type='text/markdown',

    url='https://github.com/cheney-yan/aws-okta-credential-helper',

    author='Cheney Yan',

    author_email='cheney.yan@gmail.com',

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],

    keywords='Okta AWS SAML Credential Helper',
    packages=['okta_aws_cred_helper'],
    package_dir={'okta_aws_cred_helper': 'okta_aws_cred_helper'},
    package_data={
        'okta_aws_cred_helper': find_package_data_files(
            path.join(path.dirname(__file__), 'okta_aws_cred_helper', 'data'),
            'okta_aws_cred_helper'
        )
    },
    entry_points={
        'console_scripts': [
            'okta-aws-cred-helper=okta_aws_cred_helper.helper:cli',
        ],
    }
)
