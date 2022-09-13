from setuptools import setup

import pathlib

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# About the project
ABOUT = {}
exec((HERE / "burpa" / "__version__.py").read_text(), ABOUT)

REQUIREMENTS = [
    'requests>=2.4.2',
    'attrs',
    'fire',
    'python-dotenv',
    'filelock',
    'python-dateutil',
    'importlib_resources',
]

setup(
    name='burpa',
    long_description=README,
    long_description_content_type="text/markdown",
    packages=['burpa',],
    package_data={'burpa': ['issue_defs.json']},
    entry_points = {
        'console_scripts': [
            'burpa=burpa._burpa:main']
    },
    author=ABOUT['__author__'],
    version=ABOUT['__version__'],
    python_requires='>=3.6',
    install_requires=REQUIREMENTS,
)
