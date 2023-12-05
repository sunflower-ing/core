![python](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11-blue) [![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-orange)](https://www.gnu.org/licenses/agpl-3.0) ![status](https://img.shields.io/badge/status-unstable-red)

# Sunflower Core API

This repository represents the development code for core components (API/OCSP/CRL).

## Overview

Sunflower API provides the RESTful API to base X.509 possibilities like issuing and revoking certificates, making CSR, and generating different types of keys. It also provides CRL-files serving and OCSP responder for online certificate status checking.

## Requirements

- Python 3.8+
- Runs well in containers (Dockerfiles are provided) & Kubernetes ready


## Running in development mode

1. First, install Pipenv and dependencies:

```bash
pip install --user pipenv
pipenv install
pipenv install --dev
```

2. Copy the `.env.example` file to `.env` and fill in your credentials for PostgreSQL and Celery (consider PostgreSQL and Redis servers are already started and available).

3. Activate the environment and run the project by executing `pyton manage.py runserver` command.

4. If you want to Celery tasks be able to execute run commands `python -m celery -A core worker -l info` & `python -m celery -A core beat -l info` in the separate shells.


## Documentation

Documentation is available online at [https://docs.sunflower3455.com/](https://docs.sunflower3455.com/) and in the [docs](https://github.com/sunflower-ing/docs) repository.

## Releases

You can check [https://github.com/sunflower-ing/core/releases](https://github.com/sunflower-ing/core/releases) for the releases and release notes.

## Contributing

If you'd like to contribute to this project please follow the [Issues](https://github.com/sunflower-ing/core/issues)
