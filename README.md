# lambda-authorizer-basic-auth

This is a sample template for lambda-authorizer-basic-auth - Below is a brief explanation of what we have generated for you:

```bash
.
├── lambda_authorizer_basic_auth                 <-- Source code for a lambda function
│   ├── app.py                  <-- Lambda function code
│   ├── __init__.py
│   └── requirements.txt        <-- Application dependencies
├── LICENSE                     <-- License for this project
├── NOTICE.txt
├── README.md                   <-- This instructions file
├── template.yaml               <-- SAM template
└── tests                       <-- Unit tests
    └── unit
        ├── __init__.py
        └── test_handler.py
```

## Requirements

* [AWS SAM CLI >v0.33.1](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
* [Python 3.8 installed](https://www.python.org/downloads/)
* [Docker installed](https://www.docker.com/community-edition)
* [Python Virtual Environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/)

## Setup process

## Packaging and deployment

AWS Lambda Python runtime requires a flat folder with all dependencies including the application. SAM will use `CodeUri` property to know where to look up for both application and dependencies:

```yaml
...
    HelloWorldFunction:
        Type: AWS::Serverless::Function
        Properties:
            CodeUri: lambda_authorizer_basic_auth/
            ...
```
### Installing dependencies

AWS SAM CLI has the ability to include required dependencies for Python based applications. It looks for a `requirements.txt` file in the `CodeUri` path of the application. To bundle this application's dependencies in with the application, execute `sam build`

```bash
sam build
```

This will execute a pip install of the packages listed in the `requirements.txt`

**NOTE:** As you change your application code as well as dependencies during development you'll need to make sure these steps are repeated in order to execute your Lambda and/or API Gateway locally.

### Deploying

Next, execute `sam deploy -g` to launch the guided deployment interface that will ask you some questions about your desired configuration at deployment. You can read more about this [here](https://aws.amazon.com/blogs/compute/a-simpler-deployment-experience-with-aws-sam-cli/):

```bash
sam deploy -g
```

> **See [Getting Started with AWS SAM ](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-getting-started.html) for more details in how to get started.**

## Testing

We use **Pytest** for testing our code and you can install it using pip: ``pip install pytest`` 

Next, we run `pytest` against our `tests` folder to run our initial unit tests:

```bash
python -m pytest tests/ -v
```

**NOTE**: It is recommended to use a Python Virtual environment to separate your application development from  your system Python installation.

# Appendix

### Python Virtual environment
**In case you're new to this**, python3 `virtualenv` module is not available in the standard library so we need to install it and then we can install our dependencies:

1. Create a new virtual environment
2. Install dependencies in the new virtual environment

```bash
pip install virtualenv
virtualenv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

**NOTE:** You can find more information about Virtual Environment at [Python Official Docs here](https://docs.python.org/3/tutorial/venv.html). Alternatively, you may want to look at [Pipenv](https://github.com/pypa/pipenv) as the new way of setting up development workflows
## AWS CLI commands

## Bringing to the next level

Here are a few ideas that you can use to get more acquainted as to how this overall process works:

* Create an additional API resource (e.g. /hello/{proxy+}) and return the name requested through this new path
* Update unit test to capture that
* Package & Deploy

Next, you can use the following resources to know more about beyond hello world samples and how others structure their Serverless applications:

* [AWS Serverless Application Repository](https://aws.amazon.com/serverless/serverlessrepo/)
* [Chalice Python Serverless framework](https://github.com/aws/chalice)
* Sample Python with 3rd party dependencies, pipenv and Makefile: ``sam init --location https://github.com/aws-samples/cookiecutter-aws-sam-python``
