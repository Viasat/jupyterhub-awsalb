# jupyterhub-awsalb (jupyterhub-awsalb)

This package allows Jupyterhub to use an AWS Application Load Balancer as
the proxy implementation.

# Authentication

This module uses [boto3](http://boto3.readthedocs.io/en/latest/) for talking
with the AWS apis and should therefore support any of the normal authentication
methods for boto3 such as the aws config files or environment variables.

This module can optionally use STS tokens from a [Hashicorp
Vault](https://www.vaultproject.io/) if configured. See the module for the
traitlets to set in the config file.

# TODO

[ ] Make things more asynchronous with aws api calls

# LICENSE

This module is released under the [BSD-3-Clause
License](https://opensource.org/licenses/BSD-3-Clause)
