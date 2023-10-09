#!/usr/bin/python3

from ape import project

from deployment.constants import (
    CONSTRUCTOR_PARAMS_DIR,
    CURRENT_NETWORK,
    LOCAL_BLOCKCHAIN_ENVIRONMENTS,
    OZ_DEPENDENCY,
)
from deployment.params import Deployer

VERIFY = CURRENT_NETWORK not in LOCAL_BLOCKCHAIN_ENVIRONMENTS
CONSTRUCTOR_PARAMS_FILEPATH = CONSTRUCTOR_PARAMS_DIR / "lynx" / "child.yml"


def main():
    deployer = Deployer.from_yaml(filepath=CONSTRUCTOR_PARAMS_FILEPATH, verify=VERIFY)
    deployer.run()

