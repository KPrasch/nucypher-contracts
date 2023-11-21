#!/usr/bin/python3

from ape import project

from deployment.constants import ARTIFACTS_DIR, CONSTRUCTOR_PARAMS_DIR
from deployment.params import Deployer
from deployment.registry import read_registry

VERIFY = True
CONSTRUCTOR_PARAMS_FILEPATH = CONSTRUCTOR_PARAMS_DIR / "mainnet" / "root.yml"


def main():
    current_mainnet_registry = read_registry(ARTIFACTS_DIR / "mainnet.json")
    polygon_chain_id = 137
    polygon_child_name = "PolygonChild"
    polygon_childs = [
        entry for entry in current_mainnet_registry
        if entry.chain_id == polygon_chain_id and entry.name == polygon_child_name
    ]
    if len(polygon_childs) is not 1:
        raise ValueError("Mainnet root deployment requires valid child deployment first")
    
    deployer = Deployer.from_yaml(filepath=CONSTRUCTOR_PARAMS_FILEPATH, verify=VERIFY)

    taco_application = deployer.deploy(project.TACoApplication)

    polygon_root = deployer.deploy(project.PolygonRoot)

    # Need to set child application before transferring ownership
    deployer.transact(taco_application.setChildApplication, polygon_root.address)
    deployer.transact(
        taco_application.transferOwnership,
        deployer.constants.THRESHOLD_COUNCIL_ETH_MAINNET
    )

    deployments = [
        taco_application,
        polygon_root,
    ]

    deployer.finalize(deployments=deployments)
