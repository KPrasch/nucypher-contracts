from pathlib import Path

from ape import networks, project

import deployment

LOCAL_BLOCKCHAIN_ENVIRONMENTS = ["local"]
CURRENT_NETWORK = networks.network.name
DEPLOYMENT_DIR = Path(deployment.__file__).parent
CONSTRUCTOR_PARAMS_DIR = DEPLOYMENT_DIR / "constructor_params"
ARTIFACTS_DIR = DEPLOYMENT_DIR / "artifacts"
VARIABLE_PREFIX = "$"
SPECIAL_VARIABLE_DELIMITER = ":"
HEX_PREFIX = "0x"
BYTES_PREFIX = "bytes"
DEPLOYER_INDICATOR = "deployer"
PROXY_NAME = "TransparentUpgradeableProxy"
OZ_DEPENDENCY = project.dependencies["openzeppelin"]["4.9.1"]
