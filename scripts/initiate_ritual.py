#!/usr/bin/python3

import click
from ape import project
from ape.cli import ConnectedProviderCommand, account_option, network_option

from deployment.constants import SUPPORTED_TACO_DOMAINS
from deployment.params import Transactor
from deployment.registry import contracts_from_registry
from deployment.utils import check_plugins, registry_filepath_from_domain, sample_nodes


@click.command(cls=ConnectedProviderCommand)
@account_option()
@click.option(
    "--domain",
    "-d",
    help="TACo domain",
    type=click.Choice(SUPPORTED_TACO_DOMAINS),
    required=True,
)
@click.option(
    "--duration",
    "-t",
    help="Duration of the ritual",
    type=int,
    required=True,
)
@click.option(
    "--access-controller",
    "-a",
    help="global allow list or open access authorizer.",
    type=click.Choice(["GlobalAllowList", "OpenAccessAuthorizer", "ManagedAllowList"]),
    required=True,
)
@click.option(
    "--fee-model",
    "-f",
    help="The name of a fee model contract.",
    type=click.Choice(["FreeFeeModel", "BqETHSubscription"]),
    required=True,
)
@click.option(
    "--num-nodes",
    help="Number of nodes to use for the ritual.",
    type=int,
    required=True,
)
@click.option(
    "--random-seed",
    help="Random seed integer for sampling.",
    required=False,
    type=int
)
@click.option(
    "--authority",
    help="The address of the ritual authority.",
    required=False,
    type=str
)
def cli(domain, duration, account, access_controller, fee_model, num_nodes, random_seed, authority):
    check_plugins()
    transactor = Transactor(account=account)
    registry_filepath = registry_filepath_from_domain(domain=domain)
    chain_id = project.chain_manager.chain_id
    deployments = contracts_from_registry(filepath=registry_filepath, chain_id=chain_id)
    coordinator = deployments[project.Coordinator.contract_type.name]

    try:
        access_controller = deployments[getattr(project, access_controller).contract_type.name]
        fee_model = deployments[getattr(project, fee_model).contract_type.name]
    except KeyError as e:
        raise ValueError(f"Contract not found in registry for domain {domain}: {e}")

    if not authority:
        authority = transactor.get_account().address
        click.confirm(f"Using {authority} as the ritual authority. Continue?", abort=True)

    providers = sample_nodes(
        domain=domain, num_nodes=num_nodes, duration=duration, random_seed=random_seed
    )

    transactor.transact(
        coordinator.initiateRitual,
        fee_model.address,
        providers,
        authority,
        duration,
        access_controller.address,
    )


if __name__ == "__main__":
    cli()
