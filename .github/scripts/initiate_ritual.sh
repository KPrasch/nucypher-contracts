ape run initiate_ritual \
--autosign \
--account AUTOMATION \
--network polygon:mainnet:${RPC_PROVIDER} \
--domain mainnet \
--duration 86400 \
--access-controller GlobalAllowList \
--fee-model FreeFeeModel \
--authority ${DKG_AUTHORITY_ADDRESS} \
--min-version ${MIN_VERSION} \
--num-nodes 30
