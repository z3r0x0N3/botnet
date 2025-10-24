import json
from web3 import Web3
import solcx
solcx.install_solc('0.8.20')
solcx.set_solc_version('0.8.20')
from solcx import compile_source

# ----------------------------------------------------------------------
#  Blockchain Configuration (Option B — Self-Hosted Node)
# ----------------------------------------------------------------------
# Instead of Infura or Alchemy, this connects directly to your own node.
# Make sure your local or remote Geth/Erigon/Nethermind node is running with:
#   geth --http --http.addr 0.0.0.0 --http.port 8545 --http.api eth,net,web3,personal,miner
# If remote, replace 127.0.0.1 with its IP or hostname.
# ----------------------------------------------------------------------

GANACHE_URL = "http://127.0.0.1:7545"
LOCAL_NODE_URL = "http://127.0.0.1:8545"   # your own Ethereum node
RPC_URL = LOCAL_NODE_URL                   # active connection target

# ----------------------------------------------------------------------

def compile_contract(solidity_source):
    compiled_sol = compile_source(solidity_source)
    contract_id, contract_interface = compiled_sol.popitem()
    return contract_interface


def deploy_contract(w3, contract_interface):
    contract = w3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin']
    )
    tx_hash = contract.constructor().transact({'from': w3.eth.accounts[0]})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt.contractAddress


def get_contract_instance(w3, contract_address, contract_abi):
    return w3.eth.contract(address=contract_address, abi=contract_abi)


def set_c2_url(contract_instance, w3, new_url):
    tx_hash = contract_instance.functions.setC2Url(new_url).transact({'from': w3.eth.accounts[0]})
    w3.eth.wait_for_transaction_receipt(tx_hash)


def get_c2_url(contract_instance):
    return contract_instance.functions.getC2Url().call()


if __name__ == '__main__':
    with open('C2UrlRegistry.sol', 'r') as f:
        solidity_source = f.read()

    # --- connect to your own blockchain node instead of Ganache/Infura ---
    w3 = Web3(Web3.HTTPProvider(RPC_URL))

    if not w3.is_connected():
        raise ConnectionError(f"Failed to connect to local node at {RPC_URL}. "
                              f"Ensure your node is running with --http enabled.")

    contract_interface = compile_contract(solidity_source)

    contract_address = deploy_contract(w3, contract_interface)

    print(f"Contract deployed at: {contract_address}")

    with open('contract_meta.json', 'w') as f:
        json.dump({
            'address': contract_address,
            'abi': contract_interface['abi']
        }, f)

