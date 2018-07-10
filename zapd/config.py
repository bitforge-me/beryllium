import os
import configparser

def get_filename():
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "config.cfg")

def read_cfg():
    cp = configparser.ConfigParser()
    cp.read(get_filename())

    cfg = type("cfg", (object,), {})()

    # network
    cfg.testnet = cp["network"]["testnet"]
    cfg.testnet_start_block = cp["network"]["testnet_start_block"]
    cfg.mainnet_start_block = cp["network"]["mainnet_start_block"]
    cfg.start_block = cfg.testnet_start_block
    if not cfg.testnet:
        cfg.start_block = cfg.mainnet_start_block

    # trusted node
    cfg.node_api_key = cp["node"]["node_api_key"]
    cfg.node_http_base_url = cp["node"]["node_http_base_url"]

    # wallet
    cfg.asset_id = cp["wallet"]["asset_id"]
    cfg.address = cp["wallet"]["address"]

    # webhook
    cfg.webhook_key = cp["webhook"]["key"]
    cfg.webhook_url = cp["webhook"]["url"]

    # email
    cfg.email_admin = cp["email"]["admin"]
    cfg.email_from = cp["email"]["from"]
    cfg.email_host = cp["email"]["host"]

    return cfg

def init_wallet_address(address):
    import re
    pattern = "(address=)(.*)"
    with open(get_filename()) as f:
        data = f.read()
    def subaddr(m):
        return m.group(1) + address
    data = re.sub(pattern, subaddr, data)
    with open(get_filename(), "w") as f:
        f.write(data)
