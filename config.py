import os
import configparser

def read_cfg():
    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), "config.cfg")
    cp = configparser.ConfigParser()
    cp.read(filename)

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

    return cfg
