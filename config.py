import os
import configparser

def read_cfg():
    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), "config.cfg")
    cp = configparser.ConfigParser()
    cp.read(filename)

    cfg = type("cfg", (object,), {})()

    cfg.testnet = cp["main"]["testnet"]
    cfg.testnet_start_block = cp["main"]["testnet_start_block"]
    cfg.mainnet_start_block = cp["main"]["mainnet_start_block"]
    cfg.start_block = cfg.testnet_start_block
    if not cfg.testnet:
        cfg.start_block = cfg.mainnet_start_block
    cfg.node_api_key = cp["main"]["node_api_key"]
    cfg.node_http_base_url = cp["main"]["node_http_base_url"]
    cfg.asset_id = cp["main"]["asset_id"]
    cfg.address = cp["main"]["address"]

    return cfg
