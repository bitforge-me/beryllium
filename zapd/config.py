import os
import configparser

def get_filename():
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "config.cfg")

def get_secret_filename():
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "config_secret.cfg")

def read_cfg():
    cp = configparser.ConfigParser()
    cp.read(get_filename())

    cfg = type("cfg", (object,), {})()

    # network
    cfg.testnet = cp.getboolean("network", "testnet")
    cfg.testnet_start_block = cp["network"]["testnet_start_block"]
    cfg.mainnet_start_block = cp["network"]["mainnet_start_block"]
    cfg.start_block = int(cfg.testnet_start_block)
    if not cfg.testnet:
        cfg.start_block = int(cfg.mainnet_start_block)

    # trusted node
    cfg.node_api_key = cp["node"]["node_api_key"]
    cfg.node_http_base_url = cp["node"]["node_http_base_url"]

    # wallet
    cfg.asset_id_testnet = cp["wallet"]["asset_id_testnet"]
    cfg.asset_id_mainnet = cp["wallet"]["asset_id_mainnet"]
    cfg.asset_id = cfg.asset_id_testnet
    if not cfg.testnet:
        cfg.asset_id = cfg.asset_id_mainnet
    cfg.address = cp["wallet"]["address"]

    # email
    cfg.email_admin = cp["email"]["admin"]
    cfg.email_from = cp["email"]["from"]
    cfg.email_host = cp["email"]["host"]

    # secret
    cfg.seed = None
    cfg.webhook_key = None
    cfg.webhook_url = None
    if os.path.exists(get_secret_filename()):
        cp.read(get_secret_filename())
        # wallet seed
        try:
            cfg.seed = cp["wallet"]["seed"]
        except:
            pass
        # webhook
        try:
            cfg.webhook_key = cp["webhook"]["key"]
            cfg.webhook_url = cp["webhook"]["url"]
        except:
            pass

    return cfg

def set_testnet(value):
    # write address
    import re
    with open(get_filename()) as f:
        data = f.read()
    def subtestnet(m):
        return m.group(1) + value
    pattern = "^(testnet=)(.*)"
    data = re.sub(pattern, subtestnet, data, flags=re.MULTILINE)
    with open(get_filename(), "w") as f:
        f.write(data)

def init_wallet_address(address, seed):
    # write address
    import re
    with open(get_filename()) as f:
        data = f.read()
    def subaddr(m):
        return m.group(1) + address
    pattern = "^(address=)(.*)"
    data = re.sub(pattern, subaddr, data, flags=re.MULTILINE)
    with open(get_filename(), "w") as f:
        f.write(data)

    # write seed
    cp = configparser.ConfigParser()
    cp.read(get_secret_filename())
    if not cp.has_section("wallet"):
        cp.add_section("wallet")
    if cp.has_option("wallet", "seed"):
        if cp.get("wallet", "seed") != seed:
            raise Exception("There is already a seed that is different!")
    else:
        cp.set("wallet", "seed", seed)
        with open(get_secret_filename(), "w") as f:
            cp.write(f)

def set_webhook_config(url, key):
    # write url and key
    cp = configparser.ConfigParser()
    cp.read(get_secret_filename())
    if not cp.has_section("webhook"):
        cp.add_section("webhook")
        cp.set("webhook", "url", url)
        cp.set("webhook", "key", key)
        with open(get_secret_filename(), "w") as f:
            cp.write(f)
