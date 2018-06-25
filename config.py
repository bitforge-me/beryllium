import os
import configparser

def read_cfg():
    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), "config.cfg")
    cp = configparser.ConfigParser()
    cp.read(filename)

    cfg = type("cfg", (object,), {})()

    cfg.node_http_base_url = cp["main"]["node_http_base_url"]
    cfg.asset_id = cp["main"]["asset_id"]
    cfg.address = cp["main"]["address"]

    return cfg
