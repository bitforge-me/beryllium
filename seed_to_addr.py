import sys
import pywaves

print('USAGE: seed_to_addr.py <TESTNET> <SEED>')
testnet = sys.argv[1].lower() in ['true', '1', 't', 'y', 'yes', 'yeah', 'yup', 'certainly', 'uh-huh']
print('TESTNET: ' + str(testnet))
seed = sys.argv[2]
print('SEED: ' + seed)
print('......')

pywaves.setOffline()
if testnet:
    pywaves.setChain('testnet')
addr = pywaves.Address(seed=seed)
print('ADDRESS: ' + str(addr.address))
print('PUBKEY: ' + str(addr.publicKey))
