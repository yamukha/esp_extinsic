from substrateinterface import SubstrateInterface, Keypair, KeypairType
from substrateinterface.exceptions import SubstrateRequestException

# import logging
# logging.basicConfig(level=logging.DEBUG)
block_hash = "0x51d15792ff3c5ee9c6b24ddccd95b377d5cccc759b8e76e5de9250cf58225087"

try:
    substrate = SubstrateInterface(
#        url="http://kusama.rpc.robonomics.network:80/rpc/",
        url="http://127.0.0.1:9933",
        ss58_format=2,
        type_registry_preset='kusama'
    )
except ConnectionRefusedError:
    print("No local Substrate node running, try running 'start_local_substrate_node.sh' first")
    exit()

mnemonic = "old leopard transfer rib spatial phone calm indicate online fire caution review"
keypair = Keypair.create_from_mnemonic(mnemonic, crypto_type=KeypairType.ED25519)


account_info = substrate.query('System', 'Account', params=[keypair.ss58_address])
print('priv key ', bytes(keypair.private_key).hex())
print('priv key ', keypair.private_key)

print('pub key ', bytes(keypair.public_key).hex())
print('pub key ', keypair.public_key)
print('ss58    ', keypair.ss58_address)

print('Account info', account_info.value)

call_bt = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
        'value': 1 
    }
)

call_dr = substrate.compose_call(
    call_module='Datalog',
    call_function='record',
    call_params={
        'record': 'ooooo', 
    }
)

call=call_dr # datalog record call

# Get payment info
print ("call: ",call, "\nas bytes: ", call.encode())

payment_info = substrate.get_payment_info(call=call, keypair=keypair)

print("Payment info: ", payment_info)

extrinsic = substrate.create_signed_extrinsic(
    call=call,
    keypair=keypair,
    era={'period': 64}
)

nonce = 0
era= 0
signature_payload = substrate.generate_signature_payload(call=call, era=era, nonce=nonce)

print("payload: ", signature_payload)

try:
    print ('try submit')
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=False)

    print('Extrinsic "{}" included in block "{}"'.format(
        receipt.extrinsic_hash, receipt.block_hash
    ))

    if receipt.is_success:

        print(' Success, triggered events:')
        for event in receipt.triggered_events:
            print(event.value)

    else:
        print('Extrinsic Failed: ', receipt.error_message)


except SubstrateRequestException as e:
    print("Failed to send: {}".format(e))
