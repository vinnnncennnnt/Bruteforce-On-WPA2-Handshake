from scapy.all import *

class WPA_key(Packet):
    name = "WPA_key"
    fields_desc = [ ByteField("descriptor_type", 1),
                   BitField("SMK_message",0,3),
                   BitField("encrypted_key_data",0,1),
                   BitField("request",0,1),
                   BitField("error",0,1),
                   BitField("secure",0,1),
                   BitEnumField("key_MIC",0,1,{0:'not present',1:'present'}),
                   BitField("key_ACK",1,1),
                   BitField("install",0,1),
                   BitField("key_index",0,2),
                   BitEnumField("key_type",1,1,{0:'Group Key',1:'Pairwise Key'}),
                   BitEnumField("key_descriptor_Version",2,3,{1:'HMAC-MD5 MIC',
                                                              2:'HMAC-SHA1 MIC'}),
                   LenField("len", None, "H"),
                   StrFixedLenField("replay_counter", "", 8),
                   StrFixedLenField("nonce", "", 32),
                   StrFixedLenField("key_iv", "", 16),
                   StrFixedLenField("wpa_key_rsc", "", 8),
                   StrFixedLenField("wpa_key_id", "", 8),
                   StrFixedLenField("wpa_key_mic", "", 16),
                   LenField("wpa_key_length", None, "H"),
                   StrLenField("wpa_key", "", length_from=lambda pkt:pkt.wpa_key_length)]

    def extract_padding(self, s):
        l = self.len
        return s[:l],s[l:]
    def hashret(self):
        return chr(self.type)+self.payload.hashret()
    def answers(self, other):
        if isinstance(other,WPA_key):
            return 1
        return 0

bind_layers( EAPOL, WPA_key, type=3)
    
if __name__ == "__main__":
    import socket, sys, struct
    interact(mydict=globals(), mybanner="EAPOL")
