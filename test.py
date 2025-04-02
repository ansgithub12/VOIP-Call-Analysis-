import pyshark
from collections import defaultdict

packets = pyshark.FileCapture('Forensic_challenge_4.pcap', display_filter='sip')

def packet_number(file_contents):
    count = sum(1 for _ in file_contents)
    return count

def unique_call_id(file_contents):
    calls = {}
    methods = []
    for packet in packets:
        if hasattr(packet, 'sip'):
            callid = packet.sip.get_field_value('Call-ID')
            sender = packet.sip.get_field_value('From')
            receiver = packet.sip.get_field_value('To')
            contact = packet.sip.get_field_value('Contact') # actual device ip
            method = packet.sip.get_field_value('Method')
            if method:
                methods.append(method)
               
            if callid:
                calls[callid] = (sender, receiver, contact, methods)
            
            # calls.add(callid)
    return calls



analysis_for_each_packet = unique_call_id(packets)
for call_id, (sender, receiver, contact, methods) in analysis_for_each_packet.items():
    print(f"Call-ID: {call_id}\n  Sender: {sender}\n  Receiver: {receiver}\n Device IP: {contact}\n Methods: {methods}\n")

packets.close()

# print all methods used in call 
# print initial timestamp?
# seperate fucntion for timing of each method?