import pyshark
from collections import defaultdict
import os  


def run_pkrscan(file_data):
    """
    Analyzes pcap file data for SIP call details and returns a formatted string
    containing the analysis results.
    """
    temp_pcap_file = None 
    output = ""  

    try:
        packets = pyshark.FileCapture(file_data, display_filter='sip')
    except Exception as e:
        print(f"Error loading pcap file: {e}")
    

    def packet_number(file_contents):
        count = sum(1 for _ in file_contents)
        return count

    def unique_call_id(file_contents):
        calls = {}
        for packet in file_contents:
            if hasattr(packet, 'sip'):
                callid = packet.sip.get_field_value('Call-ID')
                if not callid:
                    continue

                sender = packet.sip.get_field_value('From')
                receiver = packet.sip.get_field_value('To')
                contact = packet.sip.get_field_value('Contact')  
                method = packet.sip.get_field_value('Method')
                status_code = packet.sip.get_field_value('Status-Code')  
                
                timestamp = packet.sniff_time if hasattr(packet, 'sniff_time') else None

                via = packet.sip.get_field_value('Via')
                sender_ip = packet.ip.src if hasattr(packet, 'ip') else 'Unknown'

                if callid not in calls:
                    calls[callid] = {
                        'Call ID': callid,
                        'Sender': sender,
                        'Receiver': receiver,
                        'Device IP': contact,
                        'Methods': [],
                        'Sender Actual IP': sender_ip,
                        'Via': via,
                        'Start Time': None,
                        '200 OK Time': None,  
                        'End Time': None,
                        'Duration': None
                    }

                if method:
                    calls[callid]['Methods'].append(method)

           
                if (method == 'INVITE'):
                    calls[callid]['Start Time'] = timestamp
                if (status_code == '200'):
                    calls[callid]['200 OK Time'] = timestamp
                if (method == 'BYE'):
                    calls[callid]['End Time'] = timestamp

        for callid, data in calls.items():
            start = data['Start Time']
            end = data['End Time']
            if start and end:
                data['Duration'] = (end - start).total_seconds()

        return calls

    analysis_for_each_packet = unique_call_id(packets)
    
    packets.close() 

    for call_id, details in analysis_for_each_packet.items():
        output += f"Call-ID: {call_id}\n"
        output += f"  Sender: {details['Sender']}\n"
        output += f"  Receiver: {details['Receiver']}\n"
        output += f"  Device IP: {details['Device IP']}\n"
        output += f"  Methods: {details['Methods']}\n"
        output += f"  Sender IP: {details['Sender Actual IP']}\n"
        output += f"  Via: {details['Via']}\n"
        output += f"  Start Time: {details['Start Time']}\n"
        output += f"  200 OK Time: {details['200 OK Time']}\n"
        output += f"  End Time: {details['End Time']}\n"
        output += f"  Duration: {details['Duration']} seconds\n"
        output += "-" * 40 + "\n"


    if temp_pcap_file and os.path.exists(temp_pcap_file):
        os.remove(temp_pcap_file)

    return packet_number(packets), analysis_for_each_packet

if __name__ == '__main__':
   
    pass