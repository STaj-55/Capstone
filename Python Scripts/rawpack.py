#Raw Packet Extraction with PyShark

import pyshark
import pandas as pd
from datetime import datetime
import signal
import sys

#Set up a flag to indicate the packet capture status
capturing = True

#Define a signal handler to handle force quit
def signal_handler(sig, frame):
    global capturing
    print("\n[INFO] Manual Stop Requested by User.")
    capturing = False

#Register the signal handler for Ctrl + C
signal.signal(signal.SIGINT, signal_handler)

#Set up a PyShark Live Capture on our Bridged interface
cap = pyshark.LiveCapture(interface='en0', bpf_filter='tcp or udp')

#List to store extracted packet information
cap_pack = []

#Define the threshold after which aggregation is triggered
threshold = 1000

#Import aggregation function from agg_flows.py
from agg_flows import aggregate_packets

def capture_packets(interface='en0', theshold=1000):
    """
    This function captures packets with PyShark, extracts the necessary information information for data aggregation, and sends it when 100 packets is reached.
    """
    global cap, capturing, cap_pack
    #Capture a sufficient number of packets for further processing
    print("Lets capture some packets!")
    print("\nPress CTRL + C to stop the capture.")
    try:
        for packet in cap.sniff_continuously():
            if not capturing:
                break
        
            try:
                if 'IP' in packet:
                    protocol = 'TCP' if 'TCP' in packet else 'UDP' if 'UDP' in packet else None

                    if protocol:
                        print(f"Processing packet at {packet.sniff_time}")
                        #Extract relevant necessary information from each packet
                        pack_data = {
                            'time': packet.sniff_time,
                            'source_ip': packet.ip.src if 'IP' in packet else None,
                            'destination_ip': packet.ip.dst if 'IP' in packet else None,
                            'source_port': packet[protocol].srcport if protocol in packet else None,
                            'destination_port': packet[protocol].dstport if protocol in packet else None,
                            'protocol': packet.transport_layer,
                            'packet_length': int(packet.length),
                            'tcp_flags': packet.tcp.flags if protocol == 'TCP' else None,
                            'header_length': packet.tcp.hdr_len if protocol == 'TCP' else None,
                            'window_size': packet.tcp.window_size if protocol == 'TCP' else None,        
                        }
                        cap_pack.append(pack_data)

                        #Check if we have reached the threshold
                        if len(cap_pack) >= threshold:
                            print(f"\nThreshold has been reached. Aggregating packets...")
                            #Call the aggregate_packets function.
                            aggregate_packets(pd.DataFrame(cap_pack))
                            #Reset cap_pack after processing
                            cap_pack = []

            except AttributeError as e:
                print(f"Atrribute error: {e}")
                continue
            except Exception as e:
                print(f"[ERROR] Unexepected exception: {e}")
                continue

    except KeyboardInterrupt:
        print("\nPacket Capture stopped by user.")

    finally:
        try:
            cap.close()
        except Exception as e:
            print(f"Error while closing capture: {e}")
            
    #After the loop ends, check if there are any remaining packets to process
    if len(cap_pack) > 0:
        print(f"Process remaining {len(cap_pack)} packets.")
        flows = aggregate_packets(pd.DataFrame(cap_pack))
        return flows
    
    #If no packets are captured
    return None

    sys.exit(0)

#Main program entry point
if __name__ == '__main__':
    try:
        packets_df = capture_packets()
        if not packets_df.empty:
            print(packets_df.head())
    except KeyboardInterrupt:
        print(f"\n Main program interrupted by user.")
    finally:
        print("Program exiting.")
        sys.exit(0)
        #aggregate_packets(pd.DataFrame(cap_pack))

    #After the loop ends, save the data from the captured packets
    #df_packets = pd.DataFrame(cap_pack)
    #print(f"Captured {len(df_packets)} packets.")
    #if not df_packets.empty:
    #    print(df_packets.head())

    #Convert captured packet data to DataFrame
    #df_packets.to_csv('captured_packets.csv', index=False)