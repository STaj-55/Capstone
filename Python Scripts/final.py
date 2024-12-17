import rawpack
import agg_flows
import cleaning
import requests
import json

def main():
    while True:
        #Step 1: Capture Packets
        packets_df = rawpack.capture_packets()

        if packets_df is not None:
            #Step 2: Aggregate flows
            flows_df = agg_flows.aggregate_packets(packets_df)
            
            if flows_df is not None:
                #Step 3: Clean the data
                cleaned_data = cleaning.clean_data(flows_df)

                #Step 4: Send cleaned data to Flask API
                for index, row in cleaned_data.iterrows():
                    payload = row.to_dict()
                    response = requests.post('https:127.0.0.1:5001/predict', json=payload)

                    if response.status_code == 200:
                        print("Production:", response.json()['prediction'])
                    else:
                        print("error xD", response.json())
if __name__ == "__main__":
    main()
