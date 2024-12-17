#CICIDS2017 Cleaning

#This program will follow the same steps as Kaggle user 'StrGenIx | Laurens D'hooge',
#which will be used to initially preprocess our evaluation dataset, to then prep for
#live data feed

import numpy as np
import pandas as pd
from fastai.tabular.all import df_shrink

# Set your input and output file paths here
#input_file_path = "/Users/sultan/Desktop/Folder/Capstone/aggregated_flows.parquet"  # <-- Insert your Parquet file path here
#output_file_path = "/Users/sultan/Desktop/Folder/Capstone/prepped.parquet"  # <-- Insert the path where you want to save the cleaned Parquet

def clean_data(df):
    # List of columns to drop (for consistency across CIC NIDS datasets)
    drop_columns = [
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
    ]

    # Clean the data
    # Remove leading/trailing whitespace from column names
    df.columns = df.columns.str.strip()

    # Drop unnecessary columns if they exist
    df.drop(columns=drop_columns, inplace=True, errors='ignore')

    # Apply df_shrink to reduce memory usage
    df = df_shrink(df)

    # Replace inf/-inf with NaN and drop NaN rows 
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Remove duplicated rows and reset the index
    df.drop_duplicates(inplace=True)
    df.reset_index(inplace=True, drop=True)

    # Checks for missing values
    miss_vals = df.isnull().sum()
    print("Columns with missing values: ")
    print(miss_vals[miss_vals > 0])

    # Checks for duplicates to ensure none are present
    dupe_rows = df.duplicated().sum()
    print(f"Number of duplicate rows: {dupe_rows}")

    # Remove duplicated rows
    df.drop_duplicates(inplace=True)

    # Shows confirmation of any duplicates
    print(f"Number of duplicates rows after dropping: {df.duplicated().sum()}")

    return df
# Save the cleaned DataFrame to a new Parquet file
#df.to_parquet(output_file_path)
