import os
import json
import argparse
import pandas as pd
import numpy as np

# Set up the argument parser
parser = argparse.ArgumentParser(description="Load config from a JSON file.")
_ = parser.add_argument("json_file", type=str, help="Path to the JSON file")

# Parse the command line arguments
args = parser.parse_args()
json_file_path = args.json_file

# Template file reading
with open(json_file_path, "r") as file:
    values = json.load(file)

data = pd.read_csv(values["data"])
epsilon = values["epsilon"]
numeric = values["numeric"]

# Ensure epsilon is a float
epsilon = float(epsilon)

# Strip whitespace from column names
data.columns = data.columns.str.strip()

# Strip whitespace from all string (object) columns
str_cols = data.select_dtypes(include=["object", "string"]).columns
data[str_cols] = data[str_cols].apply(lambda col: col.str.strip())

dp_data = data.copy()

# Apply Laplace noise to each specified numeric column
for column, bounds in numeric.items():
    lower, upper = bounds
    sensitivity = upper - lower
    scale = sensitivity / epsilon

    # min(max()) is used to make sure the noisy values remain within [lower, upper]
    dp_data[column] = data[column].apply(
        lambda x: min(max(np.random.laplace(loc=x, scale=scale), lower), upper)
    )

# Create the output directory if it doesn't exist
output_dir = "dp_data"
os.makedirs(output_dir, exist_ok=True)

# Create the output file path
filename = f"{os.path.splitext(os.path.basename(values['data']))[0]}.csv"

output_file_name = os.path.join(output_dir, filename)
dp_data.to_csv(output_file_name, index=False)

print(f"Data after DP saved to: {output_file_name}")
