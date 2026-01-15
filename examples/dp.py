import argparse

import numpy as np
import pandas as pd

import cryptography_manager as cm


def main() -> None:
    # ------------------ CLI ------------------
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        type=str,
        default="./config.yaml",
        help="Path to the config file",
    )
    args = parser.parse_args()

    # ------------------ LOAD CONFIG ------------------
    config = cm.Config()
    config.load_from_file(args.config)

    dp_cfg = config.get_submodule_config("differential_privacy")

    # ------------------ LOAD CSV "DATABASE" ------------------
    csv_path = dp_cfg["data"]["database_path"]
    numeric_column = dp_cfg["data"]["numerical_column"]

    df = pd.read_csv(csv_path)

    if numeric_column not in df.columns:
        raise ValueError(f"Numeric column '{numeric_column}' not found in CSV")

    # Convert column to NumPy array
    data: np.ndarray = df[numeric_column].to_numpy()

    # ------------------ INITIALIZE DP ADAPTER ------------------
    dp = cm.adapters.DifferentialPrivacyAdapter(config)

    # ------------------ EXECUTE CONFIGURED QUERIES ------------------
    results = dp.execute_all(data)

    # ------------------ OUTPUT ------------------
    print("Differential Privacy Results")
    print("=" * 30)

    for name, value in results.items():
        print(f"{name}: {value}")

    print("-" * 30)
    print(f"Remaining ε: {dp.budget.remaining_epsilon}")


if __name__ == "__main__":
    main()
