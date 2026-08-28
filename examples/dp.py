"""
Differential privacy over a CSV "database", driven by a configuration file.

Runs the fixed query plan from config.yaml against a numeric column, debiting
the configured privacy budget as it goes. This is the library path: no service,
no tokens, no per-user accounting.

    uv run python examples/dp.py --config config.yaml
"""

import argparse

import pandas as pd

import cryptography_manager as cm


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        default="./config.yaml",
        help="Path to the configuration file",
    )
    args = parser.parse_args()

    config = cm.Config()
    config.load_from_file(args.config)
    dp_config = config.get_submodule_config("differential_privacy")

    csv_path = dp_config["data"]["database_path"]
    column = dp_config["data"]["numerical_column"]

    frame = pd.read_csv(csv_path)
    if column not in frame.columns:
        available = ", ".join(frame.columns)
        raise SystemExit(
            f"Column '{column}' not found in {csv_path}; available: {available}"
        )

    data = frame[column].to_numpy()

    adapter = cm.adapters.DifferentialPrivacyAdapter(config)
    results = adapter.execute_all(data)

    print(f"\nDifferentially private results over {csv_path}")
    print(f"Column '{column}', {len(data)} records")
    print("=" * 52)
    for name, value in results.items():
        formatted = f"{value:.4f}" if isinstance(value, float) else str(value)
        print(f"  {name:<10} {formatted:>18}")
    print("-" * 52)

    info = adapter.budget.info()
    print(
        f"  privacy budget   spent {info['spent_epsilon']:.2f}"
        f"  /  remaining {info['remaining_epsilon']:.2f}"
        f"  of {info['total_epsilon']:.2f}"
    )
    print(
        "\nResults are noisy by construction: rerunning gives different\n"
        "numbers, and each run costs budget that is never refunded."
    )


if __name__ == "__main__":
    main()
