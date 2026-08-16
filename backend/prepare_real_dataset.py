import os
import io
import requests
import pandas as pd
from urllib.parse import urlparse


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "..", "dataset")

os.makedirs(DATASET_DIR, exist_ok=True)

PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"

# Tranco's current list
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def download_phishtank():
    print("\n[1/4] Downloading PhishTank data...")

    headers = {
        "User-Agent": "PhishingDetectorResearch/1.0"
    }

    response = requests.get(
        PHISHTANK_URL,
        headers=headers,
        timeout=60
    )

    response.raise_for_status()

    df = pd.read_csv(io.BytesIO(response.content))

    print(f"PhishTank records downloaded: {len(df)}")

    return df


def download_tranco():
    print("\n[2/4] Downloading Tranco data...")

    response = requests.get(
        TRANCO_URL,
        timeout=60
    )

    response.raise_for_status()

    # Tranco file is a ZIP containing a CSV
    zip_path = os.path.join(
        DATASET_DIR,
        "tranco_latest.zip"
    )

    with open(zip_path, "wb") as f:
        f.write(response.content)

    print(f"Tranco file saved: {zip_path}")

    return zip_path


def prepare_phishing_data(df):
    print("\n[3/4] Preparing phishing URLs...")

    # Keep only verified + online phishing URLs
    df = df[
        (df["verified"] == "yes") &
        (df["online"] == "yes")
    ].copy()

    df = df[["url"]]

    df["label"] = 1

    # Remove empty URLs
    df = df.dropna(subset=["url"])

    # Remove duplicates
    df = df.drop_duplicates(subset=["url"])

    return df


def prepare_benign_data(zip_path, number_of_samples):
    print("\nPreparing benign URLs from Tranco...")

    df = pd.read_csv(
        zip_path,
        compression="zip",
        header=None,
        names=["rank", "domain"]
    )

    # Take more than needed so filtering still leaves enough
    df = df.head(number_of_samples * 2)

    df = df.dropna(subset=["domain"])

    # Convert domains into HTTPS URLs
    df["url"] = "https://" + df["domain"].astype(str)

    df["label"] = 0

    df = df[["url", "label"]]

    df = df.drop_duplicates(subset=["url"])

    return df


def get_domain(url):
    try:
        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    except Exception:
        return ""


def remove_overlap(phishing_df, benign_df):
    print("\nRemoving domain overlap...")

    phishing_domains = set(
        phishing_df["url"]
        .apply(get_domain)
    )

    before = len(benign_df)

    benign_df = benign_df[
        ~benign_df["url"]
        .apply(get_domain)
        .isin(phishing_domains)
    ]

    removed = before - len(benign_df)

    print(f"Removed overlapping benign domains: {removed}")

    return benign_df


def main():

    print("=" * 60)
    print("REAL-WORLD PHISHING DATASET PREPARATION")
    print("=" * 60)

    # ---------------------------------------------------------
    # PhishTank
    # ---------------------------------------------------------

    phishtank = download_phishtank()

    phishing_df = prepare_phishing_data(
        phishtank
    )

    print(
        f"Verified online phishing URLs: "
        f"{len(phishing_df)}"
    )

    # ---------------------------------------------------------
    # Tranco
    # ---------------------------------------------------------

    tranco_zip = download_tranco()

    # Balance the dataset
    number_of_benign = len(phishing_df)

    benign_df = prepare_benign_data(
        tranco_zip,
        number_of_benign
    )

    print(
        f"Benign URLs before filtering: "
        f"{len(benign_df)}"
    )

    # ---------------------------------------------------------
    # Remove overlap
    # ---------------------------------------------------------

    benign_df = remove_overlap(
        phishing_df,
        benign_df
    )

    # Make both classes equal
    sample_size = min(
        len(phishing_df),
        len(benign_df)
    )

    phishing_df = phishing_df.sample(
        n=sample_size,
        random_state=42
    )

    benign_df = benign_df.sample(
        n=sample_size,
        random_state=42
    )

    # ---------------------------------------------------------
    # Combine
    # ---------------------------------------------------------

    final_df = pd.concat(
        [
            phishing_df,
            benign_df
        ],
        ignore_index=True
    )

    # Shuffle
    final_df = final_df.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    # Remove accidental duplicates
    final_df = final_df.drop_duplicates(
        subset=["url"]
    )

    output_path = os.path.join(
        DATASET_DIR,
        "phishing_dataset_real.csv"
    )

    final_df.to_csv(
        output_path,
        index=False
    )

    # ---------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------

    print("\n" + "=" * 60)
    print("FINAL DATASET")
    print("=" * 60)

    print(f"Total records : {len(final_df)}")
    print(
        f"Benign       : "
        f"{sum(final_df['label'] == 0)}"
    )
    print(
        f"Phishing     : "
        f"{sum(final_df['label'] == 1)}"
    )

    print(f"\nSaved to:")
    print(output_path)

    print("\nDataset preparation complete.")


if __name__ == "__main__":
    main()