import pandas as pd

LOG_FILE = "chat_logs.jsonl"
SECRET_FILE = "secret_doc.txt"
OUTPUT_CSV = "leak_check_results.csv"

with open(SECRET_FILE, "r", encoding="utf-8") as f:
    secret_text = f.read().strip()

df = pd.read_json(LOG_FILE, lines=True)

if "response" not in df.columns:
    raise ValueError("No 'response' column found in chat_logs.jsonl")

df["confirmed_secret_leak_exact"] = df["response"].fillna("").str.contains(
    secret_text, case=False, regex=False
)

# leak indicators from the secret file
secret_lines = [line.strip() for line in secret_text.splitlines() if line.strip()]
for i, line in enumerate(secret_lines, start=1):
    df[f"secret_line_{i}_leaked"] = df["response"].fillna("").str.contains(
        line, case=False, regex=False
    )

print("=" * 60)
print("SECRET LEAK CONFIRMATION")
print("=" * 60)
print("Total events:", len(df))
print("Exact full-secret leaks:", df["confirmed_secret_leak_exact"].sum())

line_cols = [c for c in df.columns if c.startswith("secret_line_")]
for col in line_cols:
    print(f"{col}: {df[col].sum()}")

hits = df[df["confirmed_secret_leak_exact"]][
    ["timestamp", "ip", "session_id", "attack_family", "mode", "prompt", "response"]
]

if hits.empty:
    print("\nNo exact full-secret leaks found.")
else:
    print("\nExact full-secret leak events:")
    print(hits.to_string(index=False))

df.to_csv(OUTPUT_CSV, index=False)
print(f"\nSaved leak analysis to: {OUTPUT_CSV}")