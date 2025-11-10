import json
import pandas as pd
import matplotlib.pyplot as plt

# === Load blockchain data ===
with open("blockchain_export.json", "r") as f:
    blockchain_data = json.load(f)

# === General summary ===
print("\n===== BLOCKCHAIN SUMMARY =====")
print(f"Total Blocks: {blockchain_data['length']}")
print(f"Difficulty: {blockchain_data['difficulty']}")
print(f"Registered Nodes: {', '.join(blockchain_data['nodes'])}")
print(f"Pending Transactions: {blockchain_data['pending_transactions']}")

# === Extract block-level details ===
block_info = []
for block in blockchain_data["blocks"]:
    block_info.append({
        "Block Index": block["index"],
        "Transactions": len(block["transactions"]),
        "Miner (from QKD)": block["qkd_metadata"].get("node_a", "N/A"),
        "QKD Protocol": block["qkd_metadata"].get("protocol", "N/A"),
        "Error Rate": block["qkd_metadata"].get("error_rate", 0.0),
        "QKD Secure": block["qkd_metadata"].get("is_secure", False),
        "Hash (first 8 chars)": block["hash"][:8],
    })

df_blocks = pd.DataFrame(block_info)
print("\n===== BLOCK DETAILS =====")
print(df_blocks.to_string(index=False))

# === Visualization 1: Transactions per block ===
plt.figure(figsize=(8, 4))
plt.bar(df_blocks["Block Index"], df_blocks["Transactions"], color="orange", edgecolor="black")
plt.title("Number of Transactions per Block")
plt.xlabel("Block Index")
plt.ylabel("Transactions")
plt.grid(True, linestyle="--", alpha=0.6)
plt.tight_layout()
plt.show()

# === Visualization 2: QKD error rate per block ===
plt.figure(figsize=(8, 4))
plt.plot(df_blocks["Block Index"], df_blocks["Error Rate"], marker='o', color='green')
plt.title("QKD Error Rate per Block")
plt.xlabel("Block Index")
plt.ylabel("Error Rate")
plt.grid(True, linestyle="--", alpha=0.6)
plt.tight_layout()
plt.show()

# === Optional: Export summary for report ===
df_blocks.to_csv("block_results_summary.csv", index=False)
print("\nSummary exported as 'block_results_summary.csv'")
