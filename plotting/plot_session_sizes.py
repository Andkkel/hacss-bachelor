import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("session_sizes.csv", header=None, names=["messages", "signal_bytes", "hacss_bytes"])

plt.figure(figsize=(10, 6))
plt.plot(df["messages"], df["signal_bytes"] / 1024, label="Signal", marker="o")
plt.plot(df["messages"], df["hacss_bytes"] / 1024, label="HACSS", marker="o")

plt.xlabel("Messages exchanged")
plt.ylabel("Session state size (KB)")
plt.title("Session State Size Growth")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("session_sizes.png", dpi=150)
plt.show()