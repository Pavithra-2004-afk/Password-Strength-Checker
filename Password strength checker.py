import tkinter as tk
from tkinter import messagebox
import hashlib
import requests

def check_password_leak(password):
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    first5, tail = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{first5}"
    res = requests.get(url)
    if res.status_code != 200:
        return None
    hashes = (line.split(':') for line in res.text.splitlines())
    return any(tail == h for h, _ in hashes)

def password_strength(password):
    score = 0
    suggestions = []

    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters.")

    if any(c.isupper() for c in password):
        score += 1
    else:
        suggestions.append("Include uppercase letters.")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        suggestions.append("Add numbers.")

    if any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password):
        score += 1
    else:
        suggestions.append("Use special characters (!, @, #, etc.)")

    strength_levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    return strength_levels[score], suggestions, score

def analyze_password():
    password = entry.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password.")
        return

    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)

    strength, suggestions, score = password_strength(password)

    color_map = ["red", "orange", "gold", "green", "darkgreen"]
    result_text.insert(tk.END, f"🔐 Password Strength: {strength}\n", "strength")
    result_text.tag_config("strength", foreground=color_map[score], font=("Arial", 12, "bold"))

    result_text.insert(tk.END, "\n🛡️ Checking data breach...\n")
    try:
        leaked = check_password_leak(password)
        if leaked is None:
            result_text.insert(tk.END, "⚠️ Error checking breach.\n")
        elif leaked:
            result_text.insert(tk.END, "❌ Your password was found in a breach!\n")
        else:
            result_text.insert(tk.END, "✅ Not found in any known breach.\n")
    except:
        result_text.insert(tk.END, "⚠️ Could not connect to the breach API.\n")

    if suggestions:
        result_text.insert(tk.END, "\n🔒 Suggestions to strengthen your password:\n")
        for tip in suggestions:
            result_text.insert(tk.END, f"- {tip}\n")

    result_text.config(state=tk.DISABLED)

# --- Show / Hide toggle function ---
def toggle_password():
    if entry.cget("show") == "":
        entry.config(show="*")
        toggle_btn.config(text="👁 Show")
    else:
        entry.config(show="")
        toggle_btn.config(text="🙈 Hide")

# GUI Design
root = tk.Tk()
root.title("🔐 Pavithra's Password Shield")
root.geometry("480x500")
root.resizable(False, False)
root.configure(bg="#f0f8ff")

# Heading
tk.Label(root, text="🔒 Password Strength & Safety Checker", font=("Helvetica", 14, "bold"), bg="#f0f8ff").pack(pady=10)

# Entry field
tk.Label(root, text="Enter your password:", font=("Arial", 11), bg="#f0f8ff").pack()

frame = tk.Frame(root, bg="#f0f8ff")
frame.pack(pady=5)

entry = tk.Entry(frame, show="*", width=30, font=("Arial", 12))
entry.pack(side=tk.LEFT, padx=5)

toggle_btn = tk.Button(frame, text="👁 Show", command=toggle_password, bg="#2196f3", fg="white", font=("Arial", 9, "bold"))
toggle_btn.pack(side=tk.LEFT)

# Check button
tk.Button(root, text="Check Password", command=analyze_password, bg="#4caf50", fg="white", font=("Arial", 11, "bold")).pack(pady=10)

# Output Text Box
result_text = tk.Text(root, height=15, width=58, wrap=tk.WORD, font=("Arial", 10))
result_text.pack(pady=5)
result_text.config(state=tk.DISABLED)

# Footer
tk.Label(root, text="© Pavithra | Cybersecurity Dept | 2025", font=("Arial", 9), bg="#f0f8ff", fg="gray").pack(side=tk.BOTTOM, pady=5)

root.mainloop()
