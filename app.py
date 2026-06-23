from flask import Flask, render_template, request

app = Flask(__name__)

def check_phishing(url):
    score = 0
    reasons = []

    if '@' in url:
        score += 1
        reasons.append("Contains @ symbol")

    if len(url) > 75:
        score += 1
        reasons.append("Very long URL")

    for word in ["login", "verify", "bank", "secure", "account", "update"]:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains suspicious word: {word}")

    if url.startswith("http://"):
        score += 1
        reasons.append("Uses HTTP instead of HTTPS")

    return ("Suspicious" if score >= 2 else "Safe"), reasons

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    reasons = []
    if request.method == "POST":
        url = request.form["url"]
        result, reasons = check_phishing(url)
    return render_template("index.html", result=result, reasons=reasons)

if __name__ == "__main__":
    app.run(debug=True)
