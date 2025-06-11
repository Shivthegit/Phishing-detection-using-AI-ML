from flask import Flask, request, render_template
import pandas as pd
import joblib
from utils.feature_extraction import extract_features
app = Flask(__name__)
model = joblib.load("model/dt_phishing_model.pkl")
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    predictions = None
    if request.method == "POST":
        if "url" in request.form and request.form["url"]:
            url = request.form["url"]
            features = extract_features(url)
            pred = model.predict([features])[0]
            result = "🔴 Phishing" if pred else "🟢 Safe"
        elif "file" in request.files:
            file = request.files["file"]
            if file.filename.endswith(".csv"):
                df = pd.read_csv(file)
                df["features"] = df["url"].apply(extract_features)
                df["prediction"] = df["features"].apply(lambda x: model.predict([x])[0])
                df["result"] = df["prediction"].map({1: "🔴 Phishing", 0: "🟢 Safe"})
                predictions = df[["url", "result"]].to_html(classes="table table-striped")
    return render_template("index.html", result=result, predictions=predictions)
if __name__ == "__main__":
    app.run(debug=True)
