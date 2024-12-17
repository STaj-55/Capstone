from flask import Flask, request, jsonify, render_template, redirect, url_for
import numpy as np
import pandas as pd
import joblib
from cleaning import clean_data

#Initialize Flask App
app = Flask(__name__)

#Load trained model using joblib
print("chat can u load the model?")
model = joblib.load('rf_model_binary.pkl')
print("chat model loaded. so chill.")

predictions = []

#Define route to confirm app is working
@app.route('/')
def home():
    return render_template('index.html', predictions=predictions)

#Define a simple prediction route
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # List all the feature names that the model was trained on
        feature_names = [
            'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Fwd Packets Length Total', 'Bwd Packets Length Total', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
            'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Min', 'Packet Length Max',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
            'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
            'Down/Up Ratio', 'Avg Packet Size', 'Avg Fwd Segment Size',
            'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
            'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init Fwd Win Bytes',
            'Init Bwd Win Bytes', 'Fwd Act Data Packets', 'Fwd Seg Size Min',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
            'Idle Std', 'Idle Max', 'Idle Min'
        ]
    
        data = request.get_json(force=True)

        df = pd.DataFrame([data], columns=feature_names)

        cleaned_data = clean_data(df)

        if cleaned_data.shape[1] != len(model.feature_names_in_):
            return jsonify({'error': 'Invalid number of features in input data. Check for all features.'}), 400

        input_data = cleaned_data.to_numpy()

        prediction = model.predict(input_data)[0]

        result = "Malicious" if prediction == 1 else "Benign"
        response = {
            'message': f"Prediction Result",
            'prediction': result
        }

        #Append the prediction to the shared list
        predictions.append({
            'data': data,
            'result': result
        })

        #Limit to the most recent 20 preidctions
        if len(predictions) > 20:
            predictions.pop(0)

        return jsonify(response)
    
    except KeyError as e:
        return jsonify({'error': f"Missing key in input data: {str(e)}"}), 400

    #return jsonify({"message": f"Received the following data: {data}"})
#Define route to serve predictions as JSON
@app.route('/predictions', methods=['GET'])
def get_predictions():
    return jsonify(predictions)
#Expose the app using ngrok
#port = 5001
#public_url = ngrok.connect(port)
#print(f"Your public URL is: {public_url}")

#Run app
if __name__ == '__main__':
    app.run(port=5001, host='0.0.0.0', debug=True, use_reloader=False)