import joblib

class MLModel:
    def __init__(self, model_path):
        """Initializes the model by loading it from the specified path."""
        self.model_path = model_path
        self.model = self.load_model(model_path)

    def load_model(self, model_path):
        """Loads the trained model from a file."""
        try:
            model = joblib.load(model_path)
            return model
        except Exception as e:
            raise ValueError(f"Error loading the model: {e}")

    def predict(self, data):
        """Makes predictions on the given data."""
        try:
            predictions = self.model.predict(data)
            return predictions
        except Exception as e:
            raise ValueError(f"Error making predictions: {e}")
