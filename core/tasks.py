from .ml_model import predict_failure

class PredictFailureView(APIView):
    def post(self, request):
        data = request.data.get('network_data')
        prediction = predict_failure(data)
        return Response({"predicted_failure": prediction}, status=200)
