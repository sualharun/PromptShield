import pickle

with open('ml_classifier.pkl', 'rb') as f:
    model = pickle.load(f)

model['threshold'] = 0.60

with open('ml_classifier.pkl', 'wb') as f:
    pickle.dump(model, f)

print('Threshold updated to 0.60')
