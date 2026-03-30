from app.feature_extraction import FeatureExtraction
from app.model_loader import load_model


# load once when server starts
extractor = FeatureExtraction()
model = load_model()


FEATURE_ORDER = [
'having_IP_Address',
'URL_Length',
'Shortining_Service',
'having_At_Symbol',
'double_slash_redirecting',
'Prefix_Suffix',
'having_Sub_Domain',
'SSLfinal_State',
'Domain_registeration_length',
'port',
'HTTPS_token',
'Request_URL',
'URL_of_Anchor',
'Links_in_tags',
'SFH',
'Submitting_to_email',
'Abnormal_URL',
'Redirect',
'on_mouseover',
'RightClick',
'popUpWidnow',
'Iframe',
'age_of_domain',
'DNSRecord',
'web_traffic',
'Google_Index',
'Statistical_report'
]


def predict_url(url):

    # extract features
    feature_dict = extractor.extract_all_features(url)

    threat_source = feature_dict.get("Threat_Source")

    # remove UI-only field
    feature_dict.pop("Threat_Source", None)

    # convert dict → ordered vector
    feature_vector = [feature_dict.get(col, 0) for col in FEATURE_ORDER]

    # ML prediction
    prediction = model.predict([feature_vector])[0]

    probabilities = model.predict_proba([feature_vector])[0]
    class_index = list(model.classes_).index(prediction)
    probability = probabilities[class_index]

    return prediction, probability, feature_dict, threat_source