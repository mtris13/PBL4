from security.analyzer.detectors.signature import SignatureDetector


class SqliDetector(SignatureDetector):
    attack_type = "sqli"
