from security.analyzer.detectors.signature import SignatureDetector


class XssDetector(SignatureDetector):
    attack_type = "xss"
