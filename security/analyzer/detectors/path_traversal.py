from security.analyzer.detectors.signature import SignatureDetector


class PathTraversalDetector(SignatureDetector):
    attack_type = "path_traversal"
