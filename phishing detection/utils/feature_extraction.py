import re
import math
from urllib.parse import urlparse
from collections import Counter
import numpy as np

def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log2(count / lns) for count in p.values() if count)

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    full = url

    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify']
    keyword_hist = Counter(re.findall(r'\w+', url.lower()))

    features = [
        len(url),
        hostname.count('.'),
        int('@' in url),
        int(bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname))),
        url.count('-'),
        len(re.findall(r'\d', url)),
        int(parsed.scheme == 'https'),
        sum(keyword_hist.get(k, 0) for k in suspicious_keywords),
        url.count('?'),
        len(path),
        entropy(url)
    ]
    
    return np.array(features)
