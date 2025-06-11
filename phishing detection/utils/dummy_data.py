import csv
import random
benign_domains = ["example.com", "github.com", "wikipedia.org", "bbc.co.uk", "amazon.com", "google.com", "udemy.com"]
phishing_keywords = ["login", "secure", "verify", "update", "account", "password", "auth", "bank", "paypal"]
def generate_benign_urls(n):
    benign_urls = []
    for _ in range(n):
        domain = random.choice(benign_domains)
        path = random.choice(["/home", "/about", "/product", "/help", "/search?q=python", "/user/settings"])
        benign_urls.append((f"https://{domain}{path}", 0))
    return benign_urls
def generate_phishing_urls(n):
    phishing_urls = []
    for _ in range(n):
        subdomain = random.choice(["verify", "secure-login", "update-info", "auth", "account", "login", "signin"])
        domain = random.choice(["com", "ru", "net", "xyz", "online"])
        main_url = f"http://{subdomain}.{random.choice(phishing_keywords)}-{random.randint(100,999)}.{domain}"
        path = f"/{random.choice(phishing_keywords)}?id={random.randint(1000,9999)}"
        phishing_urls.append((main_url + path, 1))
    return phishing_urls
benign_data = generate_benign_urls(120)
phishing_data = generate_phishing_urls(120)
all_data = benign_data + phishing_data
random.shuffle(all_data)
csv_file = "phishing_dataset.csv"
with open(csv_file, mode='w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["url", "label"])
    writer.writerows(all_data)
print(f"Realistic phishing dataset saved to: {csv_file} (Total samples: {len(all_data)})")
