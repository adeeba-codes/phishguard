import urllib.request
import os

os.makedirs("data", exist_ok=True)

url = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv"
urllib.request.urlretrieve(url, "data/phishing.csv")

print("Downloaded phishing dataset")