import requests
import os 
import base64
import re
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(dotenv_path)
api_key = os.getenv("VIRUSTOTAL_API_KEY")

if not api_key:
    raise ValueError("API key not found. Please check your .env file.")


base_url = "https://www.virustotal.com/api/v3/urls/"
headers = {
        "accept": "application/json",
        "x-apikey": api_key, 
    }

def get_url_report(url: str) -> dict:
    url_bytes = url.encode('utf-8') 
    base64_url = base64.urlsafe_b64encode(url_bytes).decode('utf-8')  
    base64_url_without_padding = base64_url.rstrip('=') 
    
    response = requests.get(url=base_url+base64_url_without_padding ,headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.status_code}")
        return None
    
get_url_report("https://www.google.com")

def url_valid(url: str) -> bool:
    patron_url = r'(https?://(?:www\.)?\S+|www\.\S+\.\S{2,}|(?:\S+\.\S{2,}))'
    
    data = get_url_report(url)
    
    if data is None:
        return False
    
    analysis_stats = data['data']['attributes']['last_analysis_stats']
    if analysis_stats['malicious'] > 0 or analysis_stats['suspicious'] > 0:
        return False
    
    return True

def message_valid(text: str) -> bool:
    patron_url = r'(https?://(?:www\.)?\S+|www\.\S+\.\S{2,}|(?:\S+\.\S{2,}))'
    
    for url in re.findall(patron_url, text):
        if not url_valid(url):
            print('Invalid URL:', url)
            return False
        print('Valid URL:', url)
    return True