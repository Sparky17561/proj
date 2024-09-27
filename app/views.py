# email_app/views.py
import random
from django.shortcuts import render, redirect
from .forms import EmailUploadForm
from django.views.decorators.csrf import csrf_exempt
from email.parser import BytesParser, Parser
from email.policy import default
from bs4 import BeautifulSoup
from django.http import JsonResponse
from pickle import load
import os
from .models import EmailFeedback
import re
import requests
from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime
import whois
import dns.resolver
from django.http import JsonResponse
import json 
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse
import time as time_module
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options


from django.shortcuts import render, redirect

def display_email(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        proof = request.POST.get('proof')

        # Check if fields are not empty
        if email and proof:
            try:
                feedback = EmailFeedback(email=email, proof=proof)
                feedback.save()
                # Return a JSON response for success
                return JsonResponse({"message": "Thanks for Reporting", "status": "success"})
            except Exception as e:
                # Return a JSON response for error
                return JsonResponse({"message": f"Error saving feedback: {str(e)}", "status": "error"})
        else:
            # Return a JSON response for validation error
            return JsonResponse({"message": "Please fill in both the email and proof fields.", "status": "error"})
    
    # Render form on GET request
    return render(request, 'display_email.html')



def success(request):
    return render(request, 'success.html')

@csrf_exempt
def extract_email_info_view(email_file):
    try:
        msg = BytesParser(policy=default).parse(email_file)
        subject = msg['subject']
        sender = msg['from']

        body = ""
        if msg.is_multipart():
            for part in msg.iter_parts():
                if part.get_content_type() == 'text/plain':
                    body += part.get_payload(decode=True).decode(part.get_content_charset(), errors='ignore')
                elif part.get_content_type() == 'text/html':
                    html = part.get_payload(decode=True).decode(part.get_content_charset(), errors='ignore')
                    soup = BeautifulSoup(html, 'html.parser')
                    body += soup.get_text()
        else:
            if msg.get_content_type() == 'text/plain':
                body = msg.get_payload(decode=True).decode(msg.get_content_charset(), errors='ignore')
            elif msg.get_content_type() == 'text/html':
                html = msg.get_payload(decode=True).decode(msg.get_content_charset(), errors='ignore')
                soup = BeautifulSoup(html, 'html.parser')
                body = soup.get_text()

        # Function to remove meaningless words
        body = remove_meaningless_words(body)

        links = []
        if msg.is_multipart():
            for part in msg.iter_parts():
                if part.get_content_type() == 'text/html':
                    html = part.get_payload(decode=True).decode(part.get_content_charset(), errors='ignore')
                    soup = BeautifulSoup(html, 'html.parser')
                    links.extend(a['href'] for a in soup.find_all('a', href=True))
        else:
            if msg.get_content_type() == 'text/html':
                soup = BeautifulSoup(body, 'html.parser')
                links.extend(a['href'] for a in soup.find_all('a', href=True))

        attachments = []
        if msg.is_multipart():
            for part in msg.iter_parts():
                if part.get_content_disposition() and 'attachment' in part.get_content_disposition():
                    filename = part.get_filename()
                    attachments.append(filename)

        return {
            'subject': subject,
            'body': body,
            'links': links,
            'attachments': attachments
        }

    except Exception as e:
        return {'error': str(e)}

def remove_meaningless_words(text):
    # Placeholder for a real implementation
    return text

@csrf_exempt
def mail_predict(body):
    try:
        # Define the path to the model files
        model_files = {
            "vector": "app/predmodels/vector.pkl",
            "nb": "app/predmodels/nb.pkl",
            "lg": "app/predmodels/lg.pkl",
            "sgd": "app/predmodels/sgd.pkl",
            "xgb": "app/predmodels/xgb.pkl",
            "mlp": "app/predmodels/mlp.pkl"
        }

        models = {}

        # Load each model file
        for name, path in model_files.items():
            if not os.path.exists(path):
                return {'error': f"File not found: {path}"}
            with open(path, "rb") as f:
                models[name] = load(f)

        tf, nb, lg, sgd, xgb, mlp = models["vector"], models["nb"], models["lg"], models["sgd"], models["xgb"], models["mlp"]

        # Get input text from the request body
        text = body

        # Check if text is provided
        if not text:
            return {'error': 'No text provided'}

        # Use the original vectorizer to transform the new text
        text_vectorized = tf.transform([text])

        # Predict using models
        results = [
            ("NB", nb.predict(text_vectorized)),
            ("Logistic", lg.predict(text_vectorized)),
            ("SGD", sgd.predict(text_vectorized)),
            ("XG", xgb.predict(text_vectorized)),
            ("MLP", mlp.predict(text_vectorized)),
        ]

        # Determine majority vote (0 = phishing, 1 = safe)
        predictions = [result[1][0] for result in results]
        malicious_count = predictions.count(0)
        total_predictions = len(predictions)
        maliciousness_percentage = (malicious_count / total_predictions) * 100

        # Return the prediction result and maliciousness percentage as JSON
        return {
            "result": results,
            'msg': "Safe" if sum(predictions) > len(predictions) / 2 else "Not Safe",
            'maliciousness_percentage': maliciousness_percentage
        }
    except Exception as e:
        return {'error': str(e)}
                        
def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        registrar = domain_info.registrar
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return creation_date, registrar
    except Exception as e:
        return None, None

def get_dns_records(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        ips = [ip.address for ip in result]
        return ips
    except Exception as e:
        return []

def get_ip_info(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    return response.json()

def get_dns_records(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        ips = [ip.address for ip in result]
        return ips
    except Exception as e:
        print(f"DNS lookup failed: {e}")
        return []

def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json()
    except Exception as e:
        print(f"IP info lookup failed: {e}")
        return {}

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        registrar = domain_info.registrar
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return creation_date, registrar
    except Exception as e:
        print(f"WHOIS lookup failed: {e}")
        return None, None

def check_https(url):
    return url.startswith("https://")

def check_ipv6(domain):
    try:
        result = dns.resolver.resolve(domain, 'AAAA')
        return len(result) > 0
    except Exception as e:
        print(f"IPv6 check failed: {e}")
        return False

def get_page_statistics(url):
    try:
        response = requests.get(url)
        domain = urlparse(url).netloc
        subdomains = domain.split('.')[:-2]
        transfer_size_kb = len(response.content) / 1024
        cookies = response.cookies
        
        return {
            'requests': 1,  # Simplified to 1 request, in reality you would need to monitor network requests.
            'https': check_https(url),
            'ipv6': check_ipv6(domain),
            'domains': 1,
            'subdomains': len(subdomains),
            'ips': len(get_dns_records(domain)),
            'countries': len(set(get_ip_info(ip)['country'] for ip in get_dns_records(domain) if get_ip_info(ip).get('country'))),
            'transfer_kb': transfer_size_kb,
            'size_kb': transfer_size_kb,  # In a real-world case, 'size_kb' could differ based on compression, etc.
            'cookies': len(cookies)
        }
    except Exception as e:
        print(f"Page statistics gathering failed: {e}")
        return {}

def calculate_domain_age(creation_date):
    try:
        current_date = datetime.now()
        age_in_days = (current_date - creation_date).days
        return age_in_days
    except Exception as e:
        print(f"Domain age calculation failed: {e}")
    return None

def generate_report(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    ip_addresses = get_dns_records(domain)
    dns_records_exist = len(ip_addresses) > 0

    report = {
        'dns_records': 'YES' if dns_records_exist else 'NO',
        'ip_count': len(ip_addresses),
        'domain': domain,
        'ips': []
    }
    
    if ip_addresses:
        main_ip = ip_addresses[0]
        ip_info = get_ip_info(main_ip)
        location = ip_info.get("city", "") + ", " + ip_info.get("country", "")
        org = ip_info.get("org", "")
        
        report['ips'] = [{'ip': main_ip, 'location': location, 'organization': org}]
    else:
        report['message'] = "No IP addresses could be resolved."
    
    # WHOIS data
    creation_date, registrar = get_whois_info(domain)
    if creation_date:
        creation_date_str = creation_date.strftime('%B %d, %Y, %H:%M:%S (UTC)')
        domain_age_days = calculate_domain_age(creation_date)
        report['whois'] = {
            'creation_date': creation_date_str,
            'registrar': registrar,
            'domain_age_days': domain_age_days
        }
    else:
        report['message'] = "WHOIS lookup failed. Domain creation date and registrar information not available."
    
    # TLS certificate details
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issued_by = dict(x[0] for x in cert['issuer'])['organizationName']
                issued_on = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                valid_for = (datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z") - issued_on).days / 30
                
                report['tls_certificate'] = {
                    'issued_by': issued_by,
                    'issued_on': issued_on.strftime('%B %d, %Y'),
                    'valid_for_months': int(valid_for)
                }
    except Exception as e:
        report['message'] = f"TLS certificate details could not be retrieved: {e}"

    # Page statistics
    page_stats = get_page_statistics(url)
    report['page_statistics'] = page_stats

    # urlscan.io API integration (optional, if needed)
    try:
        urlscan_info = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}").json()
        scan_count = len(urlscan_info.get('results', []))
        report['urlscan_count'] = scan_count
    except Exception as e:
        report['message'] = f"urlscan.io lookup failed: {e}"
    
    return report

@csrf_exempt  # This is needed only if you are not using CSRF tokens in your requests
def url_report_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data.get('url', '')

            if not url:
                return JsonResponse({'error': 'URL is required'}, status=400)

            report = generate_report(url)
            return JsonResponse(report, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def upload_email(request):
    if request.method == 'POST':
        form = EmailUploadForm(request.POST, request.FILES)
        if form.is_valid():
            email_file = request.FILES['email_file']
            email_content = extract_email_info_view(email_file)
            email_body = email_content['body']
            email_links = email_content['links']  # Extracted email links
            email_prediction = mail_predict(email_body)
            non_malicious_percentage = 100 - email_prediction['maliciousness_percentage']

            # Initialize lists for storing reports and link results
            page_statistics_reports = []
            detailed_reports = []
            percentage_list = []  # List to store percentages of maliciousness for each URL
            # screenshot_paths = []  # List to store screenshot paths

            # Analyze each URL from email_links using the new analyse_url function
            for url in email_links:
                predictions, percentage_maliciousness = analyse_url(url)
                percentage_list.append(percentage_maliciousness)

                # Generate additional reports
                report1 = get_page_statistics(str(url))
                report2 = generate_report(str(url))

                # Capture screenshot for each URL
                # screenshot_path = capture_screenshot(url)
                # screenshot_paths.append(screenshot_path)

                # Append each report to the corresponding list
                page_statistics_reports.append(report1)
                detailed_reports.append(report2)

            # Calculate average maliciousness percentage
            average_maliciousness = round(sum(percentage_list) / len(percentage_list), 1) if percentage_list else 0

            # Prepare context with all gathered information
            context = {
                **email_content,
                **email_prediction,
                'non_malicious_percentage': non_malicious_percentage,
                'email_links': email_links,
                'average_maliciousness': average_maliciousness,
                'page_statistics_reports': page_statistics_reports,
                'detailed_reports': detailed_reports,
                # 'screenshot_paths': screenshot_paths,  # Include screenshot paths in context
            }

            return render(request, 'display_email.html', context)
    else:
        form = EmailUploadForm()
        return render(request, 'upload_email.html', {'form': form})
# email_app/views.py

import pickle
import pandas as pd
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json

# Feature extraction functions for URL analysis
def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_underline(url):
    return url.count('_')

def count_slash(url):
    return url.count('/')

def count_questionmark(url):
    return url.count('?')

def count_equal(url):
    return url.count('=')

def count_at(url):
    return url.count('@')

def count_and(url):
    return url.count('&')

def count_exclamation(url):
    return url.count('!')

def count_space(url):
    return url.count(' ')

def count_tilde(url):
    return url.count('~')

def count_comma(url):
    return url.count(',')

def count_plus(url):
    return url.count('+')

def count_asterisk(url):
    return url.count('*')

def count_hash(url):
    return url.count('#')

def count_dollar(url):
    return url.count('$')

def count_percent(url):
    return url.count('%')

def count_redirection(url):
    return url.count('://')

def get_features(url):
    features = {
        'url_length': len(url),
        'n_dots': count_dots(url),
        'n_hypens': count_hyphens(url),
        'n_underline': count_underline(url),
        'n_slash': count_slash(url),
        'n_questionmark': count_questionmark(url),
        'n_equal': count_equal(url),
        'n_at': count_at(url),
        'n_and': count_and(url),
        'n_exclamation': count_exclamation(url),
        'n_space': count_space(url),
        'n_tilde': count_tilde(url),
        'n_comma': count_comma(url),
        'n_plus': count_plus(url),
        'n_asterisk': count_asterisk(url),
        'n_hastag': count_hash(url),
        'n_dollar': count_dollar(url),
        'n_percent': count_percent(url),
        'n_redirection': count_redirection(url),
    }
    return features

def load_models(model_files):
    models = {}
    for model_name, file_path in model_files.items():
        with open(file_path, 'rb') as f:
            models[model_name] = pickle.load(f)
    return models

model_files = {
    "model1": "app/predmodels/logisticregression.pkl",
    "model2": "app/predmodels/randomforestclassifier.pkl",
    "model3": "app/predmodels/kneighborsclassifier.pkl",
    "model4": "app/predmodels/gradientboostingclassifier.pkl",
    "model5": "app/predmodels/gaussiannb.pkl",
    "model6": "app/predmodels/adaboostclassifier.pkl",
    "model7": "app/predmodels/mlpclassifier.pkl"
}

models = load_models(model_files)

def calculate_percentage_maliciousness(predictions):
    # Count number of models that predict phishing
    count_phishing = sum(1 for prediction in predictions.values() if prediction == 1)
    # Calculate percentage
    total_models = len(predictions)
    if total_models == 0:
        return 0
    percentage = (count_phishing / total_models) * 100
    return percentage

def analyse_url(url):
    features = get_features(url)
    features_df = pd.DataFrame([features])

    predictions = {}
    for model_name, model in models.items():
        prediction = model.predict(features_df)[0]
        predictions[model_name] = int(prediction)  # Convert to regular int

    percentage_maliciousness = calculate_percentage_maliciousness(predictions)
    return predictions, percentage_maliciousness


@csrf_exempt
@require_http_methods(["POST"])
def predict_view(request):
    try:
        data = json.loads(request.body)
        url = data.get('url')
        if not url:
            return JsonResponse({'error': 'URL parameter is missing'}, status=400)
        
        predictions, percentage_maliciousness = analyse_url(url)
        
        return JsonResponse({
            'predictions': predictions,
            'percentage_maliciousness': percentage_maliciousness
        })
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



# # Path to your chromedriver executable
# CHROMEDRIVER_PATH = 'C:/Users/saipr/Downloads/chromedriver-win64/chromedriver-win64/chromedriver.exe'

# # List of User-Agents to rotate
# USER_AGENTS = [
#     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
#     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
#     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
#     "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
# ]

# def setup_driver():
#     chrome_options = Options()
#     chrome_options.add_argument("--headless")  # Run in headless mode
#     chrome_options.add_argument(f"user-agent={random.choice(USER_AGENTS)}")  # Rotate User-Agent
#     chrome_service = Service(CHROMEDRIVER_PATH)
#     driver = webdriver.Chrome(service=chrome_service, options=chrome_options)
#     return driver

# def capture_screenshot(url):
#     driver = setup_driver()
#     driver.get(url)

#     # Introduce a random delay
#     time_module.sleep(random.uniform(2, 5))

#     # Create directory if it does not exist
#     output_dir = 'scraped_data/test'
#     if not os.path.exists(output_dir):
#         os.makedirs(output_dir)

#     # Save screenshot in 'test' folder
#     screenshot_path = os.path.join(output_dir, f'page_screenshot_{int(time_module.time())}.png')
#     driver.save_screenshot(screenshot_path)

#     driver.quit()

#     return screenshot_path


def index(request):
    return render(request, 'index.html')

def blog(request):
    return render(request, 'blog.html')

def blog_details(request):
    return render(request, 'blog-details.html')

def portfolio_details(request):
    return render(request, 'portfolio-details.html')

def service_details(request):
    return render(request, 'service-details.html')

def starter_page(request):
    return render(request, 'starter-page.html')




from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
import pickle
import re
import joblib
import numpy as np
import nltk
from nltk.corpus import stopwords
from youtube_comment_downloader import YoutubeCommentDownloader
from sklearn.feature_extraction.text import CountVectorizer

# Load your models
with open('app/predmodels/naive_bayes_classifier.pkl', 'rb') as model_file:
    classifier = pickle.load(model_file)

with open('app/predmodels/count_vectorizer.pkl', 'rb') as vectorizer_file:
    vectorizer = pickle.load(vectorizer_file)  # Corrected


svc_model = joblib.load('app/predmodels/best_svc_model.pkl')
rf_model = joblib.load('app/predmodels/random_forest_model.pkl')
ls_model = joblib.load('app/predmodels/linear_svc_model.pkl')

nltk.download('stopwords')
stop_words = set(stopwords.words('english'))

def clean_text(text):
    text = text.lower()
    text = re.sub(r"http\S+|www\S+|https\S+", '', text, flags=re.MULTILINE)
    text = re.sub(r'\@\w+|\#', '', text)
    text = re.sub(r'[^\x00-\x7F]+', '', text)
    text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    words = text.split()
    words = [word for word in words if word.isalpha() and word not in stop_words and len(word) > 2]
    return ' '.join(words)

def get_youtube_comments(video_url, limit=50, sort_by='top'):
    if sort_by == 'top':
        sort_by_value = 0
    elif sort_by == 'newest':
        sort_by_value = 1
    else:
        raise ValueError("Invalid sort_by value. Use 'top' or 'newest'.")

    video_id_match = re.search(r"(?:v=|\/)([0-9A-Za-z_-]{11}).*", video_url)
    if video_id_match:
        video_id = video_id_match.group(1)
    else:
        return [], None

    downloader = YoutubeCommentDownloader()
    comments = []
    try:
        for comment in downloader.get_comments(video_id, sort_by=sort_by_value):
            comments.append(comment['text'])
            if len(comments) >= limit:
                break
    except Exception as e:
        return [], str(e)

    return comments, None

def predict_sentiments(comments):
    X_comments = vectorizer.transform(comments).toarray()
    predictions = classifier.predict(X_comments)
    return predictions

def predict_spam(text):
    formatted_text = [text]
    svc_pred = svc_model.predict(formatted_text)
    rf_pred = rf_model.predict(formatted_text)
    ls_pred = ls_model.predict(formatted_text)

    predictions = np.array([svc_pred[0], rf_pred[0], ls_pred[0]])
    average_prediction = np.mean(predictions)

    return average_prediction

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import json
import pickle
import re
import joblib
import numpy as np
import nltk
from nltk.corpus import stopwords
from youtube_comment_downloader import YoutubeCommentDownloader
import traceback  # Import traceback for debugging

# Load your models
with open('app/predmodels/naive_bayes_classifier.pkl', 'rb') as model_file:
    classifier = pickle.load(model_file)

with open('app/predmodels/count_vectorizer.pkl', 'rb') as vectorizer_file:
    vectorizer = pickle.load(vectorizer_file)

svc_model = joblib.load('app/predmodels/best_svc_model.pkl')
rf_model = joblib.load('app/predmodels/random_forest_model.pkl')
ls_model = joblib.load('app/predmodels/linear_svc_model.pkl')

nltk.download('stopwords')
stop_words = set(stopwords.words('english'))

def clean_text(text):
    text = text.lower()
    text = re.sub(r"http\S+|www\S+|https\S+", '', text, flags=re.MULTILINE)
    text = re.sub(r'\@\w+|\#', '', text)
    text = re.sub(r'[^\x00-\x7F]+', '', text)
    text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    words = text.split()
    words = [word for word in words if word.isalpha() and word not in stop_words and len(word) > 2]
    return ' '.join(words)

def get_youtube_comments(video_url, limit=50, sort_by='top'):
    if sort_by == 'top':
        sort_by_value = 0
    elif sort_by == 'newest':
        sort_by_value = 1
    else:
        raise ValueError("Invalid sort_by value. Use 'top' or 'newest'.")

    # Updated regex to match various YouTube URL formats
    video_id_match = re.search(r"(?:v=|\/|youtu\.be\/)([0-9A-Za-z_-]{11})", video_url)
    if video_id_match:
        video_id = video_id_match.group(1)
    else:
        return [], "Invalid YouTube URL or unable to extract video ID"

    downloader = YoutubeCommentDownloader()
    comments = []
    try:
        for comment in downloader.get_comments(video_id, sort_by=sort_by_value):
            comments.append(comment['text'])
            if len(comments) >= limit:
                break
    except Exception as e:
        return [], str(e)

    return comments, None

def predict_sentiments(comments):
    X_comments = vectorizer.transform(comments).toarray()
    predictions = classifier.predict(X_comments)
    return predictions

def predict_spam(text):
    formatted_text = [text]
    svc_pred = svc_model.predict(formatted_text)
    rf_pred = rf_model.predict(formatted_text)
    ls_pred = ls_model.predict(formatted_text)

    predictions = np.array([svc_pred[0], rf_pred[0], ls_pred[0]])
    average_prediction = np.mean(predictions)

    return average_prediction

import json
import re
import traceback
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.shortcuts import render

# Assuming these functions are defined elsewhere in your code
# from your_app.utils import get_youtube_comments, predict_sentiments, predict_spam, analyze_url_view









def yt_page(request):
    return render(request, 'ytanalysis.html')







import json
import re
import pandas as pd
import pickle
import traceback
from django.http import JsonResponse

def load_models(model_files):
    models = {}
    for model_name, file_path in model_files.items():
        try:
            with open(file_path, 'rb') as f:
                models[model_name] = pickle.load(f)
        except Exception as e:
            print(f"Error loading {model_name} from {file_path}: {str(e)}")
    return models

# Define your model file paths
model_files = {
    "model1": "app/predmodels/logisticregression.pkl",
    "model2": "app/predmodels/randomforestclassifier.pkl",
    "model3": "app/predmodels/kneighborsclassifier.pkl",
    "model4": "app/predmodels/gradientboostingclassifier.pkl",
    "model5": "app/predmodels/gaussiannb.pkl",
    "model6": "app/predmodels/adaboostclassifier.pkl",
    "model7": "app/predmodels/mlpclassifier.pkl"
}

# Load models
models = load_models(model_files)

def calculate_average_maliciousness(predictions):
    """ Calculate the average percentage of maliciousness from model predictions. """
    if not predictions:
        return 0
    # Assuming predictions are in binary format where 1 indicates malicious
    average = sum(predictions.values()) / len(predictions)
    return average * 100  # Convert to percentage

def analyze_url(url):
    """ Analyze a URL and return predictions and average maliciousness. """
    try:
        # Get features from the URL
        features = get_features(url)
        features_df = pd.DataFrame([features])

        # Predictions from each model
        predictions = {}
        for model_name, model in models.items():
            prediction = model.predict(features_df)[0]
            predictions[model_name] = int(prediction)  # Store as integer

        # Calculate average maliciousness
        average_maliciousness = calculate_average_maliciousness(predictions)

        # Return results
        return {
            'predictions': predictions,
            'average_maliciousness': average_maliciousness
        }
    
    except Exception as e:
        return {'error': str(e)}

def analyze_comments(request):
    try:
        # Get YouTube video URL from request data
        data = json.loads(request.body)
        video_url = data.get('video_url')
        if not video_url:
            return JsonResponse({"error": "No video URL provided"}, status=400)

        sort_by = data.get('sort_by', 'top')
        limit = int(data.get('limit', 50))

        # Fetch comments
        comments, error = get_youtube_comments(video_url, limit=limit, sort_by=sort_by)
        if error:
            return JsonResponse({"error": error}, status=400)

        if not comments:
            return JsonResponse({"error": "No comments found"}, status=404)

        # Predict sentiments and spam
        predictions = predict_sentiments(comments)

        spam_comments = []
        found_urls = []
        malicious_urls = []
        url_pattern = r'https?://[^\s]+|www\.[^\s]+'  # Regex pattern to find URLs

        # Classify comments
        for comment, prediction in zip(comments, predictions):
            sentiment_label = "Good" if prediction == 2 else "Neutral" if prediction == 1 else "Bad"
            spam_score = predict_spam(comment)
            spam_label = 'Spam' if spam_score >= 0.5 else 'Not Spam'

            # If the comment is classified as spam, add it to the list
            if spam_label == 'Spam':
                spam_comments.append({
                    "comment": comment,
                    "sentiment": sentiment_label,
                    "spam": spam_label
                })

            # Find URLs in the comment and analyze each
            urls_in_comment = re.findall(url_pattern, comment)
            for url in urls_in_comment:
                found_urls.append(url)

                # Analyze the URL using the analyze_url function
                url_response = analyze_url(url)
                
                if isinstance(url_response, dict) and 'average_maliciousness' in url_response:
                    percentage_maliciousness = url_response.get('average_maliciousness', 0)
                    
                    # Check if maliciousness is above the threshold
                    if percentage_maliciousness > 50:  
                        malicious_urls.append(url)

        # Calculate spam and sentiment ratios
        total_comments = len(comments)
        spam_ratio = {
            "spam": len(spam_comments),
            "not_spam": total_comments - len(spam_comments)
        }
        sentiment_ratio = {
            "good": sum(1 for p in predictions if p == 2),
            "neutral": sum(1 for p in predictions if p == 1),
            "bad": sum(1 for p in predictions if p == 0)
        }

        # Return the spam comments, malicious URLs, and ratios as JSON
        return JsonResponse({
            "spam_comments": spam_comments,
            "malicious_urls": malicious_urls,
            "found_urls": found_urls,
            "spam_ratio": spam_ratio,
            "sentiment_ratio": sentiment_ratio
        }, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        error_message = str(e)
        traceback.print_exc()
        return JsonResponse({"error": error_message}, status=500)

