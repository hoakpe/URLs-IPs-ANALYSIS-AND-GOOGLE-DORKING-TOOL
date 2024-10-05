import whois
import socket
import requests
import ssl
import OpenSSL
import os
from tkinter import filedialog, messagebox, END, simpledialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from tabulate import tabulate
from bs4 import BeautifulSoup
import subprocess
import webbrowser
import threading
from queue import Queue
from fpdf import FPDF
import joblib
import pandas as pd

VIRUSTOTAL_API_KEY = "YOUR TOKEN"
IPINFO_ACCESS_TOKEN = "YOUR TOKEN"
ALIENVAULT_OTX_API_KEY = "YOUR TOKEN"
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 443]

dns_queries = []

# Load the trained model
model = joblib.load('url_malicious_model.joblib')

def read_api_key():
    with open("API_KEY", "r") as file:
        return file.read().strip()

def read_search_engine_id():
    with open("SEARCH_ENGINE_ID", "r") as file:
        return file.read().strip()

API_KEY = read_api_key()
SEARCH_ENGINE_ID = read_search_engine_id()

def perform_web_scraping(input_str, progress_queue):
    try:
        if is_valid_ip(input_str):
            reverse_dns_results = reverse_dns_lookup([input_str], progress_queue)
            if reverse_dns_results:
                url = list(reverse_dns_results[0].values())[0]
            else:
                progress_queue.put(1)
                return {input_str: "Reverse DNS lookup failed"}
        else:
            url = input_str

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            title = soup.title.string.strip() if soup.title else "No Title"
            meta_tags = {tag.get('name'): tag.get('content') for tag in soup.find_all('meta') if tag.get('name')}
            headers = response.headers
            links = [link.get('href') for link in soup.find_all('a') if link.get('href')]

            table_data = [
                ["Title", title],
                ["Meta Tags", ", ".join([f"{k}: {v}" for k, v in meta_tags.items()])],
                ["Headers", ", ".join([f"{k}: {v}" for k, v in headers.items()])],
                ["Links", "\n".join([link for link in links])]
            ]

            summary = "\n".join([f"{row[0]}: {row[1]}" for row in table_data])
            progress_queue.put(1)
            return {url: summary}
        else:
            progress_queue.put(1)
            return {url: f"Failed to fetch webpage. Status code: {response.status_code}"}
    except Exception as e:
        progress_queue.put(1)
        return {input_str: str(e)}

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def bulk_whois_lookup(urls, progress_queue):
    results = []
    for url in urls:
        try:
            domain_info = whois.whois(url)
            results.append({url: domain_info})
        except whois.parser.PywhoisError as e:
            results.append({url: str(e)})
        progress_queue.put(1)
    return results

def url_to_ip(urls, progress_queue):
    results = []
    for url in urls:
        try:
            ip_address = socket.gethostbyname(url)
            dns_queries.append({'url': url, 'ip_address': ip_address})
            results.append({url: ip_address})
        except socket.gaierror as e:
            results.append({url: str(e)})
        progress_queue.put(1)
    return results

def ip_geolocation(ip_addresses, progress_queue):
    results = []
    for ip in ip_addresses:
        try:
            if not is_valid_ip(ip):
                ip = socket.gethostbyname(ip)
            response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_ACCESS_TOKEN}")
            data = response.json()
            results.append({ip: data})
        except Exception as e:
            results.append({ip: str(e)})
        progress_queue.put(1)
    return results

def reverse_dns_lookup(ip_addresses, progress_queue):
    results = []
    for ip in ip_addresses:
        try:
            domain_name = socket.gethostbyaddr(ip)[0]
            results.append({ip: domain_name})
        except socket.herror as e:
            results.append({ip: f"[Errno {e.errno}] {e.strerror}"})
        progress_queue.put(1)
    return results

def ssl_certificate_analysis(urls, progress_queue):
    results = []
    for url in urls:
        try:
            cert = ssl.get_server_certificate((url, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            subject = x509.get_subject().get_components()
            issuer = x509.get_issuer().get_components()
            not_before = datetime.strptime(x509.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
            not_after = datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
            expiration_date = not_after.strftime('%Y-%m-%d %H:%M:%S')
            issue_date = not_before.strftime('%Y-%m-%d %H:%M:%S')
            results.append({
                url: {
                    "Issuer": dict(issuer),
                    "Subject": dict(subject),
                    "Issue Date": issue_date,
                    "Expiration Date": expiration_date
                }
            })
        except Exception as e:
            results.append({url: str(e)})
        progress_queue.put(1)
    return results

def port_scan(ip, ports, progress_queue):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception as e:
            print(f"Error scanning port {port} on {ip}: {e}")
        progress_queue.put(1)
    return open_ports

def nmap_scan(ip, progress_queue):
    try:
        result = subprocess.run(['nmap', '-p-', ip], capture_output=True, text=True)
        open_ports = []
        for line in result.stdout.splitlines():
            if '/tcp' in line and 'open' in line:
                port = int(line.split('/')[0])
                open_ports.append(port)
        progress_queue.put(1)
        return open_ports
    except Exception as e:
        progress_queue.put(1)
        return str(e)

def subdomain_discovery(domain, progress_queue):
    try:
        result = subprocess.run(['sublist3r', '-d', domain], capture_output=True, text=True)
        subdomains = result.stdout.splitlines()
        progress_queue.put(1)
        return subdomains
    except Exception as e:
        progress_queue.put(1)
        return str(e)

def angry_ip_scan(ip_addresses, progress_queue):
    results = {}
    for ip in ip_addresses:
        try:
            output = subprocess.check_output(
                ['C:\\Program Files\\Angry IP Scanner\\ipscan.exe', '-s', '-q', '-f:range', ip, ip, '-o', 'output.csv'])
            open_ports = [int(port.split(':')[1]) for port in output.decode().splitlines()]
            results[ip] = open_ports
        except Exception as e:
            print(f"Error scanning ports for {ip} using Angry IP Scanner: {e}")
            results[ip] = str(e)
        progress_queue.put(1)
    return results

def perform_port_scan(ip_addresses, ports, progress_queue):
    results = {}
    with ThreadPoolExecutor() as executor:
        nmap_futures = {executor.submit(nmap_scan, ip, progress_queue): ip for ip in ip_addresses}
        port_scan_futures = {executor.submit(port_scan, ip, ports, progress_queue): ip for ip in ip_addresses}
        for future in nmap_futures:
            ip = nmap_futures[future]
            try:
                open_ports = future.result()
                results[ip] = open_ports
            except Exception as e:
                print(f"Error scanning ports for {ip} using nmap: {e}")
                results[ip] = str(e)
        for future in port_scan_futures:
            ip = port_scan_futures[future]
            try:
                open_ports = future.result()
                results[ip] = open_ports
            except Exception as e:
                print(f"Error scanning ports for {ip}: {e}")
                results[ip] = str(e)
    return results

def check_url(url, api_key, progress_queue):
    params = {'apikey': api_key, 'resource': url}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
    progress_queue.put(1)
    return response.json()

def threat_intel_lookup(input_str, api_key, progress_queue):
    try:
        if not is_valid_ip(input_str):
            input_str = socket.gethostbyname(input_str)
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{input_str}/general"
        headers = {'X-OTX-API-KEY': api_key}
        response = requests.get(url, headers=headers)
        progress_queue.put(1)
        return response.json()
    except Exception as e:
        progress_queue.put(1)
        return {input_str: str(e)}

def google_search(query, api_key, cx):
    url = f"https://www.googleapis.com/customsearch/v1?q={query}&key={api_key}&cx={cx}"
    response = requests.get(url)
    data = response.json()
    return data

def perform_google_dorking(query, choices):
    operators_dict = {
        "1": "filetype:",
        "2": "site:",
        "3": "intitle:",
        "4": "inurl:",
    }
    query_parts = []
    for choice in choices:
        if choice in operators_dict:
            user_input = simpledialog.askstring("Input", f"Enter the {operators_dict[choice]} for Recon:")
            query_parts.append(f"{operators_dict[choice]}{user_input}")
    search_query = ' '.join(query_parts) + ' ' + query
    results = google_search(search_query, API_KEY, SEARCH_ENGINE_ID)
    return results

def read_input_from_file():
    file_path = filedialog.askopenfilename(title="Select file",
                                           filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
    inputs = []
    if file_path:
        try:
            with open(file_path, 'r') as file:
                inputs.extend(file.read().splitlines())
        except FileNotFoundError:
            messagebox.showerror("Error", f"File '{file_path}' not found.")
    return inputs

def generate_report(results):
    pdf = FPDF()
    pdf.add_page()

    # Add logo
    logo_path = 'logo.png'  # path to your logo image
    if os.path.exists(logo_path):
        pdf.image(logo_path, 10, 8, 33)

    pdf.set_font('Arial', 'B', 16)
    pdf.cell(200, 10, txt="Cybersecurity Analysis Report", ln=True, align='C')
    pdf.ln(10)

    for feature, feature_results in results.items():
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(200, 10, txt=feature, ln=True)
        pdf.ln(5)

        for input_str, output in feature_results.items():
            pdf.set_font('Arial', 'B', 10)
            pdf.cell(200, 10, txt=f"Input: {input_str}", ln=True)
            pdf.ln(5)
            pdf.set_font('Arial', '', 10)

            if feature == "Port Scanning":
                for port, url in output.items():
                    pdf.cell(200, 10, txt=f"Port {port}: {url}", ln=True)
            elif feature == "Subdomain Discovery":
                pdf.cell(200, 10, txt="Subdomains:", ln=True)
                pdf.ln(5)
                for subdomain in output['subdomains']:
                    pdf.cell(200, 10, txt=subdomain, ln=True)
            else:
                pdf.multi_cell(0, 10, txt=str(output).encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(5)

    # Save PDF
    report_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")])
    if report_path:
        pdf.output(report_path)
        messagebox.showinfo("Report Generated", f"Report has been generated and saved to: {report_path}")
    else:
        messagebox.showwarning("Save Cancelled", "Report generation cancelled.")

def preprocess_url_or_ip(input_str):
    # Placeholder preprocessing: update with actual feature extraction
    features = {
        'token_count': 10,
        'rank_host': 100,
        'rank_country': 50,
        'ASNno': 12345,
        'sec_sen_word_cnt': 5,
        'avg_token_length': 3.5,
        'No_of_dots': 2,
        'Length_of_url': 100,
        'avg_path_token': 4,
        'IPaddress_presence': 1,
        'Length_of_host': 15,
        'safebrowsing': 1,
        'avg_domain_token_length': 4,
        'path_token_count': 6,
        'largest_domain': 10,
        'domain_token_count': 3,
        'largest_path': 8,
        'largest_token': 5
    }
    return list(features.values())

def predict_malicious(url_features):
    df = pd.DataFrame([url_features], columns=[
        'token_count', 'rank_host', 'rank_country', 'ASNno', 'sec_sen_word_cnt',
        'avg_token_length', 'No_of_dots', 'Length_of_url', 'avg_path_token',
        'IPaddress_presence', 'Length_of_host', 'safebrowsing',
        'avg_domain_token_length', 'path_token_count', 'largest_domain',
        'domain_token_count', 'largest_path', 'largest_token'
    ])
    prediction = model.predict(df)
    return prediction[0]

def create_gui():
    root = ttk.Window(title="URL/IP Analysis and Google Dorking Tool", themename="cyborg")
    root.geometry("800x600")

    def switch_to_analysis():
        tab_control.select(analysis_tab)

    def switch_to_dorking():
        tab_control.select(dorking_tab)

    tab_control = ttk.Notebook(root)

    home_tab = ttk.Frame(tab_control)
    analysis_tab = ttk.Frame(tab_control)
    dorking_tab = ttk.Frame(tab_control)
    output_tab = ttk.Frame(tab_control)

    tab_control.add(home_tab, text="Home")
    tab_control.add(analysis_tab, text="URL/IP Analysis")
    tab_control.add(dorking_tab, text="Google Dorking")

    tab_control.pack(expand=1, fill="both")

    # Home tab widgets
    ttk.Label(home_tab, text="Select an option to proceed:", font=("Arial", 16)).pack(pady=20)
    ttk.Button(home_tab, text="URL/IP Analysis", command=switch_to_analysis).pack(pady=10)
    ttk.Button(home_tab, text="Google Dorking", command=switch_to_dorking).pack(pady=10)

    # Analysis tab widgets
    analysis_label = ttk.Label(analysis_tab, text="Enter URLs or IPs (comma-separated):")
    analysis_label.grid(row=0, column=0, columnspan=2, pady=10, padx=10, sticky="w")
    analysis_entry = ttk.Entry(analysis_tab, width=80)
    analysis_entry.grid(row=1, column=0, columnspan=2, pady=5, padx=10, sticky="w")
    file_button = ttk.Button(analysis_tab, text="Read from File", command=lambda: analysis_entry.insert(0, ','.join(read_input_from_file())))
    file_button.grid(row=1, column=2, pady=5, padx=10, sticky="w")

    feature_frame = ttk.Labelframe(analysis_tab, text="Select Features")
    feature_frame.grid(row=2, column=0, columnspan=3, pady=10, padx=10, sticky="w")

    features = [
        "Web Scraping", "WHOIS Lookup", "URL to IP", "IP Geolocation",
        "Reverse DNS Lookup", "SSL Certificate Analysis", "Port Scanning", "Subdomain Discovery", "Virus Total Check", "Threat Intel Lookup", "Malicious URL Prediction"
    ]
    feature_vars = {feature: ttk.BooleanVar() for feature in features}
    for i, feature in enumerate(features):
        ttk.Checkbutton(feature_frame, text=feature, variable=feature_vars[feature]).grid(row=i, column=0, sticky="w")

    select_all_var = ttk.BooleanVar()

    def select_all_features():
        for var in feature_vars.values():
            var.set(select_all_var.get())

    ttk.Checkbutton(feature_frame, text="Select All", variable=select_all_var, command=select_all_features).grid(row=len(features), column=0, sticky="w")

    analysis_results_text = ttk.Text(analysis_tab, wrap="word")
    analysis_results_text.grid(row=3, column=0, columnspan=3, pady=10, padx=10, sticky="nsew")
    analysis_results_text.config(state=DISABLED)

    analysis_tab.grid_rowconfigure(3, weight=1)
    analysis_tab.grid_columnconfigure(0, weight=1)
    analysis_tab.grid_columnconfigure(1, weight=1)
    analysis_tab.grid_columnconfigure(2, weight=1)

    # Progress bar
    progress_bar = ttk.Progressbar(analysis_tab, mode="determinate", bootstyle="info")
    progress_bar.grid(row=4, column=0, columnspan=3, pady=10, padx=10, sticky="ew")

    results = {}

    def analyze_input():
        nonlocal results
        inputs = analysis_entry.get().split(',')
        if not inputs:
            messagebox.showerror("Error", "Please enter at least one URL or IP.")
            return

        selected_features = [feature for feature, var in feature_vars.items() if var.get()]
        if not selected_features:
            messagebox.showerror("Error", "Please select at least one feature to perform.")
            return

        analysis_results_text.config(state=NORMAL)
        analysis_results_text.delete(1.0, END)
        analysis_results_text.config(state=DISABLED)

        results = {}

        progress_bar["value"] = 0
        total_tasks = len(inputs) * len(selected_features)
        progress_bar["maximum"] = 100

        progress_queue = Queue()

        def update_progress():
            while True:
                progress_queue.get()
                completed_tasks = progress_bar["value"] + (100 / total_tasks)
                progress_bar["value"] = min(completed_tasks, 100)
                progress_queue.task_done()

        progress_thread = threading.Thread(target=update_progress, daemon=True)
        progress_thread.start()

        def execute_tasks():
            with ThreadPoolExecutor() as executor:
                futures = {}
                if "Web Scraping" in selected_features:
                    futures["Web Scraping"] = {
                        input_str: executor.submit(perform_web_scraping, input_str, progress_queue) for input_str in inputs}
                if "WHOIS Lookup" in selected_features:
                    futures["WHOIS Lookup"] = {
                        input_str: executor.submit(bulk_whois_lookup, [input_str], progress_queue) for input_str in inputs}
                if "URL to IP" in selected_features:
                    futures["URL to IP"] = {input_str: executor.submit(url_to_ip, [input_str], progress_queue) for input_str in inputs}
                if "IP Geolocation" in selected_features:
                    futures["IP Geolocation"] = {input_str: executor.submit(ip_geolocation, [input_str], progress_queue) for input_str in inputs}
                if "Reverse DNS Lookup" in selected_features:
                    futures["Reverse DNS Lookup"] = {input_str: executor.submit(reverse_dns_lookup, [input_str], progress_queue) for input_str in inputs}
                if "SSL Certificate Analysis" in selected_features:
                    futures["SSL Certificate Analysis"] = {input_str: executor.submit(ssl_certificate_analysis, [input_str], progress_queue) for input_str in inputs}
                if "Port Scanning" in selected_features:
                    futures["Port Scanning"] = {input_str: executor.submit(perform_port_scan, [input_str], DEFAULT_PORTS, progress_queue) for input_str in inputs}
                if "Subdomain Discovery" in selected_features:
                    futures["Subdomain Discovery"] = {input_str: executor.submit(subdomain_discovery, input_str, progress_queue) for input_str in inputs}
                if "Virus Total Check" in selected_features:
                    futures["Virus Total Check"] = {input_str: executor.submit(check_url, input_str, VIRUSTOTAL_API_KEY, progress_queue) for input_str in inputs}
                if "Threat Intel Lookup" in selected_features:
                    futures["Threat Intel Lookup"] = {input_str: executor.submit(threat_intel_lookup, input_str, ALIENVAULT_OTX_API_KEY, progress_queue) for input_str in inputs}
                if "Malicious URL Prediction" in selected_features:
                    futures["Malicious URL Prediction"] = {input_str: executor.submit(predict_url_task, input_str) for input_str in inputs}

                for feature, feature_futures in futures.items():
                    feature_results = {}
                    for input_str, future in feature_futures.items():
                        try:
                            result = future.result()
                            if feature == "Port Scanning":
                                feature_results[input_str] = {port: f"http://{input_str}:{port}" for port in result[input_str]}
                            elif feature == "Subdomain Discovery":
                                feature_results[input_str] = {'subdomains': result}
                            elif feature == "Virus Total Check":
                                summary = f"URL: {result['url']}\nScan Date: {result['scan_date']}\nPositives: {result['positives']}\nTotal: {result['total']}"
                                details = result.get('scans', {})
                                feature_results[input_str] = {"summary": summary, "details": details}
                            elif feature == "Malicious URL Prediction":
                                feature_results[input_str] = {'Prediction': 'Malicious' if result else 'Not Malicious'}
                            else:
                                feature_results[input_str] = result
                        except Exception as e:
                            feature_results[input_str] = str(e)
                    results[feature] = feature_results

            for key, value in results.items():
                analysis_results_text.config(state=NORMAL)
                analysis_results_text.insert(END, f"{key}:\n", 'feature_title')
                for k, v in value.items():
                    analysis_results_text.insert(END, f"Input: {k}\n", 'input_title')
                    if key == "Port Scanning":
                        analysis_results_text.insert(END, f"{k}:\n")
                        for port, url in v.items():
                            analysis_results_text.insert(END, f"{port}\n", url)
                            analysis_results_text.tag_add(url, "end-2c", "end")
                            analysis_results_text.tag_config(url, foreground="blue", underline=True)
                            analysis_results_text.tag_bind(url, "<Button-1>", lambda e, u=url: webbrowser.open(u))
                    elif key == "Subdomain Discovery":
                        analysis_results_text.insert(END, "Subdomains:\n", 'output')
                        for subdomain in v['subdomains']:
                            analysis_results_text.insert(END, f"{subdomain}\n", 'subdomain_output')
                    elif key == "Virus Total Check":
                        analysis_results_text.insert(END, f"Output: {v['summary']}\n", "output")
                        analysis_results_text.insert(END, "Click to view details\n", "details")
                        analysis_results_text.tag_add("details", "end-2c", "end")
                        analysis_results_text.tag_config("details", foreground="blue", underline=True)
                        analysis_results_text.tag_bind("details", "<Button-1>", lambda e, d=v['details']: show_virustotal_details(d))
                    elif key == "Malicious URL Prediction":
                        analysis_results_text.insert(END, f"Output: {v['Prediction']}\n", "output")
                    else:
                        analysis_results_text.insert(END, f"Output: {v}\n", "output")
                analysis_results_text.insert(END, "\n")
                analysis_results_text.config(state=DISABLED)

        threading.Thread(target=execute_tasks, daemon=True).start()

    def predict_url_task(input_str):
        features = preprocess_url_or_ip(input_str)
        is_malicious = predict_malicious(features)
        return is_malicious

    def show_virustotal_details(details):
        details_window = ttk.Toplevel(root)
        details_window.title("VirusTotal Details")
        details_window.geometry("800x600")

        details_text = ttk.Text(details_window, wrap="word")
        details_text.pack(expand=1, fill="both")

        for engine, result in details.items():
            details_text.insert(END, f"Engine: {engine}\n")
            details_text.insert(END, f"Detected: {result.get('detected', 'N/A')}\n")
            details_text.insert(END, f"Result: {result.get('result', 'N/A')}\n")
            details_text.insert(END, f"Update: {result.get('update', 'N/A')}\n\n")

    def generate_pdf_report():
        generate_report(results)

    analysis_results_text.tag_config("feature_title", foreground="cyan", font=("Arial", 12, "bold"))
    analysis_results_text.tag_config("input_title", foreground="yellow", font=("Arial", 10, "bold"))
    analysis_results_text.tag_config("output", foreground="white")
    analysis_results_text.tag_config("subdomain_output", foreground="green", font=("Arial", 10, "italic"))

    # Create a frame to hold the buttons and pack it at the bottom
    button_frame = ttk.Frame(analysis_tab)
    button_frame.grid(row=5, column=0, columnspan=3, pady=10, padx=10, sticky="ew")

    analyze_button = ttk.Button(button_frame, text="Analyze", command=analyze_input)
    clear_button = ttk.Button(button_frame, text="Clear", command=lambda: analysis_results_text.config(state=NORMAL) or analysis_results_text.delete(1.0, END) or analysis_results_text.config(state=DISABLED))
    stop_button = ttk.Button(button_frame, text="Stop", command=lambda: print("Stop functionality to be implemented"))
    report_button = ttk.Button(button_frame, text="Generate Report", command=generate_pdf_report)

    analyze_button.pack(side="left", padx=5)
    clear_button.pack(side="left", padx=5)
    stop_button.pack(side="left", padx=5)
    report_button.pack(side="left", padx=5)

    # Google Dorking tab widgets
    dorking_query_label = ttk.Label(dorking_tab, text="Enter your search query:")
    dorking_query_label.grid(row=0, column=0, columnspan=3, pady=10, padx=10, sticky="w")
    dorking_query_entry = ttk.Entry(dorking_tab, width=80)
    dorking_query_entry.grid(row=1, column=0, columnspan=3, pady=5, padx=10, sticky="w")

    dorking_choice_frame = ttk.Labelframe(dorking_tab, text="Select Input Type(s) for Recon")
    dorking_choice_frame.grid(row=2, column=0, columnspan=3, pady=10, padx=10, sticky="w")

    dorking_choices = [
        ("File type", "1"),
        ("Website", "2"),
        ("Title", "3"),
        ("URL", "4")
    ]
    dorking_choice_vars = {choice[1]: ttk.BooleanVar() for choice in dorking_choices}
    for i, (choice, value) in enumerate(dorking_choices):
        ttk.Checkbutton(dorking_choice_frame, text=choice, variable=dorking_choice_vars[value]).grid(row=i, column=0, sticky="w")

    dorking_results_text = ttk.Text(dorking_tab, wrap="word")
    dorking_results_text.grid(row=3, column=0, columnspan=3, pady=10, padx=10, sticky="nsew")

    dorking_tab.grid_rowconfigure(3, weight=1)
    dorking_tab.grid_columnconfigure(0, weight=1)
    dorking_tab.grid_columnconfigure(1, weight=1)
    dorking_tab.grid_columnconfigure(2, weight=1)

    def dorking_action():
        query = dorking_query_entry.get().strip()
        if not query:
            messagebox.showerror("Error", "Please enter a search query.")
            return

        choices = [key for key, var in dorking_choice_vars.items() if var.get()]
        if not choices:
            messagebox.showerror("Error", "Please select at least one input type for Recon.")
            return

        dorking_results = perform_google_dorking(query, choices)
        dorking_results_text.delete(1.0, END)
        if 'items' in dorking_results:
            for item in dorking_results['items']:
                title = item.get('title', 'No Title')
                link = item.get('link', 'No Link')
                dorking_results_text.insert(END, f"{title} - {link}\n")
                dorking_results_text.tag_add("link", "end-2c", "end")
                dorking_results_text.tag_config("link", foreground="blue", underline=True)
                dorking_results_text.tag_bind("link", "<Button-1>", lambda e, url=link: webbrowser.open(url))
        else:
            dorking_results_text.insert(END, "No results found.")

    dorking_button = ttk.Button(dorking_tab, text="Perform Google Dorking", command=dorking_action)
    dorking_button.grid(row=4, column=0, columnspan=3, pady=10, padx=10, sticky="ew")

    root.mainloop()

if __name__ == "__main__":
    create_gui()
