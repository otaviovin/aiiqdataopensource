# === Importing necessary libraries and modules ===

# Flask is a lightweight WSGI web application framework for Python.
# 'flash' is used to send temporary one-time messages to templates (e.g., for errors or confirmations)
from flask import flash

# Pandas is a powerful data manipulation and analysis library.
# It is often used for working with structured/tabular data (like CSV or Excel).
import pandas as pd

# Matplotlib is a 2D plotting library for Python.
# 'pyplot' provides a MATLAB-like interface for plotting data.
import matplotlib.pyplot as plt

# Seaborn is a high-level data visualization library based on Matplotlib.
# It provides a cleaner API for drawing attractive and informative statistical graphics.
import seaborn as sns

# Base64 is a module for encoding and decoding binary data into base64 format.
# Commonly used to embed images or other binary files in HTML or JSON.
import base64

# io provides tools for working with I/O streams.
# 'BytesIO' is often used to handle in-memory binary data (e.g., images or files).
import io

# gspread is a Python API for interacting with Google Sheets.
# It allows reading, writing, and managing spreadsheets in Google Drive.
import gspread

# Google OAuth2 service account credentials.
# Used to authenticate securely when accessing Google APIs, such as Google Sheets.
from google.oauth2.service_account import Credentials

# re is the built-in regular expressions library in Python.
# It is used for pattern matching and searching within strings.
import re

# === Itertools ===
# The 'itertools' module provides a set of fast, memory-efficient tools 
# for working with iterators. It is useful for creating complex iteration logic.
from itertools import combinations  # Used to generate all possible combinations of a given iterable.
import itertools  # General import to access other itertools functions if needed.

SERVICE_ACCOUNT_INFO = {
  "type": "service_account",
  "project_id": "aiiqdata-1749032185255",
  "private_key_id": "b4c54a216295e8a6d044f8e3ee559a0f49c4c53a",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCbQgeRmM0vHPxt\nmJyaoqcMBh2NyThDJGx9ZlEq6fjiQTUKEAUB9tsiXHwx1aCQtRqKFxz+D6c2Epw1\ngy0DcNr/nrUDmligaY0twnuKA/E8wlR+gDR7CV/C0rQuv1HR//39vBWQsqerIvaz\ntXKSoZVHS4dAg8eh0BPMhYgEhMBAqRT22V2bOiwEX7kzST06ZIrAKa2dIz3Wy7P7\nDTCjcS1/2KbP5Yw1XW9ydU05zDO5Ix50hK8dFpRAwO/ltn4COgK2uOeXhiJf/ito\nqhWgMO8zHbhGzGfQJ6sPGgBYx6pG1tNLgwtk08EptNy+bBHU5SBfUb0ys9U1xftD\nn8k+n539AgMBAAECggEAEkhoxsL1Kp6htTA7BNSxki9oLImtB+8SnYO+fCy4Q8CF\nA+3WASC2Nmoor9+lvFSvTuKg5eQm/y2a2oxbcSPJjj98tnNnC2DSoLhdvudu8YY6\n1/i19WUpszIHyNd7xZx9JvOOoI8BQpxn68qqtsyzXQVuZHEAQbRUmImC9nFBiHuR\nxshF4kjnGqaMyYiM1Pp5iQDLnnEw427rSdb3zqf+kU6v/TVw3mZf28v5QkKic1XQ\nQqqatsMEZfNSwpg2doFUBKIcZJ5IpPh3wMvbfYGy7FDXvkZahNGbk2LZ8HvpQvmq\nSDnlyNVRnpdjdgLqygXldzQOIl7Hl0AYFJRv/RSSCwKBgQDLyc81aY9M7lvmRSC/\n9GRx6eDdUrUpkzxLxCCwopqAs3wnJ6gnLpBnZ48MReImWIymtjCFSE/gN1X1We4j\nyWL1miCBXY/R0v0fwuGvK08lS1mgY+6bLanPJ0WeR0fp1nqotZ9QiMJFBW6aiJWc\nt4XDbPCSFReGbFoosTy/H6F78wKBgQDDCS4GvSCAMpID2vUUBQ6opviZ6j1F6tVK\nszVbJVErXsVxad0HfRT4tjOwv8W9PH0SZ9bDVgmOCkGj43jWuThbz+HbP1R++3YE\nUxU7cBUbbGjSAb7oNgRfVKrTPOihpJ+6VlPITY+JpTpU8FkGzitzRI+Y3Ze7PVUW\n1S1EOFmqTwKBgQCQ7Nk2Q/bMICss7HZo7JXOSSRIYXxCr9nOjBEvbMPxyTL+6X31\nN3EsiII7mStGV+zW1nRVJOLhMpkn3ie0PZDp1w1M0svnzWOEBeTX3TXw8NAxd0AG\nDYhYsLYa5NhonMYoWtmMvWVjDoTk00OK6xzuqPfA+8z6JO5NSBZKWWVPLwKBgCKK\nwqsQ3eu2iSPDqLol9yWphMgFs1ppr+LuAFonLswGmeNvQ2UrIwa1hkwcetH8H46d\n82xfFYwhhuSWyfUFktS36aFiAv4GXS2A5XbEcAiOV7Yx9vS7dGTJ4wNMe0r9lAh1\nd5s3GV/gcodOlgXdh9Z/YwtI27GeuC42DTFS5ZaDAoGBAKdpPPMrlW4B9J/VSV/Z\n0JdWrE7jJalun2WUUU3G1KvTZXZd4MQIqls1LLZW6QePhgdoBrJoogWffloru/77\njnV00rjeoHVN2B8wIGZRg6zACFNkmZf8GbTcmldnOeLWdqlaAEtW5rSLn9zU4gwd\nRigd7XP6qCw4+xUJfWUqzflD\n-----END PRIVATE KEY-----\n",
  "client_email": "aiiqdata-service@aiiqdata-1749032185255.iam.gserviceaccount.com",
  "client_id": "113607119034022445441",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/aiiqdata-service%40aiiqdata-1749032185255.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}

# === Google Sheets Data Loader ===
# This function connects to a public or shared Google Sheet using the provided URL,
# extracts the sheet's ID, authenticates via a service account, retrieves the data,
# and returns both the content as a DataFrame and some metadata.
def load_google_sheet_visual_data(sheet_url):
    """
    Load data from a public/shared Google Sheet URL using a service account.

    Parameters:
        sheet_url (str): The full URL of the Google Sheet to read.

    Returns:
        Tuple[pd.DataFrame, dict]: A tuple containing:
            - A pandas DataFrame with all sheet records.
            - A dictionary with metadata (sheet ID, title, worksheet title, etc.)

    Raises:
        ValueError: If the sheet ID cannot be extracted from the URL.
        Exception: For any authentication or data loading failure.
    """    
    try:
        SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly",
                  "https://www.googleapis.com/auth/drive.readonly"]
        credentials = Credentials.from_service_account_info(SERVICE_ACCOUNT_INFO, scopes=SCOPES)
        client = gspread.authorize(credentials)

        # Extrai o ID da planilha
        match = re.search(r"/d/([a-zA-Z0-9-_]+)", sheet_url)
        if not match:
            flash("Spreadsheet ID not found in the URL.", "danger")
            raise ValueError("Spreadsheet ID not found in the URL.")

        sheet_id = match.group(1)
        spreadsheet = client.open_by_key(sheet_id)
        sheet = spreadsheet.sheet1
        data = sheet.get_all_records()

        spreadsheet_info = {
            "url": sheet_url,
            "sheet_id": sheet_id,
            "sheet_title": spreadsheet.title,
            "worksheet_title": sheet.title,
        }

        return pd.DataFrame(data), spreadsheet_info
    
    except Exception as e:
        flash("Error loading the spreadsheet:", "danger")
        raise

# === Plot Wrapper ===
# Converts any plotting function into a base64 PNG image string.
# Used to embed plots in HTML templates or APIs without saving to disk.
def plot_to_base64(plot_func):
    """
    Render a plot as a base64-encoded PNG string.

    Parameters:
        plot_func (Callable): A function that renders a Matplotlib plot.

    Returns:
        str or None: The base64-encoded image string if successful; otherwise, None.
    """
    img = io.BytesIO()

    try:
        plt.figure(figsize=(10, 6))
        plot_func()
        plt.tight_layout()
        plt.savefig(img, format="png")
        plt.close()
        img.seek(0)
        return base64.b64encode(img.getvalue()).decode("utf-8")
    
    except Exception as e:
        return None

# === Core Analysis Function for Google Sheets ===
# Performs data profiling and visualization on a DataFrame loaded from a Google Sheet.
# Automatically identifies column types, builds plots, and returns results as base64 images.
def analyze_dataframe_googlesheets(df):
    """
    Analyze a pandas DataFrame (loaded from Google Sheets) and generate statistical visualizations.

    Generates:
        - Histograms with KDE for numeric columns
        - Boxplots
        - Correlation heatmaps
        - Scatter plots (pairwise)
        - Line charts of numeric sums by category
        - Pie charts of numeric sums by category
        - Slice & Dice bar charts (OLAP-style)
        - Monthly drilldowns (if a date column is found)
        - Pivot tables as annotated heatmaps

    Parameters:
        df (pd.DataFrame): The data to analyze.

    Returns:
        dict: {
            "info": summary info about columns and datatypes,
            "images": list of {title, base64 image},
            "warnings": list of warning messages
        }
    """
    results = {
        "info": {},
        "images": [],
        "warnings": [],
    }

    results["info"]["rows"] = df.shape[0]
    results["info"]["cols"] = df.shape[1]
    results["info"]["columns"] = df.columns.tolist()
    num_cols = df.select_dtypes(include="number").columns.tolist()
    cat_cols = df.select_dtypes(include="object").columns.tolist()
    results["info"]["numeric"] = num_cols
    results["info"]["categorical"] = cat_cols

    # === Histogram with KDE ===
    for col in num_cols:
        img = plot_to_base64(lambda: sns.histplot(df[col].dropna(), kde=True))
        if img:
            results["images"].append({"title": f"Histogram with KDE - {col}", "data": img})

    # === Boxplot ===
    for col in num_cols:
        img = plot_to_base64(lambda: sns.boxplot(x=df[col].dropna()))
        if img:
            results["images"].append({"title": f"Boxplot - {col}", "data": img})

    # === Correlation Matrix ===
    if len(num_cols) >= 2:
        img = plot_to_base64(lambda: sns.heatmap(df[num_cols].corr(), annot=True, cmap="coolwarm"))
        if img:
            results["images"].append({"title": "Correlation Matrix", "data": img})

    # === Scatter Plots for Numeric Pairs ===
    if len(num_cols) >= 2:
        for x_col, y_col in combinations(num_cols, 2):
            try:
                def plot():
                    sns.scatterplot(x=df[x_col], y=df[y_col])
                    plt.title(f'Scatter Plot - {x_col} vs {y_col}')
                    plt.xlabel(x_col)
                    plt.ylabel(y_col)
                
                img = plot_to_base64(plot)
                if img:
                    results["images"].append({
                        "title": f"Scatter Plot - {x_col} vs {y_col}",
                        "data": img
                    })

            except Exception as e:
                continue

    # === Line Charts Individual ===
    for num_col in num_cols:
        try:
            def plot():
                plt.figure(figsize=(10, 5))
                plt.plot(df.index, df[num_col], marker='o', label=num_col)
                plt.title(f'Line Chart - {num_col}')
                plt.xlabel('Index')
                plt.ylabel(num_col)
                plt.grid(True)
                plt.legend()

            img = plot_to_base64(plot)
            if img:
                results["images"].append({
                    "title": f"Line Chart - {num_col}",
                    "data": img
                })

        except Exception as e:
            continue

    # === Line Chart All Numeric Columns ===
    try:
        def plot_all_lines():
            plt.figure(figsize=(12, 6))
            for num_col in num_cols:
                plt.plot(df.index, df[num_col], marker='o', label=num_col)
            plt.title(f'Line Chart - All Numeric Columns')
            plt.xlabel('Index')
            plt.ylabel('Values')
            plt.grid(True)
            plt.legend(loc='best')

        img = plot_to_base64(plot_all_lines)
        if img:
            results["images"].append({
                "title": f"Line Chart - All Numeric Columns",
                "data": img
            })

    except Exception as e:
        print(f"Error generating combined Line Chart: {e}")
        flash(f"Error generating combined Line Chart.", "danger")
    
    # === Pie Charts ===
    for cat_col in cat_cols:
        for num_col in num_cols:
            try:
                # Groups the numeric column by the categorical one (sum by category)
                grouped_values = df.groupby(cat_col)[num_col].sum().sort_values(ascending=False)

                def plot():
                    grouped_values.plot.pie(
                        autopct="%1.1f%%",
                        startangle=90,
                        figsize=(6, 6),
                        ylabel='' # Removes default y-label
                    )
                    plt.title(f'Pie Chart - {num_col} by {cat_col}')

                img = plot_to_base64(plot)
                if img:
                    results["images"].append({
                        "title": f"Pie Chart - {num_col} by {cat_col}",
                        "data": img
                    })

            except Exception as e:
                continue

    # === Pie Charts by Value ===
    for num_col in num_cols:
        try:
            counts = df[num_col].value_counts().sort_values(ascending=False)

            def plot():
                counts.plot.pie(
                    autopct='%1.1f%%',
                    startangle=90,
                    figsize=(6, 6),
                    ylabel=''
                )
                plt.title(f'Pie Chart - Value Distribution in {num_col}')

            img = plot_to_base64(plot)
            if img:
                results["images"].append({
                    "title": f"Pie Chart - Value Distribution in {num_col}",
                    "data": img
                })

        except Exception as e:
            continue
    
    # === OLAP Slice & Dice ===
    for cat_col in cat_cols:
        for num_col in num_cols:
            try:
                grouped = df.groupby(cat_col)[num_col].sum().sort_values(ascending=False)

                if grouped.shape[0] > 1:  # Só plota se houver mais de uma categoria
                    def plot():
                        grouped.head(10).plot(kind='bar', figsize=(8, 5))
                        plt.title(f'OLAP Slice & Dice - Sum of {num_col} by {cat_col}')
                        plt.xlabel(cat_col)
                        plt.ylabel(f'Sum of {num_col}')
                        plt.xticks(rotation=45)

                    img = plot_to_base64(plot)
                    if img:
                        results["images"].append({
                            "title": f"OLAP Slice & Dice - {num_col} by {cat_col}",
                            "data": img
                        })

            except Exception as e:
                continue
    
    # === OLAP Drill Down (Date Analysis) ===
    date_col = None
    for candidate_col in df.select_dtypes(include=['object', 'string']).columns:
        try:
            parsed = pd.to_datetime(df[candidate_col], errors='coerce', infer_datetime_format=True)
            if parsed.notnull().sum() > len(df) * 0.9:
                df[candidate_col] = parsed
                date_col = candidate_col
                break
            
        except Exception:
            continue

    if date_col:
        try:
            df['month'] = df[date_col].dt.to_period('M')
            for col in num_cols:
                try:
                    monthly_summary = df.groupby('month')[col].sum()
                    monthly_summary.index = monthly_summary.index.to_timestamp()

                    def make_plot(summary, col_name):
                        def plot():
                            summary.plot(marker='o', figsize=(8, 5))
                            plt.title(f"OLAP Drill Down - {col_name} (by {date_col})")
                            plt.xlabel("Month")
                            plt.ylabel(f"Sum of {col_name}")
                            plt.grid(True)
                            plt.xticks(rotation=45)
                        return plot

                    plot_func = make_plot(monthly_summary, col)
                    img = plot_to_base64(plot_func)
                    if img:
                        results["images"].append({
                            "title": f"OLAP Drill Down - {col} by {date_col}",
                            "data": img
                        })

                except Exception as e:
                    continue

        except Exception as e:
            print(f"Error in OLAP Drill Down with colunm {date_col}: {e}")
            flash(f"Error in OLAP Drill Down with colunm", "danger")

    # === Pivot Tables ===
    if len(cat_cols) >= 1 and len(num_cols) >= 1:
        cat_combinations = list(itertools.combinations(cat_cols, 2)) + [(col,) for col in cat_cols]
        pivot_tasks = [(num_col, cat_combo) for num_col in num_cols for cat_combo in cat_combinations]

        for num_col, cat_combo in pivot_tasks:
            try:
                pivot_table = pd.pivot_table(
                    df,
                    values=num_col,
                    index=cat_combo[0],
                    columns=cat_combo[1] if len(cat_combo) > 1 else None,
                    aggfunc='sum',
                    fill_value=0
                )
                def plot():
                    sns.heatmap(pivot_table, annot=True, fmt=".0f", cmap="Blues")
                    plt.title(f"Pivot Table - {num_col} by {', '.join(cat_combo)}")
                img = plot_to_base64(plot)
                if img:
                    results["images"].append({"title": f"OLAP Pivot Table - {num_col} by {', '.join(cat_combo)}", "data": img})
            except Exception as e:
                print(f"Error generating OLAP Pivot Table for {num_col} with {cat_combo}: {e}")
                flash(f"Error generating OLAP Pivot Table for {num_col} with {cat_combo}", "danger")

    # === Additional statistics per column ===
    statistics = {}

    for col in df.columns:
        if df[col].dtype in ['int64', 'float64']:
            statistics[col] = {
                "sum": df[col].sum(),
                "mean": df[col].mean(),
                "max": df[col].max(),
                "min": df[col].min(),
                "median": df[col].median(),
            }
        else:
            statistics[col] = {
                "most_frequent": df[col].mode().iloc[0] if not df[col].mode().empty else "N/A",
                "unique_count": df[col].nunique(),
                "top_5_values": df[col].value_counts().head(5).to_dict()
            }

    results["statistics"] = statistics

    return results
