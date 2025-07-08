# === Importing necessary libraries and modules ===

# Flask is a lightweight WSGI web application framework for Python.
# It is used to build web applications, handle requests, render templates, manage sessions, and provide user feedback.
from flask import Flask, request, render_template, redirect, url_for, session, flash

# Pandas is a powerful data manipulation and analysis library.
# Commonly used for working with tabular data such as CSV or Excel files.
import pandas as pd

# Matplotlib is a popular data visualization library in Python.
# 'pyplot' is its interface for creating plots and charts.
import matplotlib.pyplot as plt

# The base 'matplotlib' module provides configuration and advanced plotting tools.
import matplotlib

# Seaborn is a statistical data visualization library built on top of Matplotlib.
# It provides an easier and more visually appealing API for creating complex plots.
import seaborn as sns

# Base64 is used for encoding binary data (like images) into ASCII strings.
# Commonly used for embedding image data into HTML or JSON.
import base64

# io provides tools for working with I/O operations.
# Useful for handling in-memory binary streams (e.g., creating images without saving them to disk).
import io

# Used for authenticating with Google services via service account credentials.
# Essential for securely accessing Google APIs like Google Sheets.
from google.oauth2.service_account import Credentials

# PyMongo is the official MongoDB driver for Python.
# MongoClient is used to connect and interact with a MongoDB database.
from pymongo import MongoClient 

# os provides functions to interact with the operating system.
# Often used to access environment variables and file paths.
import os

# dotenv loads environment variables from a .env file into the environment.
# Useful for managing sensitive configuration (e.g., API keys, database URIs).
from dotenv import load_dotenv

# datetime provides classes for manipulating dates and times.
# Often used for logging, scheduling, or setting expiration policies.
import datetime

# === Itertools ===
# The 'itertools' module provides a set of fast, memory-efficient tools 
# for working with iterators. It is useful for creating complex iteration logic.
from itertools import combinations  # Used to generate all possible combinations of a given iterable.
import itertools  # General import to access other itertools functions if needed.

# Use the 'Agg' backend for matplotlib to avoid GUI requirements (for server environments)
matplotlib.use('Agg')

# Load environment variables from .env file
load_dotenv()



# Define databases
db_main = client['businessinfo'] 
db_business = client['businessdata'] 
csv_collection = db_business["csv_files"] 

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# Folder to store uploads (if used in future)
UPLOAD_FOLDER = 'uploads'

# === Save DataFrame to MongoDB ===
# This function takes a DataFrame and stores a trimmed version (max 200 rows × 5 columns)
# into a MongoDB collection, uniquely named per business. It uses session/form to get the business ID.
def save_dataframe_to_mongo(df, collection_name="uploaded_data"):
    """
    Save a filtered portion of the DataFrame (first 200 rows and 5 columns) to MongoDB.

    Parameters:
    - df (pd.DataFrame): DataFrame to be saved
    - collection_name (str): Optional name of the MongoDB collection
    """
    try:
        business_id = session.get('business_id') or request.form.get('business_id')

        if not business_id:
            print("Invalid Business ID!")
            flash("Invalid Business ID!", 'danger')
            return render_template('register.html', error="Invalid Business ID!")

        # Filter to max 200 rows and 5 columns
        df_filtered = df.iloc[:200, :5]
        records = df_filtered.to_dict(orient='records')
        csv_collection_name = f"{business_id}csv"
        csv_collection = db_business[csv_collection_name]
        delete_result = csv_collection.delete_many({}) # Delete previous records

        csv_data = {
            'business_id': business_id,
            'csv_file': records,
            'created_at': datetime.datetime.utcnow()
        }

        insert_result = csv_collection.insert_one(csv_data)

    except Exception as e:
        print(f"Error saving CSV to MongoDB: {e}")
        flash(f"Error saving CSV to MongoDB: {e}", "danger")
        return redirect(url_for('data_analysis'))

# === Load DataFrame from MongoDB ===
# Retrieves the most recent CSV-like document for the given business_id,
# converting it back into a pandas DataFrame.
def load_dataframe_from_mongo(business_id):
    """
    Load the latest saved CSV from MongoDB and convert it into a pandas DataFrame.

    Parameters:
    - business_id (str): ID of the business used to retrieve the collection

    Returns:
    - pd.DataFrame: DataFrame created from stored CSV data
    """
    mongo_client = db_business.client
    businessdata_db = mongo_client['businessdata']
    csv_collection_name = f"{business_id}csv"
    csv_collection = businessdata_db[csv_collection_name]

    latest_csv_doc = csv_collection.find_one(sort=[('created_at', -1)])

    if not latest_csv_doc:
        print(f"No CSV found for this user.")
        flash(f"No CSV found for this user.", "danger")
        return redirect(url_for('data_analysis'))

    csv_records = latest_csv_doc.get('csv_file', [])
    if not csv_records or not isinstance(csv_records, list):
        print(f"Invalid or empty CSV.")
        flash(f"Invalid or empty CSV.", "danger")
        return redirect(url_for('data_analysis'))

    return pd.DataFrame(csv_records)

# === Save Analysis to MongoDB ===
# Stores analysis results including images (charts), human-written and AI-generated
# explanations, and an optional summary, all linked to a business ID.
def save_analysis_to_mongo(business_id, charts, explanations, explanationsai, summary):
    """
    Save analysis results including charts and explanations to MongoDB.

    Parameters:
    - business_id (str): Business identifier
    - charts (list): Base64-encoded charts
    - explanations (list): Human-written chart explanations
    - explanationsai (list): AI-generated insights
    - summary (str): Overall summary of data
    """
    try:
        csv_collection_name = f"{business_id}csv"
        csv_collection = db_business[csv_collection_name]

        analysis_doc = {
            'business_id': business_id,
            'charts': charts,
            'explanations': explanations,
            'explanationsai': explanationsai,
            'summary': summary,
            'created_at': datetime.datetime.utcnow()
        }

        insert_result = csv_collection.insert_one(analysis_doc)

    except Exception as e:
        print(f"Error saving analysis to MongoDB: {e}")
        flash(f"Error saving analysis to MongoDB: {e}", "danger")

# === Helper Function ===
# Utility function to convert a Matplotlib plot to a base64-encoded PNG image string.
# This enables embedding the plot directly into HTML or returning it as JSO
def plot_to_base64(plot_func):
    """
    Executes a plotting function, captures the output as an in-memory image, and encodes it in base64.

    This is useful for embedding plots directly into HTML or JSON responses without writing them to disk.

    Args:
        plot_func (function): A function that generates a matplotlib plot when called.

    Returns:
        str or None: Base64-encoded PNG image if successful, otherwise None.
    """
    img = io.BytesIO() # Create an in-memory binary stream

    try:
        plt.figure(figsize=(10, 6)) # Set default figure size
        plot_func() # Execute the plotting function provided as argument
        plt.tight_layout() # Adjust subplot params for neat layout
        plt.savefig(img, format="png") # Save the figure to the in-memory buffer
        plt.close() # Close the plot to free memory
        img.seek(0) # Reset stream pointer to the beginning
        return base64.b64encode(img.getvalue()).decode("utf-8") # Return base64 string
    
    except Exception as e:
        return None

# === Core Analysis Function ===
# This function performs exploratory data analysis (EDA) on a pandas DataFrame.
# It automatically generates multiple types of visual insights and summary statistics.
def analyze_dataframe(df):
    """
    Analyzes a pandas DataFrame and generates statistical summaries and visualizations.

    The function automatically identifies numeric and categorical columns, and generates:
    - Histograms and KDEs for numeric data
    - Boxplots
    - Correlation heatmaps
    - Scatter plots for pairs of numeric columns
    - Line charts of numeric values grouped by categories
    - Pie charts of numeric values grouped by categories
    - OLAP-like Slice & Dice bar charts
    - Time-based drilldowns if a date column is detected
    - Pivot tables visualized via heatmaps

    Returns:
        dict: A structured dictionary containing dataset info, base64-encoded images, and potential warnings.
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

    # === Histograms with KDE ===
    for col in num_cols:
        img = plot_to_base64(lambda: sns.histplot(df[col].dropna(), kde=True))
        if img:
            results["images"].append({"title": f"Histogram with KDE - {col}", "data": img})

    # === Boxplots ===
    for col in num_cols:
        img = plot_to_base64(lambda: sns.boxplot(x=df[col].dropna()))
        if img:
            results["images"].append({"title": f"Boxplot - {col}", "data": img})

    # === Correlation Matrix ===
    if len(num_cols) >= 2:
        img = plot_to_base64(lambda: sns.heatmap(df[num_cols].corr(), annot=True, cmap="coolwarm"))
        if img:
            results["images"].append({"title": "Correlation Matrix", "data": img})

    # === Scatter Plots ===
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
        flash(f"Error generating combined Line Chart: {e}", "danger")
    
    # === Pie Charts by Category ===
    for cat_col in cat_cols:
        for num_col in num_cols:
            try:
                # Agrupa a coluna numérica pela categórica (soma por categoria)
                grouped_values = df.groupby(cat_col)[num_col].sum().sort_values(ascending=False)

                def plot():
                    grouped_values.plot.pie(
                        autopct="%1.1f%%",
                        startangle=90,
                        figsize=(6, 6),
                        ylabel=''  # Remove y-label padrão
                    )
                    plt.title(f'Pie Chart - {num_col} por {cat_col}')

                img = plot_to_base64(plot)
                if img:
                    results["images"].append({
                        "title": f"Pie Chart - {num_col} por {cat_col}",
                        "data": img
                    })

            except Exception as e:
                print(f"Error generating Pie Chart for {cat_col} e {num_col}: {e}")
                flash(f"Error generating Pie Chart for {cat_col} e {num_col}: {e}", "danger")
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
            print(f"Error generating pie chart for value_counts de {num_col}: {e}")
            flash(f"Error generating pie chart for value_counts de {num_col}: {e}", "danger")
            continue
        
    # === OLAP Slice & Dice ===
    for cat_col in cat_cols:
        for num_col in num_cols:
            try:
                grouped = df.groupby(cat_col)[num_col].sum().sort_values(ascending=False)

                if grouped.shape[0] > 1:  # Só plota se houver mais de uma categoria
                    def plot():
                        grouped.head(10).plot(kind='bar', figsize=(8, 5))
                        plt.title(f'OLAP Slice & Dice - Soma de {num_col} por {cat_col}')
                        plt.xlabel(cat_col)
                        plt.ylabel(f'Soma de {num_col}')
                        plt.xticks(rotation=45)

                    img = plot_to_base64(plot)
                    if img:
                        results["images"].append({
                            "title": f"OLAP Slice & Dice - {num_col} por {cat_col}",
                            "data": img
                        })

            except Exception as e:
                print(f"Error generating OLAP Slice & Dice for {cat_col} e {num_col}: {e}")
                flash(f"Error generating OLAP Slice & Dice for {cat_col} e {num_col}: {e}", "danger")
                continue
    
    # === OLAP Drill Down (monthly analysis) ===
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
                            plt.title(f"OLAP Drill Down - {col_name} (por {date_col})")
                            plt.xlabel("Mês")
                            plt.ylabel(f"Soma de {col_name}")
                            plt.grid(True)
                            plt.xticks(rotation=45)
                        return plot

                    plot_func = make_plot(monthly_summary, col)
                    img = plot_to_base64(plot_func)
                    if img:
                        results["images"].append({
                            "title": f"OLAP Drill Down - {col} por {date_col}",
                            "data": img
                        })

                except Exception as e:
                    print(f"Error generating OLAP Drill Down for {col}: {e}")
                    flash(f"Error generating OLAP Drill Down for {col}: {e}", "danger")
                    continue
        except Exception as e:
            print(f"General error in Drill Down with column {date_col}: {e}")
            flash(f"General error in Drill Down with column {date_col}: {e}", "danger")

    # === Pivot Tables (heatmaps) ===
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
                    plt.title(f"OLAP Pivot Table - {num_col} por {', '.join(cat_combo)}")
                img = plot_to_base64(plot)
                if img:
                    results["images"].append({"title": f"OLAP Pivot Table - {num_col} por {', '.join(cat_combo)}", "data": img})
            except Exception as e:
                print(f"Error generating OLAP Pivot Table for {num_col} with {cat_combo}: {e}")
                flash(f"Error generating OLAP Pivot Table for {num_col} with {cat_combo}: {e}", "danger")

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
