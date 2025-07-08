# === Importing necessary libraries and modules ===

# Flask - Lightweight web framework for Python
# Provides tools for handling routes, templates, sessions, redirects, and flash messages
from flask import Flask, request, render_template, redirect, url_for, session, flash

# PyMongo - MongoDB driver for Python
# Used to connect and perform operations on a MongoDB database
from pymongo import MongoClient

# OS - Operating system interface
# Used for accessing environment variables and handling file paths
import os

# Pandas - Data analysis and manipulation library
# Useful for reading, cleaning, and transforming tabular data like CSV files
import pandas as pd

# Matplotlib - Core plotting library for Python
# Used to generate static graphs and charts
import matplotlib.pyplot as plt

# Seaborn - High-level interface for statistical graphics based on Matplotlib
# Used to create visually attractive and informative statistical plots
import seaborn as sns

# Matplotlib base module - May be used for backend configuration or advanced settings
import matplotlib

# IO - Core input/output tools
# Used to handle in-memory binary streams, such as image buffers
import io

# Base64 - Encoding and decoding binary data to base64
# Commonly used to embed images in HTML or JSON responses
import base64

# dotenv - Utility to load environment variables from a .env file
# Allows secure configuration management for secrets like API keys
from dotenv import load_dotenv

# datetime - Module for working with dates and times
# Useful for logging, session expiration, and time-based calculations
import datetime

# LangChain - Integration with OpenAI's ChatGPT for conversational AI
# Used to interact with ChatGPT models within a pipeline
from langchain_openai import ChatOpenAI

# LangChain PromptTemplate - Used to format and reuse structured prompts
# Helps in constructing consistent input prompts for language models
from langchain.prompts import PromptTemplate

# === Itertools ===
# The 'itertools' module provides a set of fast, memory-efficient tools 
# for working with iterators. It is useful for creating complex iteration logic.
from itertools import combinations  # Used to generate all possible combinations of a given iterable.
import itertools  # General import to access other itertools functions if needed.

# Use the 'Agg' backend for matplotlib to avoid GUI requirements (for server environments)
matplotlib.use('Agg')

# Load environment variables from .env file
load_dotenv()

# Load MongoDB URI from environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Error: MONGODB_URI not defined in .env file")  # Fail early if missing

# Connect to MongoDB with TLS (SSL), ignoring certificate validation
client = MongoClient(MONGODB_URI, tls=True, tlsAllowInvalidCertificates=True)

# Define databases
db_main = client['businessinfo'] 
db_business = client['businessdata'] 
csv_collection = db_business["csv_files"] 

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# Folder to store uploads (if used in future)
UPLOAD_FOLDER = 'uploads'

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
        delete_result = csv_collection.delete_many({})

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
        flash(f"No CSV found for this user.", "danger")
        return redirect(url_for('data_analysis'))

    csv_records = latest_csv_doc.get('csv_file', [])

    if not csv_records or not isinstance(csv_records, list):
        flash(f"Invalid or empty CSV.", "danger")
        return redirect(url_for('data_analysis'))

    return pd.DataFrame(csv_records)

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

def generate_ai_analysis(data_description, stats_summary, user_input):
    """
    Generate insights using AI based on chart descriptions, statistics, and user input.

    Parameters:
    - data_description (str): Description of the chart/data
    - stats_summary (dict): Summary statistics of the dataset
    - user_input (str): User-provided business context or question

    Returns:
    - str: AI-generated analysis text
    """
    prompt_template = PromptTemplate.from_template("""
    You are a specialized data analyst. Analyze the following data: {data_description}. User summary: {user_input}.
    Relevant statistics: {stats_summary}
    Describe the chart interpretation clearly and objectively. Identify relevant patterns, possible trends, 
    and actionable insights by focusing on the data details.
    """)
    
    llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0.5, max_tokens=1000)
    chain = prompt_template | llm
    
    try:
        response = llm.invoke(prompt_template.format(
            data_description=data_description,
            stats_summary=stats_summary,
            user_input=user_input
        ))

        return response.content.replace(". ", ".\n\n")
    
    except Exception as e:
        print(f"Error generating analysis with LLM: {e}")
        flash(f"Error generating analysis with LLM: {e}", "danger")
        return "Error generating analysis with LLM."

def analyze_data(df, user_input):
    """
    Perform data analysis: save CSV, generate summary stats, charts, and AI explanations.

    Parameters:
    - df (pd.DataFrame): Input DataFrame uploaded by user
    - user_input (str): Optional input from user about data context

    Returns:
    - Renders HTML templates based on processing status
    """    
    result = {}

    try:
        save_dataframe_to_mongo(df)

    except Exception as e:
        print(f"Error saving CSV to MongoDB within analyze_data: {e}")
        flash(f"Error saving CSV to MongoDB within analyze_data: {e}", "danger")
        return render_template('error.html', error=str(e))

    business_id = session.get('business_id') or request.form.get('business_id')

    if not business_id:
        print("Invalid Business ID!")
        flash("Invalid Business ID!", 'danger')
        return render_template('register.html', error="Invalid Business ID!")
    
    df = load_dataframe_from_mongo(business_id)
    if df.empty:
        print("The CSV file is empty.")
        flash("The CSV file is empty.", "danger")
        return redirect(url_for('data_analysis'))

    df_filtered = df.sample(n=200, random_state=42) if len(df) > 200 else df
    df_filtered = df_filtered.iloc[:, :5]
    stats_summary = df_filtered.describe().round(2).to_dict()
    # Organize charts and explanations by type
    charts_hist, charts_box, charts_corr, charts_scatter, charts_line, charts_pie = [], [], [], [], [], []
    exps_hist, exps_box, exps_corr, exps_scatter, exps_line, exps_pie = [], [], [], [], [], []
    expsai_hist, expsai_box, expsai_corr, expsai_scatter, expsai_line, expsai_pie = [], [], [], [], [], []
    numeric_columns = df_filtered.select_dtypes(include=['number']).columns
    category_columns = df_filtered.select_dtypes(include=['object']).columns

    if len(numeric_columns) == 0:
        print("There are no numerical columns for analysis.")
        flash("There are no numerical columns for analysis.", "danger")
        return redirect(url_for('data_analysis'))

    for column in numeric_columns:
        try:
            fig, ax = plt.subplots(figsize=(8, 4))
            sns.histplot(df_filtered[column], kde=True, bins=20, ax=ax)
            ax.set_title(f'Distribuição de {column}')
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='svg', bbox_inches='tight')
            plt.close()
            img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
            charts_hist.append(img_data)

            explanation = f'Histogram with KDE (Kernel Density Estimation): Objective: This chart displays the distribution of a numerical variable, showing the frequency of values along the X-axis and the intensity of that frequency on the Y-axis. The KDE line smooths the distribution, providing a clearer view of its shape (e.g., normal, skewed, etc.).Key Insights: The general shape of the distribution (normal, skewed, etc.), peaks, tails, and potential modes (multiple peaks).The chart of {column} shows the distribution of this variable. The X-axis represents the values, and the Y-axis shows their frequency. The KDE line (Kernel Density Estimation) indicates the smoothed distribution.'
            exps_hist.append(explanation)
            explanationai = generate_ai_analysis(f"Distribution of {column}, an Histogram with KDE.", stats_summary, user_input)
            expsai_hist.append(explanationai)

        except Exception as e:
            print(f"Error generating chart for {column}: {e}")
            flash(f"Error generating chart for {column}: {e}", "danger")
            continue 

    for column in numeric_columns:
        try:
            fig, ax = plt.subplots(figsize=(8, 4))
            sns.boxplot(x=df_filtered[column], ax=ax)
            ax.set_title(f'Boxplot of {column}')
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='svg', bbox_inches='tight')
            plt.close()
            img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
            charts_box.append(img_data)

            explanation = f'Boxplot: Objective: The boxplot illustrates the data distribution across quartiles, highlighting the median, interquartile range, and any outliers. Key Insights: Median (line inside the box), spread (size of the box), and outliers (points beyond the box edges). The boxplot of {column} provides insights into the data distribution, highlighting the median, quartiles, and outliers. The "box" represents the spread between quartiles, and the "whiskers" represent values outside the interquartile range.'
            exps_box.append(explanation)
            explanationai = generate_ai_analysis(f"Boxplot of {column}, highlighting outliers and distribution.", stats_summary, user_input)
            expsai_box.append(explanationai)

        except Exception as e:
            print(f"Error generating boxplot for {column}: {e}")
            flash(f"Error generating boxplot for {column}: {e}", "danger")
            continue  

    try:
        corr = df_filtered[numeric_columns].corr()
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(corr, annot=True, cmap='coolwarm', ax=ax)
        ax.set_title('Correlation Matrix')
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='svg', bbox_inches='tight')
        plt.close()
        img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
        charts_corr.append(img_data)

        explanation = 'Correlation Matrix: Objective: This chart shows how numerical variables correlate with each other. Values close to 1 or -1 indicate a strong correlation, while values near 0 suggest little or no correlation. Key Insights: Strong or weak relationships between variables, identifying dependency patterns.The correlation matrix chart displays the relationships between variables. Values close to 1 or -1 indicate strong positive or negative correlations, respectively, while values near 0 indicate weak or no correlation.'
        exps_corr.append(explanation)
        explanationai = generate_ai_analysis(f"Correlation matrix showing how numerical variables are correlated.", stats_summary, user_input)
        expsai_corr.append(explanationai)

        if len(numeric_columns) >= 2:
            for x_col, y_col in itertools.combinations(numeric_columns, 2):
                try:
                    fig, ax = plt.subplots(figsize=(8, 5))
                    sns.scatterplot(x=df_filtered[x_col], y=df_filtered[y_col], ax=ax)
                    ax.set_title(f'Scatter Plot - {x_col} vs {y_col}')
                    ax.set_xlabel(x_col)
                    ax.set_ylabel(y_col)
                    img_buffer = io.BytesIO()
                    plt.savefig(img_buffer, format='svg', bbox_inches='tight')
                    plt.close()
                    img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
                    charts_scatter.append(img_data)

                    explanation = (
                    f'Scatter Plot - {x_col} vs {y_col}: '
                    'This chart visualizes the relationship between two numerical variables. '
                    'It helps detect linear or non-linear trends, clusters, or outliers.'
                    )
                    exps_scatter.append(explanation)
                    explanationai = generate_ai_analysis(
                        f"Scatter plot showing the relationship between {x_col} and {y_col}.",
                        stats_summary, user_input
                    )
                    expsai_scatter.append(explanationai)

                except Exception as e:
                    print(f"Error generating Scatter Plot for {x_col} and {y_col}: {e}")
                    flash(f"Error generating Scatter Plot for {x_col} and {y_col}: {e}", "danger")

    except Exception as e:
        print(f"Error generating correlation matrix: {e}")
        flash(f"Error generating correlation matrix: {e}", "danger")

    for column in numeric_columns:
        try:
            fig, ax = plt.subplots(figsize=(8, 4))
            ax.plot(df_filtered.index, df_filtered[column], label=column)
            ax.set_title(f'Line Chart of {column}')
            ax.set_xlabel('Index')
            ax.set_ylabel(f'Value of {column}')
            ax.legend()
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='svg', bbox_inches='tight')
            plt.close()
            img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
            charts_line.append(img_data)

            explanation = f'Line Chart: Objective: This chart displays the progression of a variable over the index, useful for identifying trends, seasonality, or time-based patterns. Key Insights: Upward or downward trends over time, seasonal variations, and cyclical patterns. The line chart of {column} shows the evolution of this variable over the index, helping visualize trends and fluctuations.'
            exps_line.append(explanation)
            explanationai = generate_ai_analysis("Line chart showing the progression of a variable over the index.", stats_summary, user_input)
            expsai_line.append(explanationai)

        except Exception as e:
            print(f"Error generating line chart for {column}: {e}")
            flash(f"Error generating line chart for {column}: {e}", "danger")
            continue 

        try:
            fig, ax = plt.subplots(figsize=(6, 6))
            df_filtered[column].value_counts().plot.pie(autopct='%1.1f%%', ax=ax)
            ax.set_title(f'Distribution of {column}')
            ax.set_ylabel('') 
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='svg', bbox_inches='tight')
            plt.close()
            img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
            charts_pie.append(img_data)

            explanation = f"Pie Chart: Objective: This chart displays the proportional distribution of categories within the {column} variable. It helps quickly identify the most frequent categories and compare their representation. Key Insights: Relative proportion of each category, dominant categories (largest slices), underrepresented ones, and overall balance. The pie chart of {column} displays the distribution of categorical values as percentage proportions. It helps visualize which categories are most common within the variable."
            exps_pie.append(explanation)
            explanationai = generate_ai_analysis("Pie chart showing the proportional distribution of categories within the variable.", stats_summary, user_input)
            expsai_pie.append(explanationai)

        except Exception as e:
            print(f"Error generating pie chart for {column}: {e}")
            flash(f"Error generating pie chart for {column}: {e}", "danger")
            continue

    for cat_col in category_columns:
        for num_col in numeric_columns:
            try:
                grouped_values = df.groupby(cat_col)[num_col].sum().sort_values(ascending=False)

                fig, ax = plt.subplots(figsize=(6, 6))
                grouped_values.plot.pie(
                    autopct="%1.1f%%",
                    startangle=90,
                    ax=ax
                )
                ax.set_title(f'Pie Chart - {num_col} por {cat_col}')
                ax.set_ylabel('')
                img_buffer = io.BytesIO()
                plt.savefig(img_buffer, format='svg', bbox_inches='tight')
                plt.close()
                img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
                charts_pie.append(img_data)

                explanation = f"Pie Chart - {num_col} by {cat_col}: Shows the proportion of {num_col} aggregated by each category in {cat_col}."
                exps_pie.append(explanation)
                explanationai = generate_ai_analysis(f"Pie chart showing {num_col} aggregated by {cat_col}.", stats_summary, user_input)
                expsai_pie.append(explanationai)

            except Exception as e:
                print(f"Error generating Pie Chart for {cat_col} and {num_col}: {e}")
                flash(f"Error generating Pie Chart for {cat_col} and {num_col}: {e}", "danger")

    # Combine all in correct order
    charts = charts_hist + charts_box + charts_corr + charts_scatter + charts_line + charts_pie
    explanations = exps_hist + exps_box + exps_corr + exps_scatter + exps_line + exps_pie
    explanationsai = expsai_hist + expsai_box + expsai_corr + expsai_scatter + expsai_line + expsai_pie
    
    stats_text = df_filtered.describe().to_string()
    prompt_template = PromptTemplate.from_template("""
    Analyze the following statistical data and generate an informative summary: {stats}. Additionally, consider the 
    following user request to guide the analysis: {user_input}. The summary should be concise, highlighting trends, average values, 
    and important variations.
    """)

    summary_prompt = [
        {"role": "system", "content": "You are a data analysis assistant."},
        {"role": "user", "content": prompt_template.format(stats=stats_text, user_input=user_input)}
    ]
    
    llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0.5, max_tokens=1000)
    response = llm.invoke(summary_prompt)
    summary = response.content.replace(". ", ".\n\n")
    save_analysis_to_mongo(business_id, charts, explanations, explanationsai, summary)

    result['summary'] = summary
    result['charts'] = charts
    result['explanations'] = explanations
    result['explanationsai'] = explanationsai

    return result
