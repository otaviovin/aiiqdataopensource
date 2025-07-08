# === Importing necessary modules and libraries ===

# PyMongo - Required to connect and interact with MongoDB databases
from pymongo import MongoClient  # MongoDB client to perform operations on MongoDB
import pymongo  # Additional tools from PyMongo for database management

# OS module - Used to interact with the operating system (e.g., environment variables, file paths)
import os  # For managing environment variables and file system paths

# LangChain - OpenAI Embeddings are used to convert text into vector representations
from langchain_openai import OpenAIEmbeddings  # Embedding model for semantic search and vectorization

# LangChain - Chroma is a vector store for saving and retrieving embedded documents
from langchain_community.vectorstores import Chroma  # Vector database for document retrieval

# LangChain - RetrievalQA combines a retriever with a language model for question answering
from langchain.chains import RetrievalQA  # Enables building retrieval-based QA pipelines

# LangChain - Provides access to OpenAI's chat models (e.g., GPT-4) in a conversational format
from langchain_community.chat_models import ChatOpenAI  # ChatGPT model integration for AI interactions

# Traceback - Helps in logging the stack trace when an exception occurs
import traceback  # Used for debugging and tracking errors during execution

# Dotenv - Loads environment variables from a .env file into the runtime environment
from dotenv import load_dotenv  # Ensures sensitive config is securely loaded from .env files

# FuzzyWuzzy - A library for performing approximate/fuzzy string comparisons
from fuzzywuzzy import fuzz  # Used for intent recognition or text similarity checking

# Regular Expressions - For advanced pattern matching and string validation
import re  # Regex library used to match, extract or validate specific text patterns

# Load environment variables from the .env file
load_dotenv()

# MongoDB URI from environment variables to establish a connection to MongoDB
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Error: MONGODB_URI not defined in .env file")  # Raise an error if URI is not set

# Initialize MongoDB client with TLS encryption and certificate validation disabled
client = MongoClient(MONGODB_URI, tls=True, tlsAllowInvalidCertificates=True)

# Define databases
db_main = client['businessinfo'] 
db_business = client['businessdata'] 
csv_collection = db_business["csv_files"] 

def initialize_qa_chain(business_id, final_answer):
    """
    Initializes a question and answer (QA) chain based on the top 3 best matches from the info data.
    It sets up the necessary embeddings and model for further question answering.
    
    Args:
    business_id (str): The unique identifier for the business (from the session).
    top_3_matches (list): A list of tuples containing the top 3 matching questions, answers, and procedure paths.

    Returns:
    qa_chain (RetrievalQA): The initialized QA chain object for question answering.
    """
    if not business_id:
        raise ValueError("Business ID not found in session.")  # Check if business ID is valid
    
    # Prepare info data from the top 3 matches (question, answer, procedure path)
    info_data = [final_answer]
    
    if not info_data:
        return None  # If no info data is available, return None

    # Initialize OpenAI embeddings using the API key from environment variables
    openai_api_key = os.getenv("OPENAI_API_KEY")
    embeddings = OpenAIEmbeddings(openai_api_key=openai_api_key)

    # Create a Chroma vector store to store info data as embeddings for search purposes
    vectorstore = Chroma.from_texts(
        texts=[final_answer],
        embedding=embeddings,
        persist_directory="chroma_storage"  # Directory to persist the embeddings
    )

    # Initialize the ChatOpenAI model using GPT-3.5-turbo for generating responses
    llm = ChatOpenAI(
        model="gpt-3.5-turbo",
        openai_api_key=openai_api_key,
        max_tokens=1000
    )

    # Create a QA chain using the retrieval-augmented generation method
    qa_chain = RetrievalQA.from_chain_type(
        llm=llm,
        retriever=vectorstore.as_retriever(search_type="similarity", search_kwargs={"k": 3}),
        return_source_documents=True  # Return the documents that were used to generate the answer
    )

    return qa_chain  # Return the initialized QA chain

def clean_text(text):
    """
    Cleans the input text by removing punctuation, converting it to lowercase, and trimming whitespace.
    This function normalizes the input text to make it consistent for searching and comparisons.

    Args:
    text (str): The input text that needs to be cleaned.

    Returns:
    str: The cleaned text.
    """
    text = text.lower()  # Convert text to lowercase
    text = re.sub(r'[^\w\s]', '', text)  # Remove punctuation and special characters
    text = re.sub(r'\s+', ' ', text)  # Replace multiple spaces with a single space
    text = text.strip()  # Remove any leading or trailing whitespace
    return text

def ask_question_data(question, business_id):
    """
    Processes a question and returns the appropriate answer based on the info data in MongoDB.
    If no exact match is found, it performs a fuzzy match to find the most relevant answer.
    
    Args:
    question (str): The question to be processed and answered.
    business_id (str): The unique identifier for the business (from the session).

    Returns:
    dict: A dictionary containing the answer to the question.
    """
    try:
        # Verify that MongoDB URI is correctly set in environment variables
        mongo_uri = os.getenv("MONGODB_URI")
        if not mongo_uri:
            raise ValueError("Error: MONGODB_URI not defined in .env file")  # Raise error if MongoDB URI is missing

        client = pymongo.MongoClient(mongo_uri)  # Connect to MongoDB using the URI
        db = client["businessdata"]  # Access the 'businessdata' database where collections are stored

        # Log the database being searched
        print(f"Searching in the database: businessdata")
        
        # List all collections in the 'businessdata' database
        print(f"Collections in businessdata database: {db.list_collection_names()}")

        # Access the specific collection for the given business ID
        info_collection = db[f"{business_id}csv"]
        print(f"Using collection: {business_id}csv")

        # Clean the incoming question to ensure consistent format
        cleaned_question = clean_text(question)
        print(f"Received question (cleaned): {cleaned_question}")

        result_info_collection = info_collection.find_one(
            {},  # Optionally add filters
            {
                "_id": 0,  # Exclude _id
                "charts": 1,
                "explanations": 1,
                "explanationsai": 1,
                "summary": 1
            },
            sort=[("created_at", -1)]  # Get the most recent one
        )
        print(f"Result (result_info_collection): {result_info_collection}")

        if not result_info_collection:
            return {"answer": "Sorry, no analytical data was found for this business."}
        
        charts = result_info_collection.get("charts", [])
        explanations = result_info_collection.get("explanations", [])
        explanationsai = result_info_collection.get("explanationsai", [])
        summary = result_info_collection.get("summary", "Summary not available.")

        response_parts = []

        # Limita o resumo a 500 caracteres
        response_parts.append("**Data Analysis Summary:**\n")
        response_parts.append(summary[:500] + ("..." if len(summary) > 500 else ""))

        # Limita a exibição a no máximo 3 interpretações
        response_parts.append("\n\n**Charts and Interpretations:**")
        for i, (chart, expl, expl_ai) in enumerate(zip(charts, explanations, explanationsai), 1):
            if i > 3:  # limitar a 3 interpretações
                break
            response_parts.append(f"\n\n**Interpretation {i}:**")
            if expl:
                short_expl = expl[:300] + ("..." if len(expl) > 300 else "")
                response_parts.append(f"- Manual Explanation: {short_expl}")
            if expl_ai:
                short_ai = expl_ai[:300] + ("..." if len(expl_ai) > 300 else "")
                response_parts.append(f"- AI Insight: {short_ai}")

        final_answer = "\n".join(response_parts)
        print(f"ResFinal answer (final_answer): {final_answer}")

        # Call the QA chain with the answer
        qa_chain = initialize_qa_chain(business_id, final_answer)

        if qa_chain:
            # Invoke the QA chain with the question and get the response
            response = qa_chain.invoke({"query": cleaned_question})
            answer = response["result"]
            print("Response (response) generated by the chatbot:", response)
            print("Response (answer) generated by the chatbot:", answer)
            return {"answer": answer}

        # If no match found after fuzzy search, return a default response
        print(f"No match found after fuzzy search.")
        return {"answer": "Sorry, I couldn't find an answer to your question."}

    except Exception as e:
        # Log error details if something goes wrong
        print(f"Error processing the question: {e}")
        print("Error details:", traceback.format_exc())  # Print full traceback for debugging
        return {"answer": "Sorry, there was an error processing your question."}
