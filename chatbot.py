# === Importing necessary modules and libraries ===

# PyMongo - Required to create MongoDB client and handle interactions with MongoDB databases
from pymongo import MongoClient  # MongoDB client to connect and perform operations
import pymongo  # Additional PyMongo utilities (optional, if needed for specific features)

# OS module - Used for accessing environment variables and performing file path operations
import os  # Useful for working with the file system and .env configurations

# LangChain Embeddings - Used for converting text into numerical vectors for semantic search
from langchain_openai import OpenAIEmbeddings  # OpenAI embeddings for use in LangChain pipeline

# Vector Store - Chroma is a lightweight vector database used to store and retrieve embeddings
from langchain_community.vectorstores import Chroma  # Embedding-based document retrieval with Chroma

# Retrieval-Augmented Generation - Used to combine retrieval with LLMs for accurate QA
from langchain.chains import RetrievalQA  # Enables Retrieval + Question Answering chains

# Chat Model - Interface for OpenAI's chat-based LLMs within LangChain
from langchain_community.chat_models import ChatOpenAI  # OpenAI’s ChatGPT model for dialogue-based tasks

# Traceback - Captures and formats exception tracebacks for debugging purposes
import traceback  # Helps log and trace errors with full stack information

# Dotenv - Loads environment variables from a .env file into the Python environment
from dotenv import load_dotenv  # Reads and parses .env configuration files

# FuzzyWuzzy - Library for fuzzy string matching and similarity checking
from fuzzywuzzy import fuzz  # Used for approximate string comparison, such as intent detection

# Regular Expressions - Used for advanced pattern matching in strings
import re  # Provides regex tools for validating or manipulating text

# Load environment variables from the .env file
load_dotenv()

# MongoDB URI from environment variables to establish a connection to MongoDB
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Error: MONGODB_URI not defined in .env file")  # Raise an error if URI is not set

# Initialize MongoDB client with TLS encryption and certificate validation disabled
client = MongoClient(MONGODB_URI, tls=True, tlsAllowInvalidCertificates=True)

def initialize_qa_chain(business_id, top_3_matches, plan_type="free"):
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
    info_data = [f"Question: {q}\nAnswer: {a}\nProcedure path: {p}" for q, a, p in top_3_matches]
    
    if not info_data:
        return None  # If no info data is available, return None
    
    # Select max_tokens depending on plan type
    plan_configs = {
        "free": {
            "max_tokens": 500,
            "model": "gpt-3.5-turbo"
        },
        "standard": {
            "max_tokens": 750,
            "model": "gpt-3.5-turbo"
        },
        "professional": {
            "max_tokens": 1000,
            "model": "gpt-3.5-turbo"
        }
    }

    # Get settings from plan_type, or fallback to "free"
    config = plan_configs.get(plan_type.lower(), plan_configs["free"])
    max_tokens = config["max_tokens"]
    model_name = config["model"]

    # Initialize OpenAI embeddings using the API key from environment variables
    openai_api_key = os.getenv("OPENAI_API_KEY")
    embeddings = OpenAIEmbeddings(openai_api_key=openai_api_key)

    # Create a Chroma vector store to store info data as embeddings for search purposes
    vectorstore = Chroma.from_texts(
        texts=info_data,
        embedding=embeddings,
        persist_directory="chroma_storage"  # Directory to persist the embeddings
    )

    # Initialize the ChatOpenAI model using GPT-3.5-turbo for generating responses
    llm = ChatOpenAI(
        model=model_name,
        openai_api_key=openai_api_key,
        max_tokens=max_tokens
        )

    # Create a QA chain using the retrieval-augmented generation method
    qa_chain = RetrievalQA.from_chain_type(
        llm=llm,
        retriever=vectorstore.as_retriever(search_type="similarity", search_kwargs={"k": 3}),
        # retriever=vectorstore.as_retriever(),
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

def ask_question(question, business_id):
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
        info_collection = db[f"{business_id}info"] # Access the specific collection for the given business ID
        cleaned_question = clean_text(question) # Clean the incoming question to ensure consistent format
        # Search for the question in the database using regex (case-insensitive match)
        question_data = info_collection.find_one({
            "question": {"$regex": cleaned_question, "$options": "i"}
        })

        if question_data:
            return {"answer": question_data.get("answer", "Answer not found.")} # If a direct match is found, return the associated answer

        all_questions = list(info_collection.find({}, {"_id": 0})) # Retrieve all questions from the collection

        if not all_questions:
            return {"answer": question_data.get("answer", "No questions found in the database.")}
        
        matches = []

        # Perform fuzzy matching using the FuzzyWuzzy library
        for doc in all_questions:
            question_from_db = clean_text(doc["question"])  # Clean the question from the database
            score = fuzz.ratio(cleaned_question, question_from_db)  # Calculate the fuzzy match score

            matches.append({
                "question": doc.get("question", "Unknown question"),
                "answer": doc.get("answer", "Answer not found."),
                "procedure_path": doc.get("procedure_path", "Path not found."),
                "score": score
            })

        matches.sort(key=lambda x: x["score"], reverse=True) # Sort the matches by score in descending order to get the most relevant ones
        top_3_matches = [(match["question"], match["answer"], match["procedure_path"]) for match in matches[:3]] # Select the top 3 matches

        # === Fetch the user plan type from MongoDB ===
        business_collection = db["{}".format(business_id)]
        user_data = business_collection.find_one({"username": "businessidadmin"})
        plan_type = user_data.get("plantype", "free") if user_data else "free"

        # Call the QA chain with the top 3 matches
        qa_chain = initialize_qa_chain(business_id, top_3_matches, plan_type=plan_type)
        if qa_chain:
            # Invoke the QA chain with the question and get the response
            response = qa_chain.invoke({"query": question})
            answer = response["result"]
            return {"answer": answer}

        # If no match found after fuzzy search, return a default response
        return {"answer": "Sorry, I couldn't find an answer to your question."}

    except Exception as e:
        # Log error details if something goes wrong
        return {"answer": "Sorry, there was an error processing your question."}