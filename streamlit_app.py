# -*- coding: utf-8 -*-
"""
Created on Wed Oct  2 12:38:53 2024

@author: sarathbabu.k.lv
"""
import warnings
warnings.filterwarnings('ignore')
import re
from langchain_community.document_loaders import PyPDFLoader
from langchain.docstore.document import Document 
from langchain.text_splitter import CharacterTextSplitter
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import FAISS
import streamlit as st
# import datetime
import google.generativeai as genai


def generate_response(gemini_api_key,prompt):
    txt = "You are called ARI: Audit Report Interpreter AI. You help to interpret Cybersecurity Audit Dcouments and provide appropriate results\n"
    prompt = txt+prompt
    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel(model_name="gemini-1.5-flash-latest") 
    response = model.generate_content(prompt)
    result = response.candidates[0].content.parts[0].text
    # result = result.replace("* ","")
    tokens = f"""completion_tokens: {response.usage_metadata.candidates_token_count}
\n\nprompt_tokens: {response.usage_metadata.prompt_token_count}
\n\ntotal_tokens: {response.usage_metadata.total_token_count}"""
    print(tokens)
    return result



@st.cache_resource(show_spinner=False)
def load_embed_model():
    hf = HuggingFaceEmbeddings(model_name = "sentence-transformers/all-MiniLM-L6-v2")
    return hf

def RAG(audit_file,prompt):
    file_path = (audit_file)
    loader = PyPDFLoader(file_path)
    pages = loader.load_and_split()

    docs=[]
    for i in range(len(pages)):
        to_embed = pages[i].page_content
        to_embed = re.sub("[^0-9a-zA-Z]"," ",to_embed)
        newDoc=Document(page_content=to_embed)
        docs.append(newDoc)
        
    text_splitter = CharacterTextSplitter(chunk_size=2000, chunk_overlap=0)
    docs = text_splitter.split_documents(docs)
    
    hf = load_embed_model()
    db = FAISS.from_documents(docs, hf)
    num_of_matches = 5
    results = db.similarity_search(prompt,k=num_of_matches)
    results = "\n".join([results[i].page_content for i in range(len(results))])
    return results

    
    

st.set_page_config(
    page_title="ARI: Audit Report Interpreter AI",
    page_icon=":mag:",
)


st.title(":mag: ARI: Audit Report Interpreter AI")

# page_bg_img = '''
# <style>
# .stApp{
# background-image: url("https://images.unsplash.com/photo-1542281286-9e0a16bb7366");
# background-size: cover;
# }
# </style>
# '''

# st.markdown(page_bg_img, unsafe_allow_html=True)

with st.sidebar:
    gemini_api_key = st.text_input("Enter your gemini api key here",type="password")
    #web_reports = [i for i in audit_files if 'web' in i.lower()]
    st.markdown(f"3 web application audit files")
    #app_reports = [i for i in audit_files if 'web' not in i.lower()]
    st.markdown(f"1 application audit files")
    #audit_file = st.selectbox("Choose the Audit File",['-']+audit_files)
    audit_file = st.file_uploader("Choose a file",type=['pdf'])
    
    # today = datetime.datetime.now()
    # one_month_before_today = today.month-1
    # one_month_before_today = datetime.date(today.year,today.month-1,1)
    
    # five_year_before = today.year-5
    # five_year_before = datetime.date(five_year_before,1,1)
    
    # d = st.date_input(
    #     "Select your datefilter",
    #     (one_month_before_today,today),
    #     five_year_before,today,
    #     format="DD.MM.YYYY")
    
    st.markdown(":white_check_mark: CVE 2024 report")
    st.markdown(":gray[CWE 2024 report]")
    st.markdown(":gray[NVD 2024 report]")
    st.markdown(":gray[OWASP 2024 report]")
    st.markdown(":gray[NIST 2024 report]")
    st.markdown(":gray[MITRE 2024 report]")
    # audit_file = st.selectbox("Choose the Audit File",['-']+audit_files)
    
    
    
    
        
    
# if audit_file!='-':
if audit_file is not None:
    st.markdown(f"{audit_file.name} is selected")
    

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat messages from history on app rerun
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        
        

# Accept user input
if prompt := st.chat_input("You can add your questions here"):
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})
    # Display user message in chat message container
    with st.chat_message("user"):
        st.markdown(prompt)
        print("<<<"+prompt)
    
    
    # Display assistant response in chat message container
    with st.chat_message("assistant"):
        assistant_response = "Please, enter you gemini api key"
        if gemini_api_key:
            with st.spinner("Generating Responses"): 
                # if audit_file!='-':
                if audit_file is not None:
                    context = RAG(audit_file.name,prompt)
                    prompt = "Information:\n"+context+"Question:\n"+prompt
                    print("<<<"+prompt)
                    
                assistant_response = generate_response(gemini_api_key,prompt)
                
        print(">>>"+assistant_response)
        
        
    # Add assistant response to chat history
    st.session_state.messages.append({"role": "assistant", "content": assistant_response})
    st.rerun()
