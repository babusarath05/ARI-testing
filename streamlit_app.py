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

cve_report = '{"vendor":{"0":"MITRE","1":"MITRE","2":"MITRE","3":"MITRE","4":"MITRE","5":"MITRE","6":"Solidigm","7":"Solidigm","8":"Solidigm","9":"Solidigm","10":"Solidigm","11":"Solidigm","12":"Solidigm","13":"Solidigm","14":"Solidigm","15":"JetBrains s.r.o.","16":"JetBrains s.r.o.","17":"JetBrains s.r.o.","18":"JetBrains s.r.o.","19":"MITRE","20":"MITRE","21":"MITRE","22":"MITRE","23":"MITRE","24":"MITRE"},"epss":{"0":"Not Available","1":"Not Available","2":"Not Available","3":"Not Available","4":"Not Available","5":"Not Available","6":"0.04%","7":"0.04%","8":"0.04%","9":"0.04%","10":"0.04%","11":"0.04%","12":"0.04%","13":"0.04%","14":"0.04%","15":"0.04%","16":"0.04%","17":"0.04%","18":"0.04%","19":"0.04%","20":"0.04%","21":"0.05%","22":"0.04%","23":"0.04%","24":"0.05%"},"cvss":{"0":"Not Available","1":"Not Available","2":"Not Available","3":"Not Available","4":"Not Available","5":"Not Available","6":"6.7","7":"7.0","8":"4.4","9":"5.1","10":"4.0","11":"6.5","12":"6.2","13":"4.4","14":"10.0","15":"3.5","16":"3.5","17":"4.9","18":"4.9","19":"Not Available","20":"6.7","21":"7.2","22":"Not Available","23":"6.1","24":"7.5"},"publish_date":{"0":"2024-10-10","1":"2024-10-10","2":"2024-10-10","3":"2024-10-09","4":"2024-10-09","5":"2024-10-09","6":"2024-10-07","7":"2024-10-07","8":"2024-10-07","9":"2024-10-07","10":"2024-10-07","11":"2024-10-07","12":"2024-10-07","13":"2024-10-07","14":"2024-10-07","15":"2024-10-08","16":"2024-10-08","17":"2024-10-08","18":"2024-10-08","19":"2024-10-04","20":"2024-10-04","21":"2024-10-04","22":"2024-10-04","23":"2024-10-04","24":"2024-10-04"}}'

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
    st.markdown(f"0 web application audit files present")
    #app_reports = [i for i in audit_files if 'web' not in i.lower()]
    st.markdown(f"0 application audit files present")
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
        # print("<<<"+prompt)
    
    
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
                else:
                    cve_report = load_cve_data()
                    prompt+="\n\nThe following is the Security vulnerabilities CVE report published in 2024:\n"+cve_report+"\n"
                    print("<<<"+prompt)
                    
                assistant_response = generate_response(gemini_api_key,prompt)
                
        print(">>>"+assistant_response)
        
        
    # Add assistant response to chat history
    st.session_state.messages.append({"role": "assistant", "content": assistant_response})
    st.rerun()
