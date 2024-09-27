# -----------------------------------------------------------------------------
# TITAN (Threat Investigation and Tactical Analysis Network)
# Created by: [David Terrey - https://www.linkedin.com/in/david-terrey-a06b1312/]
# Copyright (c) 2024 [David Terrey - https://www.linkedin.com/in/david-terrey-a06b1312/]
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------

import os
import re
import json
import pandas as pd
import PyPDF2
import docx
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer as SumyTokenizer
from sumy.summarizers.lsa import LsaSummarizer
import logging

def parse_sigma_rule(rule_path):
    with open(rule_path, 'r') as file:
        rule = yaml.safe_load(file)
    return rule

def extract_text_from_pdf(file_path):
    with open(file_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        text = ""
        for page in reader.pages:
            text += page.extract_text()
    return text

def extract_text_from_docx(file_path):
    doc = docx.Document(file_path)
    return "\n".join([para.text for para in doc.paragraphs])

def summarize_text(text):
    parser = PlaintextParser.from_string(text, SumyTokenizer("english"))
    summarizer = LsaSummarizer()
    summary = summarizer(parser.document, 6)  # Summarize to 6 sentences
    return " ".join([str(sentence) for sentence in summary])

def export_to_jsonl(data, output_file):
    with open(output_file, 'w') as outfile:
        for event in data:
            json.dump(event, outfile)
            outfile.write('\n')

def parse_datetime_column(df, column_name):
    try:
        df[column_name] = pd.to_datetime(df[column_name], utc=True, errors='raise')
    except Exception as e:
        logging.error(f"Error parsing datetime column '{column_name}': {e}")
        df[column_name] = pd.NaT
    return df

