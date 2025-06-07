#!/bin/bash
python -m spacy download en_core_web_lg
python -c "import nltk; nltk.download('punkt')"
