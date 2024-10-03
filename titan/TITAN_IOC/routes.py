from app import app  # Import the app instance
from flask import render_template, request, redirect
from models import IOC, db
from timesketch_client import search_timesketch
from ioc_manager import parse_ioc_file

@app.route('/')
def index():
    iocs = IOC.query.all()
    return render_template('index.html', iocs=iocs)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['ioc_file']
        ioc_data = parse_ioc_file(file)
        for ioc in ioc_data:
            new_ioc = IOC(indicator=ioc['indicator'], type=ioc['type'])
            db.session.add(new_ioc)
        db.session.commit()
        return redirect('/')
    return render_template('upload.html')

@app.route('/search', methods=['POST'])
def search():
    ioc = request.form['ioc']
    results = search_timesketch(ioc)
    return render_template('results.html', results=results)

@app.route('/tag', methods=['POST'])
def tag_event():
    event_id = request.form['event_id']
    tag = request.form['tag']
    # Tag event in Timesketch
    timesketch_client.tag_event(event_id, tag)
    return redirect('/results')
