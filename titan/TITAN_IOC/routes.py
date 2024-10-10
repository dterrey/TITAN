from flask import request, redirect, render_template, flash, jsonify
from app import app, db
from models import IOC
from datetime import datetime
import re
from timesketch_client import search_and_tag_iocs_in_timesketch, remove_ioc_or_tag

@app.route('/')
def index():
    iocs = IOC.query.all()
    return render_template('index.html', iocs=iocs)

def identify_ioc_type(ioc):
    # IPv4 regex
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc):
        return "IP"
    # SHA256 hash regex (64 hexadecimal characters)
    elif re.match(r"^[0-9a-fA-F]{64}$", ioc):
        return "Hash"
    # URL regex
    elif re.match(r"^https?:\/\/", ioc):
        return "URL"
    # Domain regex
    elif re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", ioc):
        return "Domain"
    else:
        return "Filename"

@app.route('/add_iocs', methods=['POST'])
def add_iocs():
    ioc_data = request.form['ioc_data']
    tag = request.form['tag']
    ioc_list = [ioc.strip() for ioc in re.split(r',|\n', ioc_data) if ioc.strip()]

    for ioc in ioc_list:
        ioc_type = identify_ioc_type(ioc)
        new_ioc = IOC(indicator=ioc, type=ioc_type, timestamp=datetime.now(), tag=tag)
        db.session.add(new_ioc)

    db.session.commit()  # Commit once, after adding all the IOCs to the database

    # Now pass all the IOCs to the Timesketch tagging function
    results = []
    for ioc in ioc_list:
        result = search_and_tag_iocs_in_timesketch(ioc, tag)
        results.append(result)
    
    # Flash messages only after everything is done
    flash(f"IOCs added and tagged in Timesketch: {results}")

    return redirect('/')

@app.route('/gohunt', methods=['POST'])
def go_hunt():
    data = request.json
    selected_iocs = data.get('selected_iocs', [])
    tagged_count = 0
    errors = []

    for ioc_id in selected_iocs:
        ioc = IOC.query.get(ioc_id)
        if ioc:
            try:
                # Pass the tag for each IOC (assuming the tag is stored with the IOC in the database)
                result = search_and_tag_iocs_in_timesketch(ioc.indicator, ioc.tag)
                if result.startswith("Tagged"):
                    tagged_count += 1
                else:
                    errors.append(f"Failed to tag {ioc.indicator}")
            except Exception as e:
                errors.append(str(e))

    return jsonify({
        'tagged_count': tagged_count,
        'errors': errors
    })


# Route to remove IOCs and their tags
@app.route('/delete_iocs', methods=['POST'])
def delete_iocs():
    data = request.json  # Expecting JSON data from front-end
    selected_iocs = data.get('selected_iocs', [])
    successful_removals = []
    failed_removals = []

    for ioc_id in selected_iocs:
        ioc = IOC.query.get(ioc_id)
        if ioc:
            try:
                # Remove the tag and the IOC from the table
                result = remove_ioc_or_tag(ioc.indicator, ioc.tag, remove_ioc=True)
                if "Removed IOC and tag" in result:
                    # After successfully removing from Timesketch, delete the IOC from the database
                    db.session.delete(ioc)
                    db.session.commit()  # Commit deletion of each IOC
                    successful_removals.append(ioc.indicator)
                else:
                    failed_removals.append(ioc.indicator)
            except Exception as e:
                failed_removals.append(ioc.indicator)
                print(f"Error removing IOC {ioc.indicator}: {e}")

    return jsonify({
        'success': successful_removals,
        'failed': failed_removals
    })
    
@app.route('/change_tag', methods=['POST'])
def change_tag():
    data = request.json  # Expecting JSON data from front-end
    selected_iocs = data.get('selected_iocs', [])
    new_tag = data.get('new_tag', '')

    for ioc_id in selected_iocs:
        ioc = IOC.query.get(ioc_id)
        if ioc:
            ioc.tag = new_tag
            db.session.commit()
            # Trigger tagging in Timesketch here if necessary
            search_and_tag_iocs_in_timesketch(ioc.indicator, new_tag)

    flash(f"Tag '{new_tag}' applied to selected IOCs.")
    return jsonify({'message': f"Tag '{new_tag}' applied"})  # JSON response

# Route to remove tags from IOCs but keep the IOC in the table
@app.route('/remove_tag', methods=['POST'])
def remove_tag():
    data = request.json  # Expecting JSON data from front-end
    selected_iocs = data.get('selected_iocs', [])
    successful_removals = []
    failed_removals = []

    for ioc_id in selected_iocs:
        ioc = IOC.query.get(ioc_id)
        if ioc and ioc.tag:  # Check if the tag exists
            try:
                # Remove the tag but keep the IOC in the table
                result = remove_ioc_or_tag(ioc.indicator, ioc.tag, remove_ioc=False)
                if "Removed tag" in result:
                    ioc.tag = None  # Set the tag to None in the database
                    db.session.commit()
                    successful_removals.append(ioc.indicator)
                else:
                    failed_removals.append(ioc.indicator)
            except Exception as e:
                failed_removals.append(ioc.indicator)

    return jsonify({
        'success': successful_removals,
        'failed': failed_removals
    })
    
# Helper function to verify that the tag was removed from Timesketch
def verify_removal_from_timesketch(tag):
    ts_client, sketch = connect_timesketch()

    if not sketch:
        print("Failed to connect to Timesketch.")
        return -1  # Return -1 on failure

    query = f'tag:"{tag}"'
    try:
        search_obj = sketch.explore(query_string=query)
        search_results = search_obj.to_dict()
        return len(search_results['objects'])  # Return the number of remaining events
    except Exception as e:
        print(f"Error querying Timesketch: {e}")
        return -1  # Return -1 on failure
    
@app.route('/get_updated_table')
def get_updated_table():
    iocs = IOC.query.all()  # Fetch the updated IOC data from the database
    return render_template('partials/ioc_table_body.html', iocs=iocs)  # Render only the table rows
