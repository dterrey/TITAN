#timesketch_client.py

import pandas as pd
from timesketch_api_client import client, search
from flask import current_app

def connect_timesketch():
    ts_client = client.TimesketchApi('http://localhost', username='triagex', password='admin')
    sketch_id = 4  # Update this to your sketch ID
    
    try:
        sketch = ts_client.get_sketch(sketch_id)
        search_obj = search.Search(sketch=sketch)
        search_obj.query_string = "message:test"
        search_obj.table  # Execute the query to check the connection
        print("Successfully connected to Timesketch.")
        return ts_client, sketch
    except Exception as e:
        print(f"Failed to connect to Timesketch: {e}")
        return None, None

def search_and_tag_iocs_in_timesketch(ioc_indicator, tag):
    ts_client, sketch = connect_timesketch()

    if not sketch:
        print("Failed to connect to Timesketch. Exiting.")
        return

    # Use the same query structure as before but with the new Search object
    search_obj = search.Search(sketch=sketch)
    query = f'message:"{ioc_indicator}"'
    print(f"Running query: {query}")
    
    search_obj.query_string = query
    search_results = search_obj.to_dict()  # Convert results to dictionary format
    
    # Check if the search results are valid
    if 'objects' in search_results and len(search_results['objects']) > 0:
        events_to_tag = []
        for event in search_results['objects']:
            event_id = event.get('_id')
            index_id = event.get('_index')

            print(f"Processing event ID: {event_id} with index: {index_id}")

            if event_id and index_id:
                try:
                    # Fetch event details using the event ID and index
                    event_details = sketch.get_event(event_id=event_id, index_id=index_id)
                    existing_tags = event_details.get('tag', [])

                    # Only add the tag if it's not already present
                    if tag not in existing_tags:
                        events_to_tag.append({
                            '_id': event_id,
                            '_index': index_id
                        })
                except Exception as e:
                    print(f"Error retrieving event details for {event_id}: {e}")
                    continue

        # Tag all relevant events
        if events_to_tag:
            sketch.tag_events(events_to_tag, [tag])
            print(f"Tagged {len(events_to_tag)} events with tag '{tag}' for IOC '{ioc_indicator}'")
        else:
            print(f"No new tags were applied for IOC '{ioc_indicator}'; all relevant events are already tagged.")

        # **This part ensures that we fetch the total number of tagged events after tagging**
        total_tagged_events = fetch_total_tagged_events(tag)
        print(f"Total number of events tagged with '{tag}': {total_tagged_events}")

        return {
            "tagged_count": len(events_to_tag),
            "total_tagged_events": total_tagged_events
        }

    else:
        print(f"No events found for IOC '{ioc_indicator}'.")
        return {
            "tagged_count": 0,
            "total_tagged_events": 0
        }

def remove_ioc_or_tag(ioc, tag_to_remove, remove_ioc=False):
    ts_client, sketch = connect_timesketch()

    if not sketch:
        print("Failed to connect to Timesketch. Exiting.")
        return

    try:
        # Search for events with the specified tag
        query = f'tag:"{tag_to_remove}"'
        print(f"Running query to find events with the tag: {tag_to_remove}")
        search_obj = search.Search(sketch=sketch)
        search_obj.query_string = query
        search_results = search_obj.table
        events_df = pd.DataFrame(search_results)

        if events_df.empty:
            print(f"No events found with the tag '{tag_to_remove}'.")
            return f"Failed to remove IOCs: {tag_to_remove}"

        events_to_update = []
        for _, event in events_df.iterrows():
            event_id = event['_id']
            index_id = event['_index']

            # Retrieve event details to check existing tags
            event_obj = sketch.get_event(event_id=event_id, index_id=index_id)
            existing_tags = event_obj.get('objects', {}).get('tag', [])

            # If the tag is present, add to the list for removal
            if tag_to_remove in existing_tags:
                events_to_update.append({'_id': event_id, '_index': index_id})

        # Remove the tag in batches of 500
        if events_to_update:
            batch_size = 500  # Maximum allowed per request
            total_events = len(events_to_update)
            for i in range(0, total_events, batch_size):
                batch = events_to_update[i:i + batch_size]
                sketch.untag_events(batch, [tag_to_remove])
                print(f"Removed tag '{tag_to_remove}' from batch {i // batch_size + 1}")
            print(f"Successfully removed the tag '{tag_to_remove}' from {len(events_to_update)} events.")
        else:
            print("No tags were removed; all relevant tags are already absent.")

        # If the remove_ioc flag is True, remove the IOC from the table
        if remove_ioc:
            # Code to remove the IOC from your database or table
            # Example: remove from your database here
            print(f"Removed IOC '{ioc}' from the IOC table.")
            # Add your logic to remove the IOC from the table/database here.
            return f"Removed IOC and tag: {ioc}"
        else:
            print(f"Removed tag '{tag_to_remove}' without removing the IOC.")
            return f"Removed tag only: {tag_to_remove}"

    except Exception as e:
        print(f"An unexpected error occurred while removing tags: {e}")
        return f"Failed to remove tag: {tag_to_remove}"

def fetch_total_tagged_events(tag):
    """Fetch the total number of events tagged with a specific tag in Timesketch."""
    ts_client, sketch = connect_timesketch()

    if not sketch:
        print("Failed to connect to Timesketch. Exiting.")
        return 0

    # Query Timesketch for events with the specific tag
    query = f'tag:"{tag}"'  # Use the tag instead of the IOC indicator
    search_obj = search.Search(sketch=sketch)
    search_obj.query_string = query

    try:
        search_results = search_obj.to_dict()  # Fetch results as a dictionary
        print(f"Raw search results for tag '{tag}': {search_results}")  # Debug: Print raw response
        total_events = len(search_results.get('objects', []))  # Count the events found
        print(f"Found {total_events} events tagged with '{tag}'.")
        return total_events
    except Exception as e:
        print(f"Error fetching events for tag '{tag}': {e}")
        return 0
