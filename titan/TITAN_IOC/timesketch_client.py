from timesketch_api_client import client, search

def connect_timesketch():
    # Replace these values with your actual Timesketch connection details
    ts_client = client.TimesketchApi('http://localhost', username='triagex', password='admin')
    sketch_id = 4  # Update this to your sketch ID
    
    # Test the connection to Timesketch
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

# Function to search and tag IOCs in Timesketch
def search_and_tag_iocs_in_timesketch():
    ts_client, sketch = connect_timesketch()

    if not sketch:
        print("Failed to connect to Timesketch. Exiting.")
        return

    iocs = IOC.query.all()  # Assuming IOC is a model defined in your database

    for ioc in iocs:
        query = f'message:"{ioc.indicator}"'
        search_obj = search.Search(sketch=sketch)
        search_obj.query_string = query

        try:
            search_results = search_obj.table
            if len(search_results) > 0:
                events_to_tag = []
                for event in search_results:
                    event_id = event['_id']
                    index_id = event['_index']

                    event_details = sketch.get_event(event_id=event_id, index_id=index_id)
                    existing_tags = event_details.get('tag', [])

                    if ioc.tag not in existing_tags:
                        events_to_tag.append({
                            '_id': event_id,
                            '_index': index_id
                        })

                if events_to_tag:
                    sketch.tag_events(events_to_tag, [ioc.tag])
                    print(f"Tagged {len(events_to_tag)} events with tag '{ioc.tag}' for IOC '{ioc.indicator}'")
                else:
                    print(f"No new tags were applied for IOC '{ioc.indicator}'; all relevant events are already tagged.")
            else:
                print(f"No events found for IOC '{ioc.indicator}'.")

        except Exception as e:
            print(f"An error occurred while querying or tagging IOC '{ioc.indicator}': {e}")

    return "IOC search and tagging completed."
