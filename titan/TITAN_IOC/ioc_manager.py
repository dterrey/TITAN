import json

def parse_ioc_file(file):
    # Example logic to parse an IOC file (STIX, JSON, etc.)
    ioc_data = []
    file_content = file.read().decode('utf-8')
    data = json.loads(file_content)
    for item in data['indicators']:
        ioc_data.append({'indicator': item['pattern'], 'type': item['type']})
    return ioc_data
