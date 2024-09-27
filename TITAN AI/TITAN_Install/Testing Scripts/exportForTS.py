#Custom TS Template that works. - Command to execute - python3 zircolite.py --evtx /home/triagex/Downloads/Logs/ --ruleset /opt/Zircolite-2.20.0/rules/rules_windows_generic_full.json --template /opt/Zircolite-2.20.0/templates/exportForTS.tmpl --templateOutput /home/triagex/Downloads/datanewnew.jsonl --debug

{% for elem in data %}{% for match in elem["matches"] %}{"title":{{ elem["title"]|tojson }},"id":{{ elem["id"]|tojson }},"description":{{ elem["description"]|tojson }},"tags":{{ elem["tags"]|tojson }},"message":{{ elem["title"]|tojson }},"timestamp_desc":{{ elem["rule_level"]|tojson }},{% for key, value in match.items() %}"{{ key }}":{{ value|tojson }}{%if key == "SystemTime"%},"datetime":{{ value|tojson }}{% endif %}{{ "," if not loop.last }}{% endfor %}}
{% endfor %}{% endfor %}
