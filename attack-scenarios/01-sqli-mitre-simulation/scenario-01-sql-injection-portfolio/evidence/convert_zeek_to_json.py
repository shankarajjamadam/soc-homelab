import json
import sys

def convert_zeek_log(input_file, output_file):
    with open(input_file) as infile, open(output_file, 'w') as outfile:
        headers = []
        for line in infile:
            line = line.strip()
            if line.startswith('#fields'):
                headers = line.split('\t')[1:]
            elif line.startswith('#'):
                continue
            else:
                values = line.split('\t')
                row = dict(zip(headers, values))
                outfile.write(json.dumps(row) + '\n')

# Convert files
convert_zeek_log('/home/shankar/zeek-output/scenario1-sqli/conn.log', 
                 '/home/shankar/zeek-output/scenario1-sqli/conn_json.log')
convert_zeek_log('/home/shankar/zeek-output/scenario1-sqli/http.log', 
                 '/home/shankar/zeek-output/scenario1-sqli/http_json.log')

print("Conversion complete")
