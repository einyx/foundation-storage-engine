#!/usr/bin/env python3

with open('test-metadata.json', 'rb') as f:
    data = f.read()
    # Find JSON start and end
    start = data.find(b'{')
    end = data.rfind(b'}') + 1
    if start != -1 and end > start:
        json_data = data[start:end]
        with open('cleaned.json', 'wb') as out:
            out.write(json_data)
        print(f'Extracted JSON from byte {start} to {end}')
    else:
        print('Could not find valid JSON boundaries')
