import xml.etree.ElementTree as ET
from datetime import datetime
import dateparser
import sys
import re
import os
from timezonefinder import TimezoneFinder
from math import radians, sin, cos, sqrt, atan2
import requests

# google_maps_api_key = "AIzaSyC3DKDM2DYwtnMdh1chNe_kIk1tHSQV27Q"
google_maps_api_key = "AIzaSyA4413GL0OX12jQv2gXJC88sIh0N-__4f0"

meassures_per_second = 2


def parse_kml(file_path):
    # try:
        data = {}

        tree = ET.parse(file_path)
        root = tree.getroot()

        coordinates = []
        for elem in root.iter():
            if 'name' in elem.tag:
                if (re.match(r'^Track .*', elem.text)):
                    match = re.search(r"Track (.*) .*?, (.*?) (\d\d:\d\d:\d\d)", elem.text)
                    flightUser = match.group(1)
                    flightDate = dateparser.parse(match.group(2)).date()
                    flightTime = dateparser.parse(match.group(3)).time()
                        
                    data['user'] = flightUser
                    data['date'] = str(flightDate)
                    data['time'] = str(flightTime)

            if 'coordinates' in elem.tag:
                for line in elem.text.splitlines():
                    templist = []
                    if line.strip() != "":
                        for coordinate in line.split(','):
                            templist.append(float(coordinate.strip()))
                        coordinates.append(templist)
            # print(coordinates)


        # # add the coordinates to the return
        # data['coordinates'] = coordinates

        # tzfinder = TimezoneFinder() 
        # tz = tzfinder.timezone_at(lng=coordinates[0][0], lat=coordinates[0][1])
        # data['timezone'] = tz
                        


        lat1 = 46.7225024
        lon1 = 8.1969395
        lat2 = 46.7272347
        lon2 = 8.1844957

        R = 6371000.0
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
        c = 2 * atan2(sqrt(a), sqrt(1 - a))
        distance = R * c








        endpoint = "https://maps.googleapis.com/maps/api/timezone/json"
        params = {
            'location': f'{str(coordinates[0][0])},{str(coordinates[0][1])}',
            'key': google_maps_api_key,
            'timestamp': '1679940199'
        }
        print(params)
        response = requests.get(endpoint, params=params)
        print(response.text)



        country = None
        location = None
        location_types = ["sublocality", "locality", "administrative_area_level_3", "administrative_area_level_2","administrative_area_level_1", None]
        current_location_type = None
        endpoint = "https://maps.googleapis.com/maps/api/geocode/json"
        params = {
            # 'latlng': f'{latitude},{longitude}',
            'latlng': str(coordinates[0][0])+","+str(coordinates[0][1]),
            'key': google_maps_api_key,
        }
        response = requests.get(endpoint, params=params)
        # print(response.text)
        if response.status_code == 200:
            googleData = response.json()
            for result in googleData['results']:
                for address_components in result['address_components']:
                    if not country and "country" in address_components['types']:
                        country = address_components['long_name']
                    # if address_components['types'][0] in location_types:
                    if set(address_components['types']) & set(location_types):
                        matching_type = next(iter(set(address_components['types']) & set(location_types)))
                        if location_types.index(matching_type) < location_types.index(current_location_type):
                            # print(address_components['types'][0])
                            current_location_type = matching_type
                            location = address_components['long_name']
        else:
            return {'code':10, 'message':'There was an error while fetching the results from the google API'}
        
        data['country'] = country
        data['location'] = location





        data['meassure_points'] = len(coordinates)

        data['code'] = 0
        data['message'] = "Everything fine"
        return data
        
    # except Exception as e:
    #     print(e)
        # return {'code':90, 'message':'There was an error while proccessing the kml files'}




if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_kml_file>")
    else:
        file_path = sys.argv[1]
        if (os.path.isfile(file_path)):
            temp = parse_kml(file_path)
            print(temp)
        else:
            print("file not found")
