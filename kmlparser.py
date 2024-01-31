import xml.etree.ElementTree as ET
from datetime import datetime
import dateparser
import sys
import re
import os
from timezonefinder import TimezoneFinder
import geocoder
import requests

google_maps_api_key = "AIzaSyC3DKDM2DYwtnMdh1chNe_kIk1tHSQV27Q"

meassures_per_second = 2


def parse_kml(file_path):
    # try:
        data = {}

        tree = ET.parse(file_path)
        root = tree.getroot()

        for elem in root.iter():
            coordinates = []
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


        # # add the coordinates to the return
        # data['coordinates'] = coordinates

        tzfinder = TimezoneFinder() 
        tz = tzfinder.timezone_at(lng=coordinates[0][0], lat=coordinates[0][1])
        data['timezone'] = tz




        endpoint = "https://maps.googleapis.com/maps/api/geocode/json"
        params = {
            # 'latlng': f'{latitude},{longitude}',
            'latlng': '70.978620,88.041456',
            'key': google_maps_api_key,
        }
        response = requests.get(endpoint, params=params)
        if response.status_code == 200:
            googleData = response.json()
            for result in googleData['results']:
                for address_components in result['address_components']:
                    print(address_components['short_name'])
        else:
            return {'code':10, 'message':'There was an error while fetching the results from the google API'}

        # # g = geocoder.google([coordinates[0][0], coordinates[0][1]], method='reverse', key=google_maps_api_key)
        # g = geocoder.google([2.7549691, -71.6716367], method='reverse', key=google_maps_api_key)

        # print(str(g.address))

        # # force get country
        # print(str(g[(len(g)-1)]).strip("[]"))
        # for result in g:
        #     print(result)

        # data['city'] = g.city
        # data['country'] = g.country
        # data['state'] = g.state



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
