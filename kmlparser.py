import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import dateparser
import sys
import re
import os
from timezonefinder import TimezoneFinder
from math import radians, sin, cos, sqrt, atan2
import requests
import pytz
import binascii
import geojson

# https://www.fai.org/sites/default/files/igc_fr_specification_2020-11-25_with_al6.pdf

google_maps_api_key = "AIzaSyA4413GL0OX12jQv2gXJC88sIh0N-__4f0"

meassures_per_second = 2

def generate_kml(coordinates, timestamp, person_name):
    kml = ET.Element("kml", xmlns="http://earth.google.com/kml/2.0")
    document = ET.SubElement(kml, "Document")

    # Convert timestamp to human-readable date
    timestamp_str = datetime.utcfromtimestamp(timestamp).strftime('%A, %d. %B %Y %H:%M:%S')

    # Set the name and description
    name_element = ET.SubElement(document, "name")
    name_element.text = f"Track {person_name} {timestamp_str}"

    description_element = ET.SubElement(document, "description")
    description_element.text = "by flytics"

    # Set the Style for the TrackLine
    style_element = ET.SubElement(document, "Style", id="TrackLine")
    line_style_element = ET.SubElement(style_element, "LineStyle")
    color_element = ET.SubElement(line_style_element, "color")
    color_element.text = "ff00ff00"
    width_element = ET.SubElement(line_style_element, "width")
    width_element.text = "2"

    # Add Placemark with LineString
    placemark_element = ET.SubElement(document, "Placemark")
    placemark_name_element = ET.SubElement(placemark_element, "name")
    placemark_name_element.text = "Track"
    style_url_element = ET.SubElement(placemark_element, "styleUrl")
    style_url_element.text = "#TrackLine"
    visibility_element = ET.SubElement(placemark_element, "visibility")
    visibility_element.text = "1"

    # Add LineString with coordinates
    line_string_element = ET.SubElement(placemark_element, "LineString")
    altitude_mode_element = ET.SubElement(line_string_element, "altitudeMode")
    altitude_mode_element.text = "absolute"
    coordinates_element = ET.SubElement(line_string_element, "coordinates")


    coordinates_element.text = ""
    
    for coord in coordinates:
        coordinates_element.text += f"{coord[2]},{coord[1]},{coord[3]}\n"
        
    # for index, coord in enumerate(coordinates):
    #     if index % 2 == 1: # every 2nd
    #     # if index % 3 == 2: # every 3rd
    #         coordinates_element.text += f"{coord[2]},{coord[1]},{coord[3]}\n"



    # Create and save the KML file
    tree = ET.ElementTree(kml)
    
    
    script_path = os.path.dirname(os.path.realpath(__file__))
    output_folder = os.path.join(script_path, "kml_files")
    os.makedirs(output_folder, exist_ok=True)
    
    while True:
        filename = binascii.hexlify(os.urandom(16)).decode() + ".kml"
        output_path = os.path.join(output_folder, filename)

        if not os.path.exists(output_path):
            break

    output_path = os.path.join(output_folder, filename)
    tree = ET.ElementTree(kml)
    tree.write(output_path)
    
    return filename

def generateGeoJSON(coordinates):

    coordinates = [[lon, lat, elev] for _, lat, lon, elev in coordinates]
    
    # Create a LineString feature
    line_string = geojson.LineString(coordinates)

    # Create a Feature with the LineString geometry
    feature = geojson.Feature(geometry=line_string, properties={
        "name": "by Flytics",
        "styleUrl": "#TrackLine",
        "styleHash": "25bb3816",
        "stroke": "#00ff00",
        "stroke-opacity": 1,
        "stroke-width": 2,
        "visibility": "1"
    })

    # Create a FeatureCollection with the Feature
    feature_collection = geojson.FeatureCollection([feature])

    script_path = os.path.dirname(os.path.realpath(__file__))
    output_folder = os.path.join(script_path, "geojson_files")
    os.makedirs(output_folder, exist_ok=True)
    
    while True:
        filename = binascii.hexlify(os.urandom(16)).decode() + ".geojson"
        output_path = os.path.join(output_folder, filename)

        if not os.path.exists(output_path):
            break

    output_path = os.path.join(output_folder, filename)

    with open(output_path, 'w') as f:
        geojson.dump(feature_collection, f)

    return filename


def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371000.0
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = R * c
    return distance

def get_timezone(lat, long, timestamp):
    endpoint = "https://maps.googleapis.com/maps/api/timezone/json"
    params = {
        'location': f'{str(lat)},{str(long)}',
        'key': google_maps_api_key,
        'timestamp': str(timestamp)
    }
    # print(params)
    response = requests.get(endpoint, params=params)
    return response.json()

def get_location(lat, long):
    
    country = None
    location = None
    location_types = ["establishment", "sublocality", "locality", "administrative_area_level_3", "administrative_area_level_2","administrative_area_level_1", None]
    current_location_type = None
    endpoint = "https://maps.googleapis.com/maps/api/geocode/json"
    params = {
        # 'latlng': f'{latitude},{longitude}',
        'latlng': f'{str(lat)},{str(long)}',
        'key': google_maps_api_key,
    }
    response = requests.get(endpoint, params=params)
    # print(response.json())
    if response.status_code == 200:
        googleData = response.json()
        for result in googleData['results']:
            for address_components in result['address_components']:
                if not country and "country" in address_components['types']:
                    country = address_components['long_name']
                    country_short = address_components['short_name']
                # if address_components['types'][0] in location_types:
                if set(address_components['types']) & set(location_types):
                    matching_type = next(iter(set(address_components['types']) & set(location_types)))
                    if location_types.index(matching_type) < location_types.index(current_location_type):
                        # print(address_components['types'][0])
                        current_location_type = matching_type
                        location = address_components['long_name']
        return {'country': country, 'country_code': country_short, 'location': location}
    else:
        return {'code':10, 'message':'There was an error while fetching the results from the google API'}

def degree_to_decimal(meassure, meassure_type):
    if len(meassure) == 8:
        meassures = re.search(r'^(\d\d\d)(\d\d\d\d\d)$', meassure)
    elif len(meassure) == 7:
        meassures = re.search(r'^(\d\d)(\d\d\d\d\d)$', meassure)
    else:
        return False
        
    degrees = int(meassures.group(1))
    minutes = int(meassures.group(2))
    
    minutes = str(meassures.group(2)[:2]) + '.' + str(meassures.group(2)[2:])

    return (float(degrees) + float(minutes)/60) * (-1 if meassure_type.lower() in ['w', 's'] else 1)


def parse_igc(filepath, pilot):
    try:
        data = {}
        flight_date = None
        with open(filepath, 'r', encoding='latin-1') as file:
            coordinates_list = []
            for line in file:
                temp_list = []
                # get date
                if (re.match(r'HFDTE(\d\d)(\d\d)(\d\d)', line)) and flight_date == None:
                    line_parse = re.search(r'^HFDTE(\d\d\d\d\d\d).*', line)
                    flight_date = datetime.strptime(line_parse.group(1), '%d%m%y').date()

                if (re.match(r'^B(\d\d\d\d\d\d)(\d\d\d\d\d\d\d)(\w)(\d\d\d\d\d\d\d\d)(\w)(\w)(\d\d\d\d\d\d)(\d\d\d\d).*', line)):

                    
                    line_parse = re.search(r'^B(\d\d\d\d\d\d)(\d\d\d\d\d\d\d)(\w)(\d\d\d\d\d\d\d\d)(\w)(\w)(\d\d\d\d\d\d)(\d\d\d\d).*', line)
                    flight_time = datetime.strptime(line_parse.group(1), '%H%M%S').time()                
                    
                    timezone = pytz.timezone('Europe/London')                        
                    flight_datetime = datetime.combine(flight_date, flight_time)
                    aware_datetime = timezone.localize(flight_datetime)
                    timestamp = int(aware_datetime.timestamp())
                    # print(timestamp)
                    
                    latitude = degree_to_decimal(line_parse.group(2), line_parse.group(3))
                    longitude = degree_to_decimal(line_parse.group(4), line_parse.group(5))
                    altitude = line_parse.group(8)
                    
                    temp_list.append(int(timestamp))
                    temp_list.append(float("{:.6f}".format(latitude)))
                    temp_list.append(float("{:.6f}".format(longitude)))
                    temp_list.append(int(altitude))
                    coordinates_list.append(temp_list)
            
        
            
        data['code'] = 0
        data['message'] = "Everything fine"
        data['timestamp'] = coordinates_list[0][0]
        lat = coordinates_list[0][1]
        long = coordinates_list[0][2]
        
        timezone = get_timezone(lat=lat, long=long, timestamp=data['timestamp'])
        location = get_location(lat=lat, long=long)


        data['timezone_id'] = timezone['timeZoneId']
        data['timezone_raw_offset'] = timezone['rawOffset']
        data['timezone_dst_offset'] = timezone['dstOffset']
        data['country'] = location['country']
        data['country_code'] = location['country_code']
        data['location'] = location['location']
        
        distance = 0
        for i in range(len(coordinates_list) - 1):
            distance += calculate_distance(coordinates_list[i][1], coordinates_list[i][2], coordinates_list[i+1][1], coordinates_list[i+1][2])
        # data['distance'] = float("{:.6f}".format(distance))
        data['distance'] = int(distance)
        data['distance_air'] = int(calculate_distance(coordinates_list[0][1], coordinates_list[0][2], coordinates_list[len(coordinates_list) - 1][1], coordinates_list[len(coordinates_list) - 1][2]))
        
        data['start_height'] = coordinates_list[0][3]
        data['start_lat'] = coordinates_list[0][1]
        data['start_long'] = coordinates_list[0][2]

        data['end_lat'] = coordinates_list[(len(coordinates_list)-1)][1]
        data['end_long'] = coordinates_list[(len(coordinates_list)-1)][2]
        data['end_height'] = coordinates_list[len(coordinates_list)-1][3]


        altitudes = [coord[3] for coord in coordinates_list]
        data['max_height'] = max(altitudes)
        data['min_height'] = min(altitudes)


        data['duration'] = coordinates_list[len(coordinates_list)-1][0] - coordinates_list[0][0]

        data['kml_file'] = generate_kml(coordinates=coordinates_list, timestamp=data['timestamp'], person_name=pilot)
        data['geojson_file'] = generateGeoJSON(coordinates=coordinates_list)
                        
        return data

    except Exception as e:
        return {'code': 10, 'message': "There was an error while parsing '" + filepath + "'"}



# def parse_kml(file_path):
#         # try:
#             data = {}

#             tree = ET.parse(file_path)
#             root = tree.getroot()

#             coordinates = []
#             for elem in root.iter():
#                 if 'name' in elem.tag:
#                     if (re.match(r'^Track .*', elem.text)):
#                         match = re.search(r"Track (.*) .*?, (.*?) (\d\d:\d\d:\d\d)", elem.text)
#                         flightUser = match.group(1)
#                         flightDate = dateparser.parse(match.group(2)).date()
#                         flightTime = dateparser.parse(match.group(3)).time()
                        
#                         timezone = pytz.timezone('Europe/London')                        
#                         flight_datetime = datetime.combine(flightDate, flightTime)
#                         aware_datetime = timezone.localize(flight_datetime)
#                         timestamp = int(aware_datetime.timestamp())
                        
#                         # print(timestamp)

#                         data['timestamp'] = timestamp
                            
#                         # data['user'] = flightUser
#                         # data['date'] = str(flightDate)
#                         # data['time'] = str(flightTime)

#                 if 'coordinates' in elem.tag:
#                     for line in elem.text.splitlines():
#                         templist = []
#                         if line.strip() != "":
#                             for coordinate in line.split(','):
#                                 templist.append(float(coordinate.strip()))
#                             coordinates.append(templist)
#                 # print(coordinates)


#             # # add the coordinates to the return
#             # data['coordinates'] = coordinates

#             # tzfinder = TimezoneFinder() 
#             # tz = tzfinder.timezone_at(lng=coordinates[0][0], lat=coordinates[0][1])
#             # data['timezone'] = tz
                            


#             # distance =  calculate_distance(46.7225024, 8.1969395, 46.7272347, 8.1844957)


#             lat = coordinates[0][1]
#             long = coordinates[0][0]



#             timezone = get_timezone(lat=lat, long=long, timestamp=data['timestamp'])
#             location = get_location(lat=lat, long=long)
            
            
            

#             data['timezone_id'] = timezone['timeZoneId']
#             data['timezone_raw_offset'] = timezone['rawOffset']
#             data['timezone_dst_offset'] = timezone['dstOffset']
#             data['country'] = location['country']
#             data['location'] = location['location']


#             data['meassure_points'] = len(coordinates)

#             data['code'] = 0
#             data['message'] = "Everything fine"
#             return data
        
#         # except Exception as e:
#         #     print(e)
#             # return {'code':90, 'message':'There was an error while proccessing the kml files'}




if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_igc_file>")
    else:
        file_path = sys.argv[1]
        if (os.path.isfile(file_path)):
            if file_path.lower().endswith('.igc'):
                temp = parse_igc(file_path, "Max Mustermann")
                print(temp)
            else:
                print("Unsupported file extension. Please use .igc files.")
        else:
            print("file not found")
