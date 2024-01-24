import xml.etree.ElementTree as ET
from datetime import datetime
import dateparser
import sys
import re
import os
from timezonefinder import TimezoneFinder

meassures_per_second = 2


def parse_kml(file_path):

        try:
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
                        if line != "":
                            for coordinate in line.split(','):
                                templist.append(float(coordinate))
                            coordinates.append(templist)

            # data['coordinates'] = coordinates

            tzfinder = TimezoneFinder() 
            tz = tzfinder.timezone_at(lng=coordinates[0][0], lat=coordinates[0][1])
            data['timezone'] = tz

            data['meassure_points'] = len(coordinates)

            data['status'] = 200
            data['message'] = "Everything fine"
            return data
        
        except Exception as e:
            print(e)
            return False




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
