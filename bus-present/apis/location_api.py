from flask import jsonify, Blueprint, request
import requests
from urllib.parse import quote

GEOAPIFY_API_KEY = "your api key here"

def get_location_details(address):
    try:
        encoded_address = quote(address)
        url = f"https://api.geoapify.com/v1/geocode/search?text={encoded_address}&apiKey={GEOAPIFY_API_KEY}"
        
        response = requests.get(url)
        data = response.json()
        
        if data.get('features') and len(data['features']) > 0:
            location = data['features'][0]
            coordinates = location['geometry']['coordinates']
            return jsonify({
                'success': True,
                'lat': coordinates[1],
                'lng': coordinates[0],
                'formatted_address': location['properties']['formatted']
            })
        return jsonify({'success': False, 'message': 'Location not found'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

def get_bus_locations():
    # You can integrate real bus location data here
    return jsonify({'message': 'Use the search functionality to find locations'})

def update_bus_location(bus_id, address):
    try:
        # Get coordinates from address using Geoapify
        location_details = get_location_details(address)
        if location_details.is_json:
            json_data = location_details.get_json()
            if json_data and json_data.get('success'):
                # In a real app, update the bus location in your database
                return jsonify({
                    'success': True,
                    'bus_id': bus_id,
                    'lat': json_data['lat'],
                    'lng': json_data['lng']
                })
            return location_details
        return jsonify({'success': False, 'message': 'Invalid response from geocoding service'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

location_api = Blueprint('location_api', __name__)

@location_api.route('/api/geocode')
def geocode():
    address = request.args.get('address')
    if not address:
        return jsonify({'success': False, 'message': 'Address is required'}), 400
    return get_location_details(address) 
