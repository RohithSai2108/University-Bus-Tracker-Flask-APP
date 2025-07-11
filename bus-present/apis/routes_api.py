from flask import jsonify

def get_routes():
    routes = [
        {
            "id": 1,
            "name": "Campus Loop",
            "stops": [
                {"id": 1, "name": "Main Gate", "lat": 40.7128, "lng": -74.0060},
                {"id": 2, "name": "Library", "lat": 40.7138, "lng": -74.0070},
                {"id": 3, "name": "Dormitory", "lat": 40.7148, "lng": -74.0080}
            ]
        },
        {
            "id": 2,
            "name": "Downtown Express",
            "stops": [
                {"id": 4, "name": "Main Gate", "lat": 40.7128, "lng": -74.0060},
                {"id": 5, "name": "City Center", "lat": 40.7228, "lng": -74.0160}
            ]
        }
    ]
    return jsonify(routes)

def get_route(route_id):
    routes = {
        1: {
            "id": 1,
            "name": "Campus Loop",
            "stops": [
                {"id": 1, "name": "Main Gate", "lat": 40.7128, "lng": -74.0060},
                {"id": 2, "name": "Library", "lat": 40.7138, "lng": -74.0070},
                {"id": 3, "name": "Dormitory", "lat": 40.7148, "lng": -74.0080}
            ]
        },
        2: {
            "id": 2,
            "name": "Downtown Express",
            "stops": [
                {"id": 4, "name": "Main Gate", "lat": 40.7128, "lng": -74.0060},
                {"id": 5, "name": "City Center", "lat": 40.7228, "lng": -74.0160}
            ]
        }
    }
    route = routes.get(route_id)
    if route:
        return jsonify(route)
    return jsonify({"error": "Route not found"}), 404
