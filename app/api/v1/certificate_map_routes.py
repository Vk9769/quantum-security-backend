from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.postgres import get_db
from app.models.certificate import Certificate

router = APIRouter()

city_coords = {
    "Mumbai": (19.076, 72.8777),
    "Pune": (18.5204, 73.8567),
    "New Delhi": (28.6139, 77.209),
    "Delhi": (28.6139, 77.209),
    "Bangalore": (12.9716, 77.5946),
    "Hyderabad": (17.385, 78.4867),

    # 🔥 ADD THESE (VERY IMPORTANT)
    "Austin": (30.2672, -97.7431),
    "Palo Alto": (37.4419, -122.1430),
    "California": (36.7783, -119.4179),
    "Texas": (31.9686, -99.9018),
}

def parse_subject(subject: str):
    data = {}
    parts = subject.split(",")

    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            data[key.strip()] = value.strip()

    return {
        "domain": data.get("CN"),
        "city": data.get("L"),
        "state": data.get("ST"),
        "country": data.get("C"),
    }

@router.get("/certificate-map")
def get_certificate_map(db: Session = Depends(get_db)):
    certs = db.query(Certificate).all()

    result = []

    for cert in certs:
        parsed = parse_subject(cert.subject)

        city = parsed["city"]

        if not city or city not in city_coords:
            continue

        lat, lng = city_coords[city]

        result.append({
            "domain": parsed["domain"],
            "lat": lat,
            "lng": lng,
            "city": city,
            "state": parsed["state"],
            "country": parsed["country"]
        })

    return result