# Geolocation from Images and Media

## Trigger
Load when geolocating a photo (find where it was taken), performing reverse image search, extracting EXIF/metadata from media files, analyzing satellite imagery, reading road signs or reflected text, converting coordinate formats (MGRS, Plus Codes, What3Words), or verifying a location via crowd-sourced photos.

## Attack Surface
Target characteristics: photos of unknown locations (landmarks, streets, buildings, coastlines, signs), images with EXIF strips (GPS coordinates, camera model, timestamp), reflected/mirrored text in windows or water, satellite imagery requiring infrastructure map correlation, street-level photos that match Google Street View panoramas, and images of music-themed landmarks encoding data.

## Decision Tree
1. Extract EXIF/metadata: `exiftool image.jpg` for GPS coordinates, camera model, timestamp.
2. If no EXIF (or stripped), perform reverse image search with cropped regions.
3. Identify visual clues: road signs, business names, architecture style, vegetation, license plates, language, driving side.
4. Use infrastructure maps (OpenRailwayMap, OpenInfraMap) to match rail/power features.
5. For signs: OCR text, identify country from sign style/language/driving side.
6. For Street View images: extract panorama features, compile candidate panoramas, use ORB feature matching.
7. Convert to required coordinate format: MGRS, Plus Codes, or What3Words.
8. Verify via Google Maps crowd-sourced photos or Street View.

## Techniques

### EXIF and Metadata Extraction
```bash
exiftool image.jpg                  # Full EXIF data
identify -verbose image.jpg | head -30  # ImageMagick metadata
pdfinfo document.pdf                # PDF metadata
mediainfo video.mp4                 # Video metadata
```

### Reverse Image Search
```
Google Lens:      lens.google.com          Best for cropped landmarks/shops/signs
Google Images:    images.google.com        Most comprehensive
TinEye:           tineye.com               Best for exact match (no AI)
Yandex:           yandex.com/images        Good for faces, Eastern Europe
Baidu:            graph.baidu.com          Best for Chinese locations
Bing:             bing.com/images          Alternative index
```

Crop to the most distinctive element (shop sign, building facade, landmark) before searching -- Google Lens performs significantly better on cropped regions than full scenes.

### Visual Clue Identification for Country
```
Feature                       Country/Region
Kanji + blue highway signs    Japan
Cyrillic + wide boulevards    Russia/CIS
White X-shape crossing signs  Canada
Yellow diamond warning signs  USA/Canada
Green autobahn signs          Germany
Brown tourist signs           France
Bollards with red reflectors  Netherlands
Blue/white signs, menlou gate China
```

### Street View Panorama Matching
```python
import cv2
import numpy as np

# ORB feature detection and matching
challenge = cv2.imread('challenge.jpg')
candidate = cv2.imread('panorama.jpg')

orb = cv2.ORB_create(nfeatures=5000)
kp1, des1 = orb.detectAndCompute(challenge, None)
kp2, des2 = orb.detectAndCompute(candidate, None)

bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
matches = bf.match(des1, des2)
score = sum(1 for m in matches if m.distance < 50)
print(f"Feature match score: {score}")
```

### Street View API
```bash
# Check if Street View coverage exists at a location
curl "https://maps.googleapis.com/maps/api/streetview/metadata?location=LAT,LNG&key=KEY"

# Get Street View image
curl "https://maps.googleapis.com/maps/api/streetview?size=640x480&location=LAT,LNG&heading=90&key=KEY"
```

### Road Sign OCR and Route Tracing
```python
# Systematic approach:
# 1. Determine driving side (left=Japan/UK/Australia, right=most others)
# 2. Identify sign language/script (Kanji, Cyrillic, Arabic, Latin)
# 3. OCR text from directional signs to get town names and route numbers
# 4. Search identified route number + town names to find road corridor
# 5. Match terrain features against satellite view

# Example: Japanese expressway signs
# - Blue signs with white Kanji + route numbers (e.g., E59)
# - Distinctive guardrail style (galvanized steel, wavy profile)
# - Concrete seawalls on coastal roads
```

### Post-Soviet Architecture and Brand Identification
```python
# Recognition chain:
# 1. Brutalist concrete buildings -> post-Soviet region
# 2. Vehicle models -> Russian/CIS market cars
# 3. Cyrillic signage -> Russian-language region
# 4. Regional flags alongside tricolor -> specific federal subject
# 5. Named restaurants/chains (e.g., "Mimino") -> search geographic distribution
# 6. Coastal features + architecture -> narrow to specific region

# Restaurant/brand geolocation:
# - Identify readable business name or logo
# - Search "[name] locations" or "[name] branches"
# - Cross-reference with coastline, terrain, infrastructure
# - Google Maps business search for named establishments
```

### Reflected/Mirrored Text Reading
```bash
# Flip image horizontally with ImageMagick
convert input.jpg -flop flipped.jpg

# Or with Python/PIL
python3 -c "
from PIL import Image
img = Image.open('input.jpg')
img.transpose(Image.FLIP_LEFT_RIGHT).save('flipped.jpg')
"
```

Search strategies for partial reflected text:
- `"Aguas de Lind"` (quoted partial match)
- `"Aguas de Lind" city` (add context keyword)
- `"Aguas de Lind*" brazil` (add country if identifiable)

### MGRS Coordinate Conversion
MGRS format: `4V FH 246 677` (grid zone + 100km square + easting/northing)
Use online MGRS converter -> lat/long -> Google Maps. Challenge titles mentioning "grid" are clues.

### Google Plus Codes (Open Location Codes)
Format: `XXXX+XX` (local) or `8FVC9G8F+6W` (global)
Charset: `23456789CFGHJMPQRVWX` (no 0,1,A,B, etc.)
- Drop a pin on Google Maps -> Plus Code appears in location details.
- Precision: ~14m x 14m (vs. W3W's 3m x 3m).
- Free, no API key needed.

### What3Words Geolocation (3m x 3m Grid)
Workflow:
1. Identify location via reverse image search/landmarks/signs.
2. Get precise GPS coordinates from Google Maps satellite view.
3. Convert to W3W at what3words.com (enter coordinates in search bar).
4. Fine-tune: shift coordinates by small amounts to check adjacent squares.

Precision matters: a building entrance vs. its parking lot may have different W3W addresses. Match the EXACT viewpoint of the photo. Use micro-landmarks (utility poles, pathway rocks, bollards) visible in both the challenge image and Street View.

### Overpass Turbo Spatial Queries
Query OpenStreetMap data to find POIs within radius of other POIs:
```
[out:json][timeout:25];
{{geocodeArea:Barcelona}}->.searchArea;
(
  node["railway"="subway_entrance"](area.searchArea);
)->.metros;
(
  node(around.metros:10)["shop"~"newsagent|kiosk"];
  way(around.metros:10)["shop"~"newsagent|kiosk"];
);
out body;
>; out skel qt;
```

### Google Maps Crowd-Sourced Photo Verification
1. Identify candidate location name from other OSINT clues.
2. Search location on Google Maps.
3. Click Photos tab (user-submitted images).
4. Compare scene elements against challenge image to confirm match.

### Music-Themed Landmark Geolocation
Multi-image challenges: each image of a music-themed landmark encodes a piano key number (1-88). Sequence of key numbers encodes the flag. Identify all locations first (easy part), then decode the key sequence.

### IP Geolocation
```bash
curl "http://ip-api.com/json/192.0.2.60"
curl "http://ipinfo.io/192.0.2.60/json"
```

### Monumental Letters / Letreiro Identification
Search terms for 3D city name letters:
- Google: `"letras monumentales" [city]` or `"letreiro turístico" [city]`
- OpenStreetMap: search for nodes tagged `tourism=attraction`
- Common in Latin American plazas, often reflected in water pools

## Bypass
- If EXIF is stripped (Twitter, Facebook), check for visual watermarks, embedded metadata in comments nearby, or the image filename itself.
- If Google Lens returns nothing useful, try Yandex (better for Eastern Europe/Russia) or Baidu (better for China).
- If the image is too generic, look for power lines, unique vegetation species, utility pole designs, or weather patterns to narrow the region.
- If the scene is indoors, search for recognizable chain brands, electrical outlet shapes (country-specific), or window view layouts.
- If Street View is unavailable, use Mapillary (crowd-sourced street imagery) or OpenStreetCam.

## Verification
- Coordinates from geolocation match the challenge image when checked on Google Street View.
- What3Words address / Plus Code / MGRS coordinates convert to the exact location shown in the photo.
- Multiple independent clues (road sign + architecture + vegetation) converge on the same location.
- Google Maps crowd-sourced photos show the same scene elements at the candidate location.
- ORB feature matching produces high match count between candidate panorama and challenge image.

## Pitfalls
- What3Words adjacent 3m squares have completely different word triples -- small coordinate errors produce wrong results.
- Twitter strips EXIF on upload -- do not expect GPS data from Twitter-served images.
- Street View panoramas have capture dates; the image may be years old and landscape may have changed.
- Reflections and watermarks can be misleading -- confirm with multiple independent clues.
- Overpass Turbo queries can timeout if the search area is too large or the query is too broad.
- 3D letters/letreiros are easily confused across similar cities -- verify the exact font and color scheme.
