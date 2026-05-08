# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
Image OSINT - Reverse image search + EXIF metadata + face detection
Image se person dhundho, location nikalo, face analyze karo
"""

import logging
import os
import re
import base64
import hashlib
import json
from pathlib import Path
from modules.utils import rate_limited_get

# TensorFlow / DeepFace verbose logs suppress karo
os.environ.setdefault('TF_CPP_MIN_LOG_LEVEL', '3')
os.environ.setdefault('TF_ENABLE_ONEDNN_OPTS', '0')
os.environ.setdefault('GRPC_VERBOSITY', 'ERROR')
os.environ.setdefault('GLOG_minloglevel', '3')

logger = logging.getLogger(__name__)


class ImageOSINT:

    def run(self, image_path: str) -> dict:
        result = {
            'image_path':     image_path,
            'image_hash':     None,
            'file_size':      0,
            'dimensions':     None,
            'reverse_search': [],
            'face_detected':  False,
            'face_analysis':  {},
            'metadata':       {},
            'gps_location':   None,
            'risk_level':     'LOW',
            'risk_flags':     [],
            'error':          None,
        }

        path = Path(image_path)
        if not path.exists():
            result['error'] = f"Image not found: {image_path}"
            return result

        result['file_size'] = path.stat().st_size
        result['image_hash'] = self._hash_image(image_path)
        result['metadata']   = self._extract_metadata(image_path, result)
        result['dimensions'] = self._get_dimensions(image_path)

        self._reverse_image_search(result, image_path)
        self._detect_face(result, image_path)
        self._calc_risk(result)
        return result

    # ── Hash ──────────────────────────────────────────────────────────────────

    def _hash_image(self, path: str) -> str:
        with open(path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()

    def _get_dimensions(self, path: str) -> str:
        try:
            from PIL import Image
            img = Image.open(path)
            dimensions = f"{img.width}x{img.height}"
            img.close()
            return dimensions
        except Exception:
            return None

    # ── EXIF Metadata ─────────────────────────────────────────────────────────

    def _extract_metadata(self, image_path: str, result: dict) -> dict:
        """EXIF metadata extract karo — GPS, camera, timestamp"""
        metadata = {}
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS

            img = Image.open(image_path)
            exif_raw = img._getexif()
            if not exif_raw:
                img.close()
                return metadata

            for tag_id, value in exif_raw.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag == 'GPSInfo':
                    gps = {}
                    for gps_id, gps_val in value.items():
                        gps_tag = GPSTAGS.get(gps_id, gps_id)
                        gps[gps_tag] = gps_val
                    metadata['GPSInfo'] = gps
                    # Parse GPS coordinates
                    coords = self._parse_gps(gps)
                    if coords:
                        result['gps_location'] = coords
                        metadata['GPS_Coordinates'] = f"{coords['lat']:.6f}, {coords['lon']:.6f}"
                        metadata['GPS_Maps_URL'] = f"https://maps.google.com/?q={coords['lat']},{coords['lon']}"
                elif tag in ('DateTime', 'DateTimeOriginal', 'Make', 'Model',
                             'Software', 'Artist', 'Copyright', 'ImageDescription',
                             'XPComment', 'XPAuthor', 'XPTitle'):
                    metadata[tag] = str(value)[:200]
            
            img.close()
        except ImportError:
            metadata['error'] = 'Pillow not installed: pip install Pillow'
        except Exception as e:
            logger.debug(f"EXIF extraction failed: {e}")
        return metadata

    def _parse_gps(self, gps_info: dict) -> dict:
        """GPS IFD dict ko decimal coordinates mein convert karo"""
        try:
            def to_decimal(dms, ref):
                d, m, s = dms
                decimal = float(d) + float(m)/60 + float(s)/3600
                if ref in ('S', 'W'):
                    decimal = -decimal
                return decimal

            lat = to_decimal(gps_info['GPSLatitude'],  gps_info.get('GPSLatitudeRef', 'N'))
            lon = to_decimal(gps_info['GPSLongitude'], gps_info.get('GPSLongitudeRef', 'E'))
            alt = None
            if 'GPSAltitude' in gps_info:
                alt = float(gps_info['GPSAltitude'])
            return {'lat': lat, 'lon': lon, 'altitude': alt}
        except Exception:
            return None

    # ── Reverse Image Search ──────────────────────────────────────────────────

    def _reverse_image_search(self, result: dict, image_path: str):
        """Multiple reverse image search engines"""

        with open(image_path, 'rb') as f:
            img_bytes = f.read()
        img_b64 = base64.b64encode(img_bytes).decode()
        img_size = len(img_bytes)

        # 1. Yandex Images — best for face search, no API key needed
        try:
            resp = rate_limited_get(
                'https://yandex.com/images/search',
                namespace='image',
                method='POST',
                data={'upfile': img_bytes},
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml',
                },
                timeout=15,
            )
            if resp and resp.status_code in (200, 302):
                # Extract redirect URL or search results
                location = resp.headers.get('Location', '')
                if location:
                    result['reverse_search'].append({
                        'source': 'yandex_images',
                        'url':    f"https://yandex.com{location}" if location.startswith('/') else location,
                        'note':   'Yandex reverse image search result',
                    })
                else:
                    # Try to extract matches from HTML
                    matches = re.findall(r'"url":"(https?://[^"]+)"', resp.text[:5000])
                    for url in matches[:3]:
                        result['reverse_search'].append({
                            'source': 'yandex_images',
                            'url':    url,
                        })
        except Exception as e:
            logger.debug(f"Yandex search failed: {e}")

        # 2. Google Lens — manual URL (best results but requires browser)
        result['reverse_search'].append({
            'source': 'google_lens',
            'url':    'https://lens.google.com/',
            'note':   'Upload image manually for best results',
            'image_size_bytes': img_size,
        })

        # 3. Bing Visual Search URL
        result['reverse_search'].append({
            'source': 'bing_visual',
            'url':    'https://www.bing.com/visualsearch',
            'note':   'Upload image manually',
        })

        # 4. TinEye — free reverse image search
        try:
            resp = rate_limited_get(
                'https://tineye.com/search',
                namespace='image',
                method='POST',
                files={'image': ('image.jpg', img_bytes, 'image/jpeg')},
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=20,
                allow_redirects=True,
            )
            if resp and resp.status_code == 200:
                # Extract match count
                count_match = re.search(r'(\d+)\s+results?', resp.text, re.I)
                count = count_match.group(1) if count_match else '?'
                result['reverse_search'].append({
                    'source': 'tineye',
                    'url':    resp.url,
                    'note':   f'{count} matches found',
                })
        except Exception as e:
            logger.debug(f"TinEye search failed: {e}")

    # ── Face Detection ────────────────────────────────────────────────────────

    def _detect_face(self, result: dict, image_path: str):
        """OpenCV se face detect karo"""
        try:
            import cv2
            img = cv2.imread(image_path)
            if img is None:
                return

            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

            # Frontal face
            frontal = cv2.CascadeClassifier(
                cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            )
            faces = frontal.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

            # Profile face bhi check karo
            profile = cv2.CascadeClassifier(
                cv2.data.haarcascades + 'haarcascade_profileface.xml'
            )
            profile_faces = profile.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5)

            total_faces = len(faces) + len(profile_faces)

            if total_faces > 0:
                result['face_detected'] = True
                result['risk_flags'].append({
                    'severity': 'HIGH',
                    'flag':     'Face detected in image',
                    'detail':   f"{total_faces} face(s) found — identity verification possible",
                })
                # DeepFace analysis
                self._deepface_analysis(result, image_path)
            else:
                result['risk_flags'].append({
                    'severity': 'INFO',
                    'flag':     'No face detected',
                    'detail':   'No human face found in image',
                })

        except ImportError:
            result['risk_flags'].append({
                'severity': 'INFO',
                'flag':     'OpenCV not available',
                'detail':   'pip install opencv-python for face detection',
            })
        except Exception as e:
            logger.debug(f"Face detection failed: {e}")

    def _deepface_analysis(self, result: dict, image_path: str):
        """DeepFace se age, gender, emotion analyze karo"""
        # TensorFlow verbose logs suppress karo
        import os
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
        os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
        import logging as _logging
        _logging.getLogger('tensorflow').setLevel(_logging.ERROR)
        _logging.getLogger('absl').setLevel(_logging.ERROR)
        try:
            import absl.logging
            absl.logging.set_verbosity(absl.logging.ERROR)
        except Exception:
            pass

        try:
            from deepface import DeepFace
            analysis = DeepFace.analyze(
                img_path=image_path,
                actions=['age', 'gender', 'race', 'emotion'],
                enforce_detection=False,
                silent=True,
            )
            if isinstance(analysis, list):
                analysis = analysis[0]

            result['face_analysis'] = {
                'age':     analysis.get('age'),
                'gender':  analysis.get('dominant_gender'),
                'emotion': analysis.get('dominant_emotion'),
                'race':    analysis.get('dominant_race'),
                'source':  'deepface',
            }
            result['risk_flags'].append({
                'severity': 'HIGH',
                'flag':     'Face biometric analysis complete',
                'detail':   f"Age: ~{analysis.get('age')} | Gender: {analysis.get('dominant_gender')} | Emotion: {analysis.get('dominant_emotion')}",
            })
        except ImportError:
            result['face_analysis'] = {'note': 'DeepFace not installed: pip install deepface'}
        except Exception as e:
            logger.debug(f"DeepFace analysis failed: {e}")

    # ── Risk Calculation ──────────────────────────────────────────────────────

    def _calc_risk(self, result: dict):
        flags = result['risk_flags']

        # GPS location — highest risk
        if result.get('gps_location'):
            flags.append({
                'severity': 'CRITICAL',
                'flag':     'GPS location embedded in image',
                'detail':   f"Exact location: {result['metadata'].get('GPS_Coordinates', 'N/A')}",
            })

        # Camera/device info
        if result['metadata'].get('Make') or result['metadata'].get('Model'):
            device = f"{result['metadata'].get('Make','')} {result['metadata'].get('Model','')}".strip()
            flags.append({
                'severity': 'MEDIUM',
                'flag':     'Device information in metadata',
                'detail':   f"Camera/device: {device}",
            })

        # Timestamp
        if result['metadata'].get('DateTime') or result['metadata'].get('DateTimeOriginal'):
            ts = result['metadata'].get('DateTimeOriginal') or result['metadata'].get('DateTime')
            flags.append({
                'severity': 'LOW',
                'flag':     'Timestamp in metadata',
                'detail':   f"Photo taken: {ts}",
            })

        # Reverse search matches
        real_matches = [r for r in result['reverse_search']
                        if r['source'] not in ('google_lens', 'bing_visual')]
        if real_matches:
            flags.append({
                'severity': 'HIGH',
                'flag':     'Image found in reverse search',
                'detail':   f"Found via: {', '.join(r['source'] for r in real_matches)}",
            })

        severities = [f['severity'] for f in flags]
        if 'CRITICAL' in severities:
            result['risk_level'] = 'CRITICAL'
        elif 'HIGH' in severities:
            result['risk_level'] = 'HIGH'
        elif 'MEDIUM' in severities:
            result['risk_level'] = 'MEDIUM'
        else:
            result['risk_level'] = 'LOW'
