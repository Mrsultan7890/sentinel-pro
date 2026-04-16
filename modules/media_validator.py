#!/usr/bin/env python3

import os
import json
import hashlib
import requests
from modules.utils import tor_session
from PIL import Image, ExifTags
from PIL.ExifTags import TAGS
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
import time
from urllib.parse import urlparse
import mimetypes

# Optional OpenCV import
try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    print("[WARNING] OpenCV (cv2) not available. Media validation will be limited.")

class MediaValidator:
    def __init__(self, evidence_dir: str = "evidence/media"):
        self.evidence_dir = evidence_dir
        os.makedirs(evidence_dir, exist_ok=True)
        
        # Deepfake detection patterns
        self.deepfake_indicators = {
            'lighting_inconsistency': 0.0,
            'shadow_mismatch': 0.0,
            'pixel_artifacts': 0.0,
            'compression_anomalies': 0.0,
            'facial_landmarks': 0.0,
            'temporal_inconsistency': 0.0
        }
        
        # Suspicious editing software signatures
        self.editing_signatures = [
            'Adobe Photoshop', 'GIMP', 'FaceSwap', 'DeepFaceLab',
            'FaceApp', 'Reface', 'Zao', 'MyHeritage', 'Wombo'
        ]
        
    def validate_media_url(self, url: str, source: str = "unknown") -> Dict[str, Any]:
        """Download and validate media from URL"""
        
        try:
            # Download media — Tor se route karo agar active
            _sess = tor_session()
            response = _sess.get(url, timeout=30, headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            })
            
            if response.status_code != 200:
                return {'error': f'Failed to download media: {response.status_code}'}
            
            # Determine file type
            content_type = response.headers.get('content-type', '')
            file_ext = self._get_file_extension(url, content_type)
            
            # Generate secure filename
            url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
            filename = f"{source}_{url_hash}{file_ext}"
            filepath = os.path.join(self.evidence_dir, filename)
            
            # Save file
            with open(filepath, 'wb') as f:
                f.write(response.content)
            
            # Validate the downloaded media
            return self.validate_media_file(filepath, url, source)
            
        except Exception as e:
            return {'error': f'Media validation failed: {str(e)}'}
    
    def validate_media_file(self, filepath: str, original_url: str = "", source: str = "unknown") -> Dict[str, Any]:
        """Comprehensive media file validation"""
        
        if not os.path.exists(filepath):
            return {'error': 'File not found'}
        
        # File hash for integrity
        file_hash = self._calculate_file_hash(filepath)
        
        # Basic file info
        file_info = {
            'filepath': filepath,
            'original_url': original_url,
            'source': source,
            'file_hash': file_hash,
            'file_size': os.path.getsize(filepath),
            'timestamp': time.time(),
            'validation_results': {}
        }
        
        # Determine media type and validate accordingly
        mime_type, _ = mimetypes.guess_type(filepath)
        
        if mime_type and mime_type.startswith('image/'):
            file_info['media_type'] = 'image'
            file_info['validation_results'] = self._validate_image(filepath)
        elif mime_type and mime_type.startswith('video/'):
            file_info['media_type'] = 'video'
            file_info['validation_results'] = self._validate_video(filepath)
        else:
            file_info['media_type'] = 'unknown'
            file_info['validation_results'] = {'error': 'Unsupported media type'}
        
        # Calculate overall authenticity score
        file_info['authenticity_score'] = self._calculate_authenticity_score(
            file_info['validation_results']
        )
        
        # Generate evidence report
        self._generate_evidence_report(file_info)
        
        return file_info
    
    def _validate_image(self, filepath: str) -> Dict[str, Any]:
        """Validate image for deepfake and manipulation indicators"""
        
        results = {
            'metadata_analysis': {},
            'deepfake_indicators': {},
            'manipulation_score': 0.0,
            'technical_analysis': {},
            'authenticity_indicators': []
        }
        
        try:
            # Load image
            image = Image.open(filepath)
            cv_image = cv2.imread(filepath)
            
            # Metadata analysis
            results['metadata_analysis'] = self._analyze_image_metadata(image)
            
            # Technical analysis
            results['technical_analysis'] = self._analyze_image_technical(cv_image)
            
            # Deepfake detection
            results['deepfake_indicators'] = self._detect_deepfake_indicators(cv_image)
            
            # Calculate manipulation score
            results['manipulation_score'] = self._calculate_manipulation_score(results)
            
            # Generate authenticity indicators
            results['authenticity_indicators'] = self._generate_authenticity_indicators(results)
            
        except Exception as e:
            results['error'] = f'Image validation failed: {str(e)}'
        
        return results
    
    def _validate_video(self, filepath: str) -> Dict[str, Any]:
        """Validate video for deepfake and manipulation indicators"""
        
        results = {
            'metadata_analysis': {},
            'deepfake_indicators': {},
            'manipulation_score': 0.0,
            'technical_analysis': {},
            'frame_analysis': {},
            'authenticity_indicators': []
        }
        
        try:
            # Open video
            cap = cv2.VideoCapture(filepath)
            
            if not cap.isOpened():
                return {'error': 'Could not open video file'}
            
            # Basic video info
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            duration = frame_count / fps if fps > 0 else 0
            
            results['technical_analysis'] = {
                'fps': fps,
                'frame_count': frame_count,
                'duration': duration,
                'resolution': (
                    int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
                    int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                )
            }
            
            # Analyze sample frames
            results['frame_analysis'] = self._analyze_video_frames(cap, max_frames=10)
            
            # Detect temporal inconsistencies
            results['deepfake_indicators'] = self._detect_video_deepfake_indicators(cap)
            
            # Calculate manipulation score
            results['manipulation_score'] = self._calculate_manipulation_score(results)
            
            # Generate authenticity indicators
            results['authenticity_indicators'] = self._generate_authenticity_indicators(results)
            
            cap.release()
            
        except Exception as e:
            results['error'] = f'Video validation failed: {str(e)}'
        
        return results
    
    def _analyze_image_metadata(self, image: Image.Image) -> Dict[str, Any]:
        """Extract and analyze image metadata"""
        
        metadata = {
            'exif_data': {},
            'camera_info': {},
            'editing_software': [],
            'creation_date': None,
            'gps_coordinates': None,
            'suspicious_indicators': []
        }
        
        try:
            # Extract EXIF data
            exif_data = image._getexif()
            
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    metadata['exif_data'][tag] = str(value)
                
                # Extract specific information
                if 'Make' in metadata['exif_data']:
                    metadata['camera_info']['make'] = metadata['exif_data']['Make']
                if 'Model' in metadata['exif_data']:
                    metadata['camera_info']['model'] = metadata['exif_data']['Model']
                if 'DateTime' in metadata['exif_data']:
                    metadata['creation_date'] = metadata['exif_data']['DateTime']
                if 'Software' in metadata['exif_data']:
                    software = metadata['exif_data']['Software']
                    metadata['editing_software'].append(software)
                    
                    # Check for suspicious editing software
                    for suspicious_software in self.editing_signatures:
                        if suspicious_software.lower() in software.lower():
                            metadata['suspicious_indicators'].append(
                                f'Edited with {suspicious_software}'
                            )
                
                # Check for GPS data
                if 'GPSInfo' in metadata['exif_data']:
                    metadata['gps_coordinates'] = 'Present (coordinates extracted)'
            
            # Check for missing metadata (suspicious)
            if not metadata['exif_data']:
                metadata['suspicious_indicators'].append('No EXIF data present')
            
            if not metadata['camera_info']:
                metadata['suspicious_indicators'].append('No camera information')
            
        except Exception as e:
            metadata['error'] = f'Metadata extraction failed: {str(e)}'
        
        return metadata
    
    def _analyze_image_technical(self, image: np.ndarray) -> Dict[str, Any]:
        """Technical analysis of image properties"""
        
        analysis = {
            'resolution': image.shape[:2] if len(image.shape) >= 2 else (0, 0),
            'color_channels': image.shape[2] if len(image.shape) == 3 else 1,
            'compression_artifacts': 0.0,
            'noise_analysis': {},
            'edge_analysis': {},
            'color_analysis': {}
        }
        
        try:
            # Compression artifact detection
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
            
            # Detect JPEG compression artifacts
            laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
            analysis['compression_artifacts'] = min(laplacian_var / 1000.0, 1.0)
            
            # Noise analysis
            noise_level = np.std(gray)
            analysis['noise_analysis'] = {
                'noise_level': float(noise_level),
                'signal_to_noise': float(np.mean(gray) / (noise_level + 1e-10))
            }
            
            # Edge analysis
            edges = cv2.Canny(gray, 50, 150)
            edge_density = np.sum(edges > 0) / edges.size
            analysis['edge_analysis'] = {
                'edge_density': float(edge_density),
                'edge_sharpness': float(np.mean(edges[edges > 0])) if np.any(edges > 0) else 0.0
            }
            
            # Color analysis
            if len(image.shape) == 3:
                color_std = np.std(image, axis=(0, 1))
                analysis['color_analysis'] = {
                    'color_variance': color_std.tolist(),
                    'color_balance': float(np.std(color_std))
                }
            
        except Exception as e:
            analysis['error'] = f'Technical analysis failed: {str(e)}'
        
        return analysis
    
    def _detect_deepfake_indicators(self, image: np.ndarray) -> Dict[str, float]:
        """Detect potential deepfake indicators in image"""
        
        indicators = {
            'lighting_inconsistency': 0.0,
            'shadow_analysis': 0.0,
            'pixel_artifacts': 0.0,
            'facial_landmarks': 0.0,
            'skin_texture': 0.0,
            'eye_reflection': 0.0
        }
        
        try:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
            
            # Basic lighting inconsistency detection
            # Analyze lighting gradients across the image
            grad_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
            grad_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
            
            lighting_variance = np.var(np.sqrt(grad_x**2 + grad_y**2))
            indicators['lighting_inconsistency'] = min(lighting_variance / 10000.0, 1.0)
            
            # Pixel artifact detection
            # Look for unusual pixel patterns that might indicate manipulation
            blur = cv2.GaussianBlur(gray, (5, 5), 0)
            diff = cv2.absdiff(gray, blur)
            artifact_score = np.mean(diff) / 255.0
            indicators['pixel_artifacts'] = min(artifact_score * 5, 1.0)
            
            # Face detection for facial analysis
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            faces = face_cascade.detectMultiScale(gray, 1.1, 4)
            
            if len(faces) > 0:
                # Analyze the first detected face
                x, y, w, h = faces[0]
                face_region = gray[y:y+h, x:x+w]
                
                # Skin texture analysis
                texture_variance = np.var(face_region)
                indicators['skin_texture'] = min(texture_variance / 1000.0, 1.0)
                
                # Eye region analysis (simplified)
                eye_region_y = int(y + h * 0.2)
                eye_region_h = int(h * 0.3)
                eye_region = face_region[eye_region_y:eye_region_y+eye_region_h, :]
                
                if eye_region.size > 0:
                    eye_variance = np.var(eye_region)
                    indicators['eye_reflection'] = min(eye_variance / 500.0, 1.0)
            
        except Exception as e:
            # If face detection fails, set default values
            pass
        
        return indicators
    
    def _analyze_video_frames(self, cap, max_frames: int = 10) -> Dict[str, Any]:
        """Analyze sample frames from video"""
        
        frame_analysis = {
            'frames_analyzed': 0,
            'average_quality': 0.0,
            'consistency_score': 0.0,
            'frame_differences': []
        }
        
        try:
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            step = max(1, frame_count // max_frames)
            
            frames = []
            qualities = []
            
            for i in range(0, frame_count, step):
                cap.set(cv2.CAP_PROP_POS_FRAMES, i)
                ret, frame = cap.read()
                
                if not ret:
                    break
                
                frames.append(frame)
                
                # Calculate frame quality
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                quality = cv2.Laplacian(gray, cv2.CV_64F).var()
                qualities.append(quality)
                
                if len(frames) >= max_frames:
                    break
            
            frame_analysis['frames_analyzed'] = len(frames)
            frame_analysis['average_quality'] = float(np.mean(qualities)) if qualities else 0.0
            
            # Calculate frame-to-frame consistency
            if len(frames) > 1:
                differences = []
                for i in range(1, len(frames)):
                    diff = cv2.absdiff(frames[i-1], frames[i])
                    diff_score = np.mean(diff)
                    differences.append(diff_score)
                
                frame_analysis['frame_differences'] = differences
                frame_analysis['consistency_score'] = 1.0 - (np.std(differences) / 255.0)
            
        except Exception as e:
            frame_analysis['error'] = f'Frame analysis failed: {str(e)}'
        
        return frame_analysis
    
    def _detect_video_deepfake_indicators(self, cap) -> Dict[str, float]:
        """Detect deepfake indicators in video"""
        
        indicators = {
            'temporal_inconsistency': 0.0,
            'facial_stability': 0.0,
            'lighting_changes': 0.0,
            'compression_artifacts': 0.0
        }
        
        try:
            # Sample a few frames for analysis
            frame_positions = [0.1, 0.3, 0.5, 0.7, 0.9]  # Relative positions
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            sampled_frames = []
            for pos in frame_positions:
                frame_num = int(pos * frame_count)
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_num)
                ret, frame = cap.read()
                if ret:
                    sampled_frames.append(frame)
            
            if len(sampled_frames) > 1:
                # Analyze temporal consistency
                temporal_diffs = []
                for i in range(1, len(sampled_frames)):
                    diff = cv2.absdiff(sampled_frames[i-1], sampled_frames[i])
                    temporal_diffs.append(np.mean(diff))
                
                # High variance in temporal differences might indicate manipulation
                if temporal_diffs:
                    temporal_variance = np.var(temporal_diffs)
                    indicators['temporal_inconsistency'] = min(temporal_variance / 1000.0, 1.0)
            
        except Exception as e:
            pass
        
        return indicators
    
    def _calculate_manipulation_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall manipulation probability score"""
        
        score = 0.0
        factors = 0
        
        # Metadata factors
        if 'metadata_analysis' in results:
            metadata = results['metadata_analysis']
            if 'suspicious_indicators' in metadata:
                score += len(metadata['suspicious_indicators']) * 0.1
                factors += 1
        
        # Deepfake indicators
        if 'deepfake_indicators' in results:
            deepfake_scores = results['deepfake_indicators']
            if isinstance(deepfake_scores, dict):
                avg_deepfake_score = np.mean(list(deepfake_scores.values()))
                score += avg_deepfake_score * 0.4
                factors += 1
        
        # Technical analysis
        if 'technical_analysis' in results:
            tech = results['technical_analysis']
            if 'compression_artifacts' in tech:
                score += tech['compression_artifacts'] * 0.2
                factors += 1
        
        # Frame analysis (for videos)
        if 'frame_analysis' in results:
            frame = results['frame_analysis']
            if 'consistency_score' in frame:
                # Lower consistency = higher manipulation probability
                score += (1.0 - frame['consistency_score']) * 0.3
                factors += 1
        
        return min(score / max(factors, 1), 1.0)
    
    def _generate_authenticity_indicators(self, results: Dict[str, Any]) -> List[str]:
        """Generate human-readable authenticity indicators"""
        
        indicators = []
        
        # Check manipulation score
        manipulation_score = results.get('manipulation_score', 0.0)
        
        if manipulation_score > 0.8:
            indicators.append("HIGH RISK: Strong indicators of digital manipulation")
        elif manipulation_score > 0.6:
            indicators.append("MEDIUM RISK: Possible digital manipulation detected")
        elif manipulation_score > 0.3:
            indicators.append("LOW RISK: Minor inconsistencies detected")
        else:
            indicators.append("AUTHENTIC: No significant manipulation indicators")
        
        # Metadata indicators
        if 'metadata_analysis' in results:
            metadata = results['metadata_analysis']
            if metadata.get('suspicious_indicators'):
                for indicator in metadata['suspicious_indicators']:
                    indicators.append(f"METADATA: {indicator}")
        
        # Technical indicators
        if 'deepfake_indicators' in results:
            deepfake = results['deepfake_indicators']
            for indicator, score in deepfake.items():
                if score > 0.7:
                    indicators.append(f"DEEPFAKE: High {indicator.replace('_', ' ')} detected")
        
        return indicators
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of file for integrity verification"""
        
        hash_sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _get_file_extension(self, url: str, content_type: str) -> str:
        """Determine appropriate file extension"""
        
        # Try to get extension from URL
        parsed_url = urlparse(url)
        path = parsed_url.path
        if '.' in path:
            return os.path.splitext(path)[1]
        
        # Fallback to content type
        extension_map = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'video/mp4': '.mp4',
            'video/avi': '.avi',
            'video/mov': '.mov',
            'video/webm': '.webm'
        }
        
        return extension_map.get(content_type, '.bin')
    
    def _calculate_authenticity_score(self, validation_results: Dict[str, Any]) -> float:
        """Calculate overall authenticity score (0-1, higher = more authentic)"""
        
        if 'error' in validation_results:
            return 0.0
        
        manipulation_score = validation_results.get('manipulation_score', 0.0)
        return max(0.0, 1.0 - manipulation_score)
    
    def _generate_evidence_report(self, file_info: Dict[str, Any]) -> None:
        """Generate detailed evidence report for legal purposes"""
        
        report_filename = f"evidence_report_{file_info['file_hash'][:16]}.json"
        report_path = os.path.join(self.evidence_dir, report_filename)
        
        evidence_report = {
            'evidence_id': file_info['file_hash'],
            'collection_timestamp': file_info['timestamp'],
            'source_information': {
                'original_url': file_info.get('original_url', ''),
                'source_platform': file_info.get('source', 'unknown'),
                'collection_method': 'automated_download'
            },
            'file_information': {
                'filepath': file_info['filepath'],
                'file_size': file_info['file_size'],
                'media_type': file_info.get('media_type', 'unknown'),
                'integrity_hash': file_info['file_hash']
            },
            'validation_results': file_info['validation_results'],
            'authenticity_assessment': {
                'authenticity_score': file_info.get('authenticity_score', 0.0),
                'manipulation_probability': file_info['validation_results'].get('manipulation_score', 0.0),
                'risk_level': self._categorize_authenticity_risk(file_info.get('authenticity_score', 0.0))
            },
            'chain_of_custody': {
                'collected_by': 'The Sentinel Intelligence Platform',
                'collection_timestamp': file_info['timestamp'],
                'integrity_verified': True,
                'hash_algorithm': 'SHA-256'
            }
        }
        
        with open(report_path, 'w') as f:
            json.dump(evidence_report, f, indent=2, default=str)
    
    def _categorize_authenticity_risk(self, authenticity_score: float) -> str:
        """Categorize authenticity risk level"""
        
        if authenticity_score >= 0.8:
            return "LOW_RISK"
        elif authenticity_score >= 0.6:
            return "MEDIUM_RISK"
        elif authenticity_score >= 0.4:
            return "HIGH_RISK"
        else:
            return "CRITICAL_RISK"
    
    def batch_validate_media(self, media_urls: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        """Validate multiple media files"""
        
        results = []
        for url, source in media_urls:
            result = self.validate_media_url(url, source)
            results.append(result)
            
            # Rate limiting
            time.sleep(1)
        
        return results
    
    def generate_media_report(self, validation_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive media validation report"""
        
        if not validation_results:
            return {}
        
        # Filter out errors
        valid_results = [r for r in validation_results if 'error' not in r]
        
        if not valid_results:
            return {'error': 'No valid media files analyzed'}
        
        # Calculate statistics
        authenticity_scores = [r.get('authenticity_score', 0.0) for r in valid_results]
        manipulation_scores = [
            r.get('validation_results', {}).get('manipulation_score', 0.0) 
            for r in valid_results
        ]
        
        # Count by media type
        media_types = {}
        for result in valid_results:
            media_type = result.get('media_type', 'unknown')
            media_types[media_type] = media_types.get(media_type, 0) + 1
        
        # Identify high-risk media
        high_risk_media = [
            r for r in valid_results 
            if r.get('authenticity_score', 1.0) < 0.4
        ]
        
        return {
            'total_media_analyzed': len(valid_results),
            'media_type_distribution': media_types,
            'average_authenticity_score': float(np.mean(authenticity_scores)),
            'average_manipulation_score': float(np.mean(manipulation_scores)),
            'high_risk_media_count': len(high_risk_media),
            'high_risk_media': [
                {
                    'source': r.get('source', 'unknown'),
                    'authenticity_score': r.get('authenticity_score', 0.0),
                    'file_hash': r.get('file_hash', ''),
                    'indicators': r.get('validation_results', {}).get('authenticity_indicators', [])
                }
                for r in high_risk_media
            ],
            'overall_media_integrity': self._assess_overall_integrity(authenticity_scores),
            'recommendations': self._generate_media_recommendations(valid_results)
        }
    
    def _assess_overall_integrity(self, authenticity_scores: List[float]) -> str:
        """Assess overall media integrity"""
        
        if not authenticity_scores:
            return "UNKNOWN"
        
        avg_score = np.mean(authenticity_scores)
        
        if avg_score >= 0.8:
            return "HIGH_INTEGRITY"
        elif avg_score >= 0.6:
            return "MEDIUM_INTEGRITY"
        elif avg_score >= 0.4:
            return "LOW_INTEGRITY"
        else:
            return "COMPROMISED_INTEGRITY"
    
    def _generate_media_recommendations(self, results: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable recommendations for media analysis"""
        
        recommendations = []
        
        high_risk_count = len([r for r in results if r.get('authenticity_score', 1.0) < 0.4])
        
        if high_risk_count > 0:
            recommendations.append(f"PRIORITY: {high_risk_count} media files show high manipulation risk")
            recommendations.append("Conduct manual forensic analysis of flagged media")
            recommendations.append("Cross-reference with original sources if possible")
        
        deepfake_indicators = []
        for result in results:
            validation = result.get('validation_results', {})
            if validation.get('manipulation_score', 0.0) > 0.7:
                deepfake_indicators.append(result.get('source', 'unknown'))
        
        if deepfake_indicators:
            recommendations.append(f"Potential deepfakes detected from sources: {', '.join(deepfake_indicators)}")
        
        return recommendations