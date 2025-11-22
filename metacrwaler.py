#!/usr/bin/env python3
"""
MEGA-SENTINEL: Universal Sensitive Data Extraction Platform
A comprehensive tool for extracting secrets, metadata, and sensitive data from ALL file types.
Supports: JavaScript, PDF, Office Documents, Images, Archives, Text Files, and more.
"""

import asyncio
import aiohttp
import re
import json
import sys
import argparse
import os
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict, Counter
import time
import hashlib
import urllib.parse
from urllib.robotparser import RobotFileParser
import ssl
import random
from bs4 import BeautifulSoup
import logging
import math
import datetime
from email.utils import parsedate_to_datetime
import zipfile
import tarfile
import gzip
import binascii
import base64
import struct
from io import BytesIO
import xml.etree.ElementTree as ET

# Try to import optional dependencies for advanced file parsing
try:
    import PyPDF2
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
    print("Warning: PyPDF2 not installed. PDF extraction limited.")

try:
    from PIL import Image
    import exifread
    IMAGE_SUPPORT = True
except ImportError:
    IMAGE_SUPPORT = False
    print("Warning: PIL/exifread not installed. Image metadata extraction limited.")

try:
    import olefile
    OFFICE_SUPPORT = True
except ImportError:
    OFFICE_SUPPORT = False
    print("Warning: olefile not installed. Office document extraction limited.")

try:
    import magic
    MAGIC_SUPPORT = True
except ImportError:
    MAGIC_SUPPORT = False
    print("Warning: python-magic not installed. File type detection limited.")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('MegaSentinel')

# --- Universal File Type Detector ---

class UniversalFileDetector:
    """Detect and classify file types using multiple methods."""
    
    def __init__(self):
        self.signatures = {
            # PDF
            b'%PDF-': 'pdf',
            # Office Documents
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'office',  # OLE2 (doc, xls, ppt)
            b'PK\x03\x04': 'office',  # Office Open XML (docx, xlsx, pptx)
            # Images
            b'\xFF\xD8\xFF': 'jpeg',
            b'\x89PNG\r\n\x1a\n': 'png',
            b'GIF8': 'gif',
            b'BM': 'bmp',
            b'II*\x00': 'tiff',
            b'MM\x00*': 'tiff',
            # Archives
            b'PK\x03\x04': 'zip',
            b'PK\x05\x06': 'zip',
            b'PK\x07\x08': 'zip',
            b'\x1F\x8B\x08': 'gzip',
            b'BZh': 'bzip2',
            b'\xFD7zXZ\x00': 'xz',
            b'\x37\x7A\xBC\xAF\x27\x1C': '7z',
            # Audio/Video
            b'ID3': 'mp3',
            b'\xFF\xFB': 'mp3',
            b'RIFF': 'avi/wav',
            b'\x00\x00\x00 ftyp': 'mp4',
            b'ftyp': 'mp4',
            # Text files
            b'#!/bin/bash': 'script',
            b'#!/bin/sh': 'script',
            b'#!/usr/bin/env python': 'script',
            b'<?php': 'php',
            b'<!DOCTYPE html': 'html',
            b'<html': 'html',
        }
    
    def detect_file_type(self, content: bytes, filename: str = "") -> str:
        """Detect file type from content and filename."""
        # Check magic signatures
        for signature, file_type in self.signatures.items():
            if content.startswith(signature):
                return file_type
        
        # Check filename extension
        ext = Path(filename).suffix.lower() if filename else ""
        ext_mapping = {
            '.js': 'javascript', '.jsx': 'javascript', '.ts': 'javascript',
            '.pdf': 'pdf',
            '.doc': 'office', '.docx': 'office', '.xls': 'office', '.xlsx': 'office',
            '.ppt': 'office', '.pptx': 'office',
            '.jpg': 'image', '.jpeg': 'image', '.png': 'image', '.gif': 'image',
            '.bmp': 'image', '.tiff': 'image', '.webp': 'image',
            '.zip': 'archive', '.tar': 'archive', '.gz': 'archive', '.7z': 'archive',
            '.rar': 'archive',
            '.txt': 'text', '.log': 'text', '.csv': 'text', '.json': 'text', '.xml': 'text',
            '.sql': 'database', '.db': 'database', '.sqlite': 'database',
            '.pem': 'certificate', '.key': 'certificate', '.crt': 'certificate',
            '.env': 'config', '.config': 'config', '.yml': 'config', '.yaml': 'config',
            '.php': 'php', '.html': 'html', '.htm': 'html', '.css': 'css',
        }
        
        if ext in ext_mapping:
            return ext_mapping[ext]
        
        # Try to detect text files
        try:
            content.decode('utf-8')
            return 'text'
        except:
            return 'binary'

# --- Comprehensive Sensitive Data Patterns ---

class ComprehensivePatternEngine:
    """Advanced pattern recognition for ALL types of sensitive data."""
    
    def __init__(self):
        self.patterns = self._initialize_comprehensive_patterns()
    
    def _initialize_comprehensive_patterns(self) -> Dict[str, str]:
        """Initialize comprehensive sensitive data patterns."""
        return {
            # API Keys and Secrets
            "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"[a-zA-Z0-9+/]{40}",
            "stripe_secret_key": r"sk_(live|test)_[0-9a-zA-Z]{24,}",
            "stripe_public_key": r"pk_(live|test)_[0-9a-zA-Z]{24,}",
            "github_token": r"ghp_[a-zA-Z0-9]{36}",
            "github_oauth": r"gho_[a-zA-Z0-9]{36}",
            "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
            "slack_webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            
            # Cloud Services
            "azure_account_key": r"AccountKey=[a-zA-Z0-9+/=]{88}",
            "twilio_api_key": r"SK[0-9a-fA-F]{32}",
            "sendgrid_api_key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "mailgun_api_key": r"key-[0-9a-fA-F]{32}",
            "digitalocean_token": r"dop_v1_[a-f0-9]{64}",
            "heroku_api_key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            
            # Authentication Tokens
            "jwt_token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "bearer_token": r"bearer\s+[a-zA-Z0-9._-]{20,}",
            "oauth_token": r"ya29\.[0-9a-zA-Z_-]+",
            "session_token": r"session[_-]?[iI]d?[=:\s]+['\"]?([a-zA-Z0-9=+/]{16,})['\"]?",
            
            # Cryptographic Material
            "private_key": r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
            "ssh_private_key": r"-----BEGIN\s+(?:OPENSSH|RSA)\s+PRIVATE\s+KEY-----",
            "ssh_public_key": r"ssh-(rsa|ed25519)\s+[A-Za-z0-9+/]+[=]{0,2}",
            "pgp_private_key": r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
            "pgp_public_key": r"-----BEGIN\s+PGP\s+PUBLIC\s+KEY\s+BLOCK-----",
            "certificate": r"-----BEGIN\s+CERTIFICATE-----",
            
            # Database Connections
            "mongodb_uri": r"mongodb(\+srv)?://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+(?:\?[a-zA-Z0-9._-]+=[a-zA-Z0-9._-]+(?:&[a-zA-Z0-9._-]+=[a-zA-Z0-9._-]+)*)?",
            "postgres_uri": r"postgres(ql)?://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[0-9]+/[a-zA-Z0-9._-]+",
            "mysql_uri": r"mysql://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[0-9]+/[a-zA-Z0-9._-]+",
            "redis_uri": r"redis://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[0-9]+",
            "sqlite_path": r"sqlite:///([\/a-zA-Z0-9._-]+)",
            
            # Personal Identifiable Information (PII)
            "email_address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "phone_number": r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "ip_address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "mac_address": r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})",
            
            # Web3/Blockchain
            "ethereum_address": r"0x[a-fA-F0-9]{40}",
            "bitcoin_address": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
            "metamask_seed": r"\b(?:[a-z]+\s+){11,23}[a-z]+\b",
            "private_key_hex": r"[a-fA-F0-9]{64}",
            
            # Configuration Secrets
            "env_secret": r"(?:secret|password|key|token)[=:\s]+['\"]?([a-zA-Z0-9!@#$%^&*()_+-=]{8,})['\"]?",
            "config_password": r"password[=:\s]+['\"]?([^'\"]+)['\"]?",
            "api_key_config": r"api[_-]?key[=:\s]+['\"]?([a-zA-Z0-9_-]{10,50})['\"]?",
            
            # File Paths and URLs
            "absolute_path": r"(?:/|[A-Z]:\\)[^\s\"'<>|?*]+\.[a-z]{2,4}",
            "url_path": r"https?://[^\s\"'<>]+\.[a-z]{2,4}(?:/[^\s\"'<>]*)?",
            "local_file_path": r"(?:\./|\.\./|[A-Za-z]:\\|/)[^\s\"']*\.(?:js|php|html|txt|json|xml|yml|yaml|conf|config|ini)",
            
            # Base64 encoded data
            "base64_data": r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
            
            # Hex encoded data
            "hex_encoded": r"(?:[0-9a-fA-F]{2}){8,}",
            
            # Financial data
            "bank_account": r"\b\d{8,17}\b",
            "swift_code": r"[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?",
            "iban": r"[A-Z]{2}\d{2}[A-Z0-9]{4,}",
            
            # Medical data
            "medical_record": r"MRN\s*:?\s*[A-Z0-9]{6,}",
            "health_insurance": r"HI\s*:?\s*[A-Z0-9]{8,}",
            
            # Government IDs
            "passport_number": r"[A-Z][0-9]{8}",
            "driver_license": r"[A-Z][0-9]{4,}",
        }

# --- Universal File Parser ---

class UniversalFileParser:
    """Parse and extract data from ALL file types."""
    
    def __init__(self):
        self.detector = UniversalFileDetector()
        self.pattern_engine = ComprehensivePatternEngine()
    
    async def parse_file(self, content: bytes, filename: str = "", url: str = "") -> Dict[str, Any]:
        """Parse any file type and extract sensitive data."""
        file_type = self.detector.detect_file_type(content, filename)
        
        result = {
            'filename': filename,
            'url': url,
            'file_type': file_type,
            'file_size': len(content),
            'md5_hash': hashlib.md5(content).hexdigest(),
            'sha256_hash': hashlib.sha256(content).hexdigest(),
            'extracted_data': {},
            'sensitive_patterns': [],
            'metadata': {},
            'analysis_timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            # Extract based on file type
            if file_type == 'pdf':
                result.update(await self._parse_pdf(content))
            elif file_type == 'office':
                result.update(await self._parse_office_document(content))
            elif file_type == 'image':
                result.update(await self._parse_image(content))
            elif file_type == 'archive':
                result.update(await self._parse_archive(content, filename))
            elif file_type in ['javascript', 'text', 'php', 'html', 'css']:
                result.update(await self._parse_text_content(content))
            else:
                # Fallback: try to extract from any binary file
                result.update(await self._parse_binary_content(content))
            
            # Always run pattern matching on raw content
            text_content = self._extract_text_from_binary(content)
            if text_content:
                result['sensitive_patterns'] = self._find_sensitive_patterns(text_content)
            
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Error parsing {filename}: {e}")
        
        return result
    
    async def _parse_pdf(self, content: bytes) -> Dict[str, Any]:
        """Extract data from PDF files."""
        extracted = {'pdf_data': {}}
        
        if not PDF_SUPPORT:
            extracted['pdf_data']['error'] = "PDF parsing requires PyPDF2"
            return extracted
        
        try:
            pdf_file = BytesIO(content)
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            
            # Extract metadata
            info = pdf_reader.metadata
            if info:
                extracted['pdf_data']['metadata'] = dict(info)
            
            # Extract text from all pages
            text_content = ""
            for page_num in range(len(pdf_reader.pages)):
                try:
                    page = pdf_reader.pages[page_num]
                    text_content += page.extract_text() + "\n"
                except Exception as e:
                    logger.warning(f"Error extracting text from PDF page {page_num}: {e}")
            
            if text_content:
                extracted['pdf_data']['text_content'] = text_content
                extracted['pdf_data']['page_count'] = len(pdf_reader.pages)
                
                # Find patterns in text
                patterns = self._find_sensitive_patterns(text_content)
                if patterns:
                    extracted['pdf_data']['sensitive_patterns_in_text'] = patterns
            
        except Exception as e:
            extracted['pdf_data']['error'] = f"PDF parsing error: {str(e)}"
        
        return extracted
    
    async def _parse_office_document(self, content: bytes) -> Dict[str, Any]:
        """Extract data from Office documents (doc, docx, xls, xlsx, etc.)."""
        extracted = {'office_data': {}}
        
        try:
            # Check if it's OLE2 format (old Office)
            if content.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1') and OFFICE_SUPPORT:
                extracted['office_data'].update(self._parse_ole_document(content))
            
            # Check if it's Office Open XML (new Office)
            elif content.startswith(b'PK\x03\x04'):
                extracted['office_data'].update(await self._parse_office_open_xml(content))
            
            else:
                extracted['office_data']['error'] = "Unsupported Office format"
                
        except Exception as e:
            extracted['office_data']['error'] = f"Office document parsing error: {str(e)}"
        
        return extracted
    
    def _parse_ole_document(self, content: bytes) -> Dict[str, Any]:
        """Parse OLE2 format Office documents."""
        result = {}
        
        if not OFFICE_SUPPORT:
            result['error'] = "OLE parsing requires olefile"
            return result
        
        try:
            ole = olefile.OleFileIO(BytesIO(content))
            
            # Extract metadata
            meta = ole.get_metadata()
            if meta:
                result['metadata'] = {
                    'author': meta.author,
                    'title': meta.title,
                    'subject': meta.subject,
                    'created': str(meta.create_time) if meta.create_time else None,
                    'modified': str(meta.last_saved_time) if meta.last_saved_time else None,
                }
            
            # List streams
            result['streams'] = list(ole.listdir())
            
            # Try to extract text from common streams
            text_content = ""
            for stream_path in ole.listdir():
                try:
                    stream_name = '/'.join(stream_path)
                    if 'WordDocument' in stream_name or 'PowerPoint' in stream_name:
                        stream_data = ole.openstream(stream_path).read()
                        # Simple text extraction from binary
                        text_content += self._extract_text_from_binary(stream_data)
                except:
                    continue
            
            if text_content:
                result['extracted_text'] = text_content
                patterns = self._find_sensitive_patterns(text_content)
                if patterns:
                    result['sensitive_patterns'] = patterns
            
            ole.close()
            
        except Exception as e:
            result['error'] = f"OLE parsing error: {str(e)}"
        
        return result
    
    async def _parse_office_open_xml(self, content: bytes) -> Dict[str, Any]:
        """Parse Office Open XML format (docx, xlsx, pptx)."""
        result = {}
        
        try:
            with zipfile.ZipFile(BytesIO(content)) as zip_ref:
                # Extract core properties
                if 'docProps/core.xml' in zip_ref.namelist():
                    core_xml = zip_ref.read('docProps/core.xml')
                    result['metadata'] = self._parse_office_metadata(core_xml)
                
                # Extract text content from document
                text_content = ""
                for name in zip_ref.namelist():
                    if name.endswith(('.xml', '.rels')) and 'word/' in name:
                        try:
                            xml_content = zip_ref.read(name)
                            text_content += self._extract_text_from_xml(xml_content) + " "
                        except:
                            continue
                
                if text_content:
                    result['extracted_text'] = text_content.strip()
                    patterns = self._find_sensitive_patterns(text_content)
                    if patterns:
                        result['sensitive_patterns'] = patterns
                
                # List all files in archive
                result['contained_files'] = zip_ref.namelist()
                
        except Exception as e:
            result['error'] = f"Office Open XML parsing error: {str(e)}"
        
        return result
    
    async def _parse_image(self, content: bytes) -> Dict[str, Any]:
        """Extract metadata from image files."""
        extracted = {'image_data': {}}
        
        if not IMAGE_SUPPORT:
            extracted['image_data']['error'] = "Image parsing requires PIL/exifread"
            return extracted
        
        try:
            image = Image.open(BytesIO(content))
            
            # Basic image info
            extracted['image_data']['format'] = image.format
            extracted['image_data']['size'] = image.size
            extracted['image_data']['mode'] = image.mode
            
            # EXIF data
            try:
                exif_data = image._getexif()
                if exif_data:
                    exif_dict = {}
                    for tag_id, value in exif_data.items():
                        tag = ExifTags.TAGS.get(tag_id, tag_id)
                        exif_dict[tag] = str(value)
                    extracted['image_data']['exif'] = exif_dict
            except:
                pass
            
            # GPS data extraction
            gps_info = self._extract_gps_info(content)
            if gps_info:
                extracted['image_data']['gps'] = gps_info
            
        except Exception as e:
            extracted['image_data']['error'] = f"Image parsing error: {str(e)}"
        
        return extracted
    
    def _extract_gps_info(self, content: bytes) -> Dict[str, Any]:
        """Extract GPS coordinates from image EXIF data."""
        try:
            tags = exifread.process_file(BytesIO(content))
            gps_data = {}
            
            if 'GPS GPSLatitude' in tags and 'GPS GPSLongitude' in tags:
                lat = self._convert_to_degrees(tags['GPS GPSLatitude'].values)
                lon = self._convert_to_degrees(tags['GPS GPSLongitude'].values)
                
                if 'GPS GPSLatitudeRef' in tags:
                    lat_ref = tags['GPS GPSLatitudeRef'].values
                    if lat_ref == 'S':
                        lat = -lat
                
                if 'GPS GPSLongitudeRef' in tags:
                    lon_ref = tags['GPS GPSLongitudeRef'].values
                    if lon_ref == 'W':
                        lon = -lon
                
                gps_data['latitude'] = lat
                gps_data['longitude'] = lon
            
            return gps_data
        except:
            return {}
    
    def _convert_to_degrees(self, value) -> float:
        """Convert GPS coordinates to decimal degrees."""
        d, m, s = value
        return float(d) + float(m) / 60 + float(s) / 3600
    
    async def _parse_archive(self, content: bytes, filename: str) -> Dict[str, Any]:
        """Extract files from archives and analyze them."""
        extracted = {'archive_data': {}}
        
        try:
            archive_files = []
            
            # Try different archive formats
            if filename.endswith('.zip') or content.startswith(b'PK'):
                with zipfile.ZipFile(BytesIO(content)) as zip_ref:
                    for file_info in zip_ref.infolist():
                        if not file_info.is_dir():
                            file_content = zip_ref.read(file_info.filename)
                            archive_files.append({
                                'filename': file_info.filename,
                                'size': file_info.file_size,
                                'compressed_size': file_info.compress_size,
                                'content_preview': file_content[:1000]  # First 1000 bytes
                            })
            
            elif filename.endswith('.tar') or content.startswith(b'ustar'):
                with tarfile.open(fileobj=BytesIO(content)) as tar_ref:
                    for member in tar_ref.getmembers():
                        if member.isfile():
                            file_content = tar_ref.extractfile(member).read()
                            archive_files.append({
                                'filename': member.name,
                                'size': member.size,
                                'content_preview': file_content[:1000]
                            })
            
            elif filename.endswith('.gz') or content.startswith(b'\x1F\x8B\x08'):
                with gzip.GzipFile(fileobj=BytesIO(content)) as gz_ref:
                    decompressed = gz_ref.read()
                    archive_files.append({
                        'filename': 'decompressed_content',
                        'size': len(decompressed),
                        'content_preview': decompressed[:1000]
                    })
            
            extracted['archive_data']['files'] = archive_files
            extracted['archive_data']['file_count'] = len(archive_files)
            
        except Exception as e:
            extracted['archive_data']['error'] = f"Archive parsing error: {str(e)}"
        
        return extracted
    
    async def _parse_text_content(self, content: bytes) -> Dict[str, Any]:
        """Parse text-based files."""
        extracted = {'text_data': {}}
        
        try:
            text_content = content.decode('utf-8', errors='ignore')
            extracted['text_data']['content_preview'] = text_content[:5000]  # First 5000 chars
            extracted['text_data']['line_count'] = len(text_content.split('\n'))
            extracted['text_data']['word_count'] = len(text_content.split())
            
            # Extract comments from code files
            if any(ext in (extracted.get('filename', '') or '') for ext in ['.js', '.php', '.html', '.css']):
                comments = self._extract_comments(text_content)
                if comments:
                    extracted['text_data']['comments'] = comments
            
        except Exception as e:
            extracted['text_data']['error'] = f"Text parsing error: {str(e)}"
        
        return extracted
    
    async def _parse_binary_content(self, content: bytes) -> Dict[str, Any]:
        """Parse binary files for embedded strings and patterns."""
        extracted = {'binary_data': {}}
        
        try:
            # Extract strings from binary
            strings = self._extract_strings_from_binary(content)
            if strings:
                extracted['binary_data']['embedded_strings'] = strings[:100]  # Limit to 100 strings
            
            # Look for base64 encoded data
            base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
            base64_matches = base64_pattern.findall(content.decode('latin-1', errors='ignore'))
            if base64_matches:
                extracted['binary_data']['base64_blocks'] = base64_matches[:10]
            
        except Exception as e:
            extracted['binary_data']['error'] = f"Binary parsing error: {str(e)}"
        
        return extracted
    
    def _extract_text_from_binary(self, content: bytes) -> str:
        """Extract readable text from binary data."""
        try:
            # Try UTF-8 first
            text = content.decode('utf-8', errors='ignore')
            if len(text) > 10:  # If we got reasonable text
                return text
        except:
            pass
        
        try:
            # Fallback to Latin-1
            text = content.decode('latin-1', errors='ignore')
            return text
        except:
            return ""
    
    def _extract_strings_from_binary(self, content: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII strings from binary data."""
        strings = []
        current_string = ""
        
        for byte in content:
            char = chr(byte) if 32 <= byte <= 126 else ''
            if char:
                current_string += char
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def _extract_text_from_xml(self, content: bytes) -> str:
        """Extract text content from XML."""
        try:
            root = ET.fromstring(content)
            text_parts = []
            
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    text_parts.append(elem.text.strip())
                if elem.tail and elem.tail.strip():
                    text_parts.append(elem.tail.strip())
            
            return ' '.join(text_parts)
        except:
            return ""
    
    def _parse_office_metadata(self, xml_content: bytes) -> Dict[str, str]:
        """Parse Office document metadata from XML."""
        try:
            root = ET.fromstring(xml_content)
            ns = {'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'}
            
            metadata = {}
            fields = {
                'creator': 'author',
                'lastModifiedBy': 'last_modified_by',
                'created': 'created_date',
                'modified': 'modified_date',
                'title': 'title',
                'subject': 'subject',
                'description': 'description',
                'keywords': 'keywords',
            }
            
            for elem_name, field_name in fields.items():
                elem = root.find(f'cp:{elem_name}', ns)
                if elem is not None and elem.text:
                    metadata[field_name] = elem.text
            
            return metadata
        except:
            return {}
    
    def _extract_comments(self, text: str) -> List[str]:
        """Extract comments from source code."""
        comments = []
        
        # Single-line comments
        single_line = re.findall(r'//\s*(.+)$', text, re.MULTILINE)
        comments.extend(single_line)
        
        # Multi-line comments
        multi_line = re.findall(r'/\*\s*(.*?)\*/', text, re.DOTALL)
        for comment in multi_line:
            # Split multi-line comments into individual lines
            lines = [line.strip() for line in comment.split('\n') if line.strip()]
            comments.extend(lines)
        
        # HTML/PHP comments
        html_comments = re.findall(r'<!--\s*(.*?)\s*-->', text, re.DOTALL)
        for comment in html_comments:
            lines = [line.strip() for line in comment.split('\n') if line.strip()]
            comments.extend(lines)
        
        return [c for c in comments if len(c) > 5]  # Only meaningful comments
    
    def _find_sensitive_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Find sensitive data patterns in text."""
        findings = []
        
        for pattern_name, pattern in self.pattern_engine.patterns.items():
            try:
                matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    matched_text = match.group()
                    
                    # Skip obvious false positives
                    if self._is_false_positive(matched_text, pattern_name):
                        continue
                    
                    findings.append({
                        'pattern_type': pattern_name,
                        'matched_text': self._mask_sensitive_data(matched_text),
                        'full_match': matched_text,
                        'position': match.span(),
                        'risk_score': self._calculate_pattern_risk(pattern_name, matched_text)
                    })
                    
            except Exception as e:
                logger.warning(f"Pattern matching error for {pattern_name}: {e}")
                continue
        
        return findings
    
    def _is_false_positive(self, text: str, pattern_type: str) -> bool:
        """Check if a match is likely a false positive."""
        # Common false positive patterns
        false_positives = {
            'email_address': ['example.com', 'test@test.com', 'user@example.com'],
            'ip_address': ['0.0.0.0', '127.0.0.1', '255.255.255.255'],
            'credit_card': ['0000-0000-0000-0000', '1234-5678-9012-3456'],
        }
        
        if pattern_type in false_positives:
            for fp in false_positives[pattern_type]:
                if fp in text.lower():
                    return True
        
        return False
    
    def _calculate_pattern_risk(self, pattern_type: str, matched_text: str) -> float:
        """Calculate risk score for a pattern match."""
        risk_scores = {
            'private_key': 1.0, 'ssh_private_key': 1.0, 'pgp_private_key': 1.0,
            'aws_secret_key': 0.9, 'stripe_secret_key': 0.9,
            'credit_card': 0.9, 'ssn': 0.9, 'passport_number': 0.8,
            'api_key': 0.7, 'oauth_token': 0.7, 'jwt_token': 0.6,
            'email_address': 0.3, 'phone_number': 0.4,
        }
        
        base_risk = risk_scores.get(pattern_type, 0.5)
        
        # Adjust based on context
        if any(keyword in matched_text.lower() for keyword in ['test', 'example', 'dummy']):
            base_risk *= 0.3  # Reduce risk for test data
        
        return min(base_risk, 1.0)
    
    def _mask_sensitive_data(self, text: str) -> str:
        """Mask sensitive data for safe display."""
        if len(text) <= 8:
            return text
        
        return text[:4] + '*' * max(4, len(text) - 8) + text[-4:]

# --- Enhanced Web Crawler with Universal Support ---

class UniversalCrawler:
    """Crawler that can handle and extract data from ALL file types."""
    
    def __init__(self, max_pages: int = 100, max_depth: int = 3, delay: float = 1.0,
                 crawl_mode: str = 'internal', base_domain: str = None,
                 extract_all: bool = True):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay
        self.crawl_mode = crawl_mode
        self.base_domain = base_domain
        self.extract_all = extract_all
        self.visited_urls = set()
        self.discovered_files = set()
        self.parser = UniversalFileParser()
        self.session = None
        self.robots_parsers = {}
        
    async def __aenter__(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context, limit=20)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def crawl_site(self, start_url: str) -> List[Dict[str, Any]]:
        """Crawl a website and extract data from ALL discovered files."""
        logger.info(f"Starting universal crawl of: {start_url}")
        
        if not self.base_domain:
            parsed_url = urllib.parse.urlparse(start_url)
            self.base_domain = parsed_url.netloc
        
        self.visited_urls.clear()
        self.discovered_files.clear()
        
        parsed_url = urllib.parse.urlparse(start_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        if await self._check_robots_txt(base_url, start_url):
            await self._crawl_page(start_url, depth=0)
            
            pending_tasks = [t for t in asyncio.all_tasks() 
                           if t is not asyncio.current_task() and not t.done()]
            if pending_tasks:
                await asyncio.wait(pending_tasks, timeout=30.0)
        else:
            logger.warning(f"robots.txt disallows crawling: {start_url}")
        
        # Process all discovered files
        results = []
        for file_url in self.discovered_files:
            try:
                file_data = await self._fetch_and_parse_file(file_url)
                if file_data:
                    results.append(file_data)
            except Exception as e:
                logger.error(f"Error processing {file_url}: {e}")
        
        logger.info(f"Crawl completed. Found {len(self.discovered_files)} files, processed {len(results)}.")
        return results
    
    async def _fetch_and_parse_file(self, url: str) -> Dict[str, Any]:
        """Fetch a file and parse it for sensitive data."""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.read()
                    filename = url.split('/')[-1] or 'unknown'
                    
                    # Parse the file
                    result = await self.parser.parse_file(content, filename, url)
                    result['http_headers'] = dict(response.headers)
                    result['file_size_downloaded'] = len(content)
                    
                    return result
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
        
        return {}
    
    async def _crawl_page(self, url: str, depth: int):
        """Recursively crawl a page and discover files."""
        if (depth > self.max_depth or len(self.visited_urls) >= self.max_pages or 
            url in self.visited_urls or not self.session or self.session.closed):
            return
        
        self.visited_urls.add(url)
        logger.info(f"Crawling [{depth}]: {url}")
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content_type = response.headers.get('content-type', '')
                    content = await response.read()
                    
                    if 'text/html' in content_type:
                        await self._extract_files_from_html(content, url)
                        await self._extract_and_follow_links(content, url, depth)
                    else:
                        # This is a direct file - add to discovery list
                        if self._should_crawl_url(url):
                            self.discovered_files.add(url)
                    
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
        
        await asyncio.sleep(self.delay + random.uniform(0, 0.5))
    
    async def _extract_files_from_html(self, html_content: bytes, base_url: str):
        """Extract file URLs from HTML content."""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Script files
        for script in soup.find_all('script', src=True):
            file_url = urllib.parse.urljoin(base_url, script['src'])
            if self._should_crawl_url(file_url):
                self.discovered_files.add(file_url)
        
        # Link elements (CSS, etc.)
        for link in soup.find_all('link', href=True):
            file_url = urllib.parse.urljoin(base_url, link['href'])
            if self._should_crawl_url(file_url):
                self.discovered_files.add(file_url)
        
        # Anchor tags with file extensions
        for anchor in soup.find_all('a', href=True):
            href = anchor['href']
            file_url = urllib.parse.urljoin(base_url, href)
            
            # Check if it's a file (not HTML)
            if (self._is_file_url(file_url) and self._should_crawl_url(file_url)):
                self.discovered_files.add(file_url)
    
    async def _extract_and_follow_links(self, html_content: bytes, base_url: str, depth: int):
        """Extract and follow links from HTML content."""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        links_found = 0
        tasks = []
        
        for link in soup.find_all('a', href=True):
            if links_found >= 10:
                break
                
            href = link['href']
            full_url = urllib.parse.urljoin(base_url, href)
            
            if self._should_crawl_url(full_url) and not self._is_file_url(full_url):
                if (depth < self.max_depth and 
                    len(self.visited_urls) < self.max_pages and 
                    full_url not in self.visited_urls and
                    self.session and not self.session.closed):
                    
                    task = asyncio.create_task(self._crawl_page(full_url, depth + 1))
                    tasks.append(task)
                    links_found += 1
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def _is_file_url(self, url: str) -> bool:
        """Check if URL points to a file (not HTML)."""
        file_extensions = [
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.js', '.css', '.json', '.xml', '.txt', '.csv',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.zip', '.tar', '.gz', '.7z', '.rar',
            '.pem', '.key', '.crt', '.cer',
        ]
        
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        
        return any(path.endswith(ext) for ext in file_extensions)
    
    def _should_crawl_url(self, url: str) -> bool:
        """Determine if URL should be crawled."""
        if not self._is_valid_url(url):
            return False
        
        parsed_url = urllib.parse.urlparse(url)
        
        if self.crawl_mode == 'internal':
            return parsed_url.netloc == self.base_domain
        elif self.crawl_mode == 'external':
            return True
        else:
            return parsed_url.netloc == self.base_domain
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL for crawling."""
        parsed = urllib.parse.urlparse(url)
        return (parsed.scheme in ['http', 'https'] and 
                parsed.netloc and 
                not parsed.fragment and
                not url.startswith('mailto:'))
    
    async def _check_robots_txt(self, base_url: str, url: str) -> bool:
        """Check if URL is allowed by robots.txt."""
        if base_url not in self.robots_parsers:
            robots_url = f"{base_url}/robots.txt"
            try:
                async with self.session.get(robots_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        parser = RobotFileParser()
                        parser.parse(content.splitlines())
                        self.robots_parsers[base_url] = parser
                    else:
                        self.robots_parsers[base_url] = None
            except Exception as e:
                logger.warning(f"Failed to fetch robots.txt: {e}")
                self.robots_parsers[base_url] = None
        
        parser = self.robots_parsers.get(base_url)
        if parser:
            return parser.can_fetch("*", url)
        return True

# --- Mega Sentinel CLI ---

class MegaSentinelCLI:
    """Comprehensive CLI for universal sensitive data extraction."""
    
    def __init__(self):
        self.parser = UniversalFileParser()
        self.colors = {
            'RED': '\033[91m', 'GREEN': '\033[92m', 'YELLOW': '\033[93m', 
            'BLUE': '\033[94m', 'MAGENTA': '\033[95m', 'CYAN': '\033[96m',
            'BOLD': '\033[1m', 'UNDERLINE': '\033[4m', 'END': '\033[0m'
        }
    
    async def analyze_targets(self, targets: List[str], output_file: str = None,
                            crawl: bool = False, crawl_depth: int = 2,
                            extract_all: bool = True):
        """Analyze targets for sensitive data."""
        all_results = []
        
        if crawl:
            for target in targets:
                if target.startswith(('http://', 'https://')):
                    print(f"{self.colors['BLUE']}[*]{self.colors['END']} Crawling: {target}")
                    async with UniversalCrawler(max_depth=crawl_depth, extract_all=extract_all) as crawler:
                        results = await crawler.crawl_site(target)
                        all_results.extend(results)
                        print(f"{self.colors['GREEN']}[+]{self.colors['END']} Found {len(results)} files from {target}")
        
        # Analyze direct targets
        for target in targets:
            print(f"{self.colors['BLUE']}[*]{self.colors['END']} Analyzing: {target}")
            try:
                if target.startswith(('http://', 'https://')):
                    content, headers = await self._fetch_content(target)
                    if content:
                        result = await self.parser.parse_file(content, target, target)
                        all_results.append(result)
                        self._display_results(result)
                else:
                    # Local file
                    if os.path.exists(target):
                        with open(target, 'rb') as f:
                            content = f.read()
                        result = await self.parser.parse_file(content, target, target)
                        all_results.append(result)
                        self._display_results(result)
                    else:
                        print(f"{self.colors['YELLOW']}[!]{self.colors['END']} File not found: {target}")
                
                if output_file:
                    self._save_results(all_results, output_file)
                    
            except Exception as e:
                print(f"{self.colors['RED']}[!]{self.colors['END']} Error analyzing {target}: {e}")
        
        # Display summary
        if all_results:
            self._display_summary(all_results)
    
    async def _fetch_content(self, url: str) -> Tuple[bytes, Dict]:
        """Fetch content from URL."""
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                headers = {'User-Agent': 'Mozilla/5.0 (compatible; MegaSentinel/1.0)'}
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        content = await response.read()
                        return content, dict(response.headers)
                    else:
                        return b'', {}
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return b'', {}
    
    def _display_results(self, result: Dict[str, Any]):
        """Display analysis results."""
        filename = result.get('filename', 'Unknown')
        file_type = result.get('file_type', 'unknown')
        
        print(f"\n{self.colors['BOLD']}{self.colors['CYAN']}=== ANALYSIS: {filename} ({file_type}) ==={self.colors['END']}")
        
        # Display sensitive patterns
        patterns = result.get('sensitive_patterns', [])
        if patterns:
            high_risk = [p for p in patterns if p['risk_score'] >= 0.7]
            medium_risk = [p for p in patterns if 0.4 <= p['risk_score'] < 0.7]
            
            if high_risk:
                print(f"\n{self.colors['RED']}{self.colors['BOLD']}🚨 HIGH RISK FINDINGS:{self.colors['END']}")
                for pattern in high_risk[:5]:
                    print(f"  {self.colors['RED']}↳ {pattern['pattern_type']}{self.colors['END']}")
                    print(f"    Match: {pattern['matched_text']}")
                    print(f"    Risk: {pattern['risk_score']:.2f}")
            
            if medium_risk:
                print(f"\n{self.colors['YELLOW']}⚠️  MEDIUM RISK FINDINGS:{self.colors['END']}")
                for pattern in medium_risk[:3]:
                    print(f"  {self.colors['YELLOW']}↳ {pattern['pattern_type']}{self.colors['END']}")
                    print(f"    Match: {pattern['matched_text']}")
        
        # Display file-specific data
        for data_type, data in result.get('extracted_data', {}).items():
            if data and not data.get('error'):
                print(f"\n{self.colors['BLUE']}📁 {data_type.upper()} DATA:{self.colors['END']}")
                if 'metadata' in data:
                    for key, value in list(data['metadata'].items())[:3]:
                        print(f"  {key}: {value}")
        
        # Display statistics
        print(f"\n{self.colors['GREEN']}📊 STATISTICS:{self.colors['END']}")
        print(f"  File Size: {result.get('file_size', 0)} bytes")
        print(f"  Sensitive Patterns Found: {len(patterns)}")
        print(f"  File Type: {file_type}")
        print(f"  MD5: {result.get('md5_hash', 'N/A')[:16]}...")
    
    def _display_summary(self, results: List[Dict[str, Any]]):
        """Display summary report."""
        print(f"\n{self.colors['BOLD']}{self.colors['MAGENTA']}📊 COMPREHENSIVE SUMMARY{'='*50}{self.colors['END']}")
        
        total_files = len(results)
        total_patterns = sum(len(r.get('sensitive_patterns', [])) for r in results)
        high_risk_files = sum(1 for r in results if any(p['risk_score'] >= 0.7 for p in r.get('sensitive_patterns', [])))
        
        file_types = Counter(r.get('file_type', 'unknown') for r in results)
        
        print(f"Total Files Analyzed: {total_files}")
        print(f"Total Sensitive Patterns Found: {total_patterns}")
        print(f"High Risk Files: {high_risk_files}")
        print(f"File Types: {dict(file_types)}")
        
        # Top sensitive pattern types
        all_patterns = []
        for result in results:
            all_patterns.extend(result.get('sensitive_patterns', []))
        
        pattern_counts = Counter(p['pattern_type'] for p in all_patterns)
        if pattern_counts:
            print(f"\n{self.colors['RED']}🔍 TOP SENSITIVE PATTERNS:{self.colors['END']}")
            for pattern_type, count in pattern_counts.most_common(10):
                print(f"  {pattern_type}: {count} occurrences")
    
    def _save_results(self, results: List[Dict], output_file: str):
        """Save results to JSON file."""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"{self.colors['GREEN']}[+]{self.colors['END']} Results saved to: {output_file}")
        except Exception as e:
            print(f"{self.colors['RED']}[!]{self.colors['END']} Failed to save results: {e}")

# --- Main Execution ---

async def main():
    """Main execution function."""
    cli = MegaSentinelCLI()
    
    parser = argparse.ArgumentParser(
        description='MEGA-SENTINEL: Universal Sensitive Data Extraction Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Analyze a single file
  python mega_sentinel.py -f document.pdf
  
  # Analyze a website with crawling
  python mega_sentinel.py -u https://example.com --crawl
  
  # Analyze multiple files
  python mega_sentinel.py -f file1.pdf -f file2.docx -f file3.jpg
  
  # Analyze with output file
  python mega_sentinel.py -u https://example.com --crawl -o results.json
  
  # Analyze local directory
  python mega_sentinel.py -d ./documents

Supported File Types:
  📄 Documents: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX
  🖼️  Images: JPG, PNG, GIF, BMP, TIFF, WEBP
  📁 Archives: ZIP, TAR, GZ, 7Z, RAR
  🔐 Certificates: PEM, KEY, CRT, CER
  💻 Code: JS, PHP, HTML, CSS, JSON, XML
  📊 Data: CSV, TXT, LOG, SQL
  🌐 Web: All web-accessible files
        '''
    )
    
    parser.add_argument('-u', '--url', action='append', help='Target URL to analyze')
    parser.add_argument('-f', '--file', action='append', help='Local file to analyze')
    parser.add_argument('-d', '--directory', help='Directory to analyze recursively')
    parser.add_argument('-l', '--list', help='File containing list of targets')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('--crawl', action='store_true', help='Crawl website to discover files')
    parser.add_argument('--crawl-depth', type=int, default=2, help='Maximum crawl depth')
    parser.add_argument('--max-files', type=int, default=100, help='Maximum files to analyze')
    
    args = parser.parse_args()
    
    targets = []
    
    if args.url:
        targets.extend(args.url)
    
    if args.file:
        targets.extend(args.file)
    
    if args.directory:
        if os.path.isdir(args.directory):
            for root, dirs, files in os.walk(args.directory):
                for file in files:
                    targets.append(os.path.join(root, file))
        else:
            print(f"Error: Directory not found: {args.directory}")
            return
    
    if args.list:
        try:
            with open(args.list, 'r') as f:
                targets.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"Error: Target list file not found: {args.list}")
            return
    
    if not targets:
        print("Error: No targets specified. Use -u, -f, -d, or -l to specify targets.")
        print("Use -h for help.")
        return
    
    # Limit number of files if specified
    if args.max_files and len(targets) > args.max_files:
        print(f"Limiting analysis to {args.max_files} files (use --max-files to change)")
        targets = targets[:args.max_files]
    
    await cli.analyze_targets(
        targets=targets,
        output_file=args.output,
        crawl=args.crawl,
        crawl_depth=args.crawl_depth
    )

if __name__ == '__main__':
    # Check for basic dependencies
    try:
        import aiohttp
        from bs4 import BeautifulSoup
    except ImportError as e:
        print(f"Error: Missing required dependency - {e}")
        print("Please install required packages:")
        print("pip install aiohttp beautifulsoup4")
        sys.exit(1)
    
    # Warn about optional dependencies
    if not PDF_SUPPORT:
        print("Note: Install PyPDF2 for full PDF support: pip install PyPDF2")
    if not IMAGE_SUPPORT:
        print("Note: Install PIL and exifread for image metadata: pip install Pillow exifread")
    if not OFFICE_SUPPORT:
        print("Note: Install olefile for Office document support: pip install olefile")
    
    print("🚀 MEGA-SENTINEL: Universal Sensitive Data Extraction")
    print("=" * 60)
    
    # Run the application
    asyncio.run(main())
