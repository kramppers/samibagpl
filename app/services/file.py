import unicodedata
import re
import os

def sanitize_filename(filename: str, max_length: int = 100) -> str:
    """
    Sanitize filename to be safe across different operating systems.
    Removes invalid characters, normalizes unicode, and limits length.
    Enhanced for Windows zip file compatibility.
    """
    if not filename:
        return "download"

    # Normalize unicode characters
    filename = unicodedata.normalize('NFKD', filename)

    # Remove non-ASCII characters that might cause issues
    filename = filename.encode('ascii', 'ignore').decode('ascii')

    # Remove or replace invalid characters for Windows/Mac/Linux
    # Invalid chars: < > : " | ? * \ / and control characters
    invalid_chars = r'[<>:"|?*\\/-\x00-\x1f\x7f]'
    filename = re.sub(invalid_chars, '_', filename)

    # Remove problematic Windows reserved names
    reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
                      'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4',
                      'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']

    name_part = filename.split('.')[0] if '.' in filename else filename
    if name_part.upper() in reserved_names:
        filename = f"file_{filename}"

    # Remove leading/trailing spaces and dots (Windows issue)
    filename = filename.strip('. ')

    # Replace multiple spaces/underscores with single ones
    filename = re.sub(r'[_\s]+', '_', filename)

    # Ensure it doesn't start with special characters
    filename = re.sub(r'^[._-]+', '', filename)

    # Remove any remaining problematic sequences
    filename = re.sub(r'__+', '_', filename)  # Multiple underscores
    filename = re.sub(r'\.\.+', '.', filename)  # Multiple dots

    # Limit length while preserving extension
    if len(filename) > max_length:
        name_part, ext_part = os.path.splitext(filename)
        max_name_length = max_length - len(ext_part)
        if max_name_length > 0:
            filename = name_part[:max_name_length] + ext_part
        else:
            filename = filename[:max_length]

    # Final cleanup - ensure no trailing dots or spaces (Windows)
    filename = filename.rstrip('. ')

    # Fallback if empty
    if not filename or filename in ['', '.', '_']:
        return "download"

    return filename


def get_media_type_for_file(file_extension: str) -> str:
    """
    Get appropriate media type based on file extension.
    Returns proper MIME type for common file types.
    """
    # Normalize extension to lowercase
    ext = file_extension.lower()

    # Common media types mapping
    media_types = {
        # Documents
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'txt': 'text/plain',
        'rtf': 'application/rtf',

        # Images
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'bmp': 'image/bmp',
        'svg': 'image/svg+xml',
        'webp': 'image/webp',

        # Audio
        'mp3': 'audio/mpeg',
        'wav': 'audio/wav',
        'ogg': 'audio/ogg',
        'flac': 'audio/flac',
        'm4a': 'audio/mp4',

        # Video
        'mp4': 'video/mp4',
        'avi': 'video/x-msvideo',
        'mov': 'video/quicktime',
        'wmv': 'video/x-ms-wmv',
        'flv': 'video/x-flv',
        'webm': 'video/webm',

        # Archives
        'zip': 'application/zip',
        'rar': 'application/vnd.rar',
        '7z': 'application/x-7z-compressed',
        'tar': 'application/x-tar',
        'gz': 'application/gzip',

        # Code files
        'js': 'application/javascript',
        'css': 'text/css',
        'html': 'text/html',
        'xml': 'application/xml',
        'json': 'application/json',
        'py': 'text/x-python',
        'java': 'text/x-java-source',
        'cpp': 'text/x-c++src',
        'c': 'text/x-csrc',
        'php': 'application/x-httpd-php',

        # Other common types
        'exe': 'application/vnd.microsoft.portable-executable',
        'dmg': 'application/x-apple-diskimage',
        'iso': 'application/x-iso9660-image',
    }

    return media_types.get(ext, 'application/octet-stream')
