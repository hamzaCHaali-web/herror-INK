from flask import Flask, abort, request, jsonify, send_file
from datetime import datetime, timedelta, timezone
import hashlib
import math
import os
import re
import tempfile
import uuid
from pathlib import Path

from database import Database
from security import Security

APP_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = APP_DIR / 'dist'

app = Flask(__name__, static_folder=None)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')

database_path = Path(os.environ.get('DATABASE_PATH', 'instance/horrorlink.db'))
if not database_path.is_absolute():
    database_path = APP_DIR / database_path
db = Database(str(database_path))

ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:5173,http://localhost:3000').split(',')
ROOM_EXPIRATION_MINUTES = int(os.environ.get('ROOM_EXPIRATION_MINUTES', 60))
DEVICE_ONLINE_TIMEOUT_MINUTES = int(os.environ.get('DEVICE_ONLINE_TIMEOUT_MINUTES', 5))
COMMAND_EXPIRATION_MINUTES = int(os.environ.get('COMMAND_EXPIRATION_MINUTES', 5))
MAX_PIN_ATTEMPTS = int(os.environ.get('MAX_PIN_ATTEMPTS', 10))
PIN_RATE_LIMIT_WINDOW_MINUTES = int(os.environ.get('PIN_RATE_LIMIT_WINDOW_MINUTES', 5))
MAX_AUDIO_UPLOAD_BYTES = int(os.environ.get('MAX_AUDIO_UPLOAD_BYTES', 50 * 1024 * 1024))
if MAX_AUDIO_UPLOAD_BYTES <= 0:
    raise RuntimeError('MAX_AUDIO_UPLOAD_BYTES must be greater than zero')
ALLOWED_AUDIO_FORMATS = {
    item.strip().lower().lstrip('.')
    for item in os.environ.get('ALLOWED_AUDIO_FORMATS', 'mp3,wav,ogg,m4a').split(',')
    if item.strip()
}
AUDIO_STORAGE_DIR = Path(os.environ.get('AUDIO_STORAGE_DIR', APP_DIR / 'instance' / 'audio'))
if not AUDIO_STORAGE_DIR.is_absolute():
    AUDIO_STORAGE_DIR = APP_DIR / AUDIO_STORAGE_DIR
AUDIO_STORAGE_DIR = AUDIO_STORAGE_DIR.resolve()
try:
    if os.path.commonpath((str(FRONTEND_DIST.resolve()), str(AUDIO_STORAGE_DIR))) == str(FRONTEND_DIST.resolve()):
        raise RuntimeError('AUDIO_STORAGE_DIR must be outside backend/dist')
except ValueError:
    pass
app.config['MAX_CONTENT_LENGTH'] = MAX_AUDIO_UPLOAD_BYTES + 1024 * 1024
_AUDIO_FILE_PATTERN = re.compile(r'audio_([0-9a-f]{32})\.(mp3|wav|ogg|m4a)$')

VALID_SOUNDS = ['creepy_whisper', 'door_creak', 'footsteps', 'screech', 'thunder', 'laugh', 'breathing', 'growl']
AUDIO_FORMATS = {
    '.mp3': ('audio/mpeg',),
    '.wav': ('audio/wav', 'audio/x-wav'),
    '.ogg': ('audio/ogg', 'application/ogg'),
    '.m4a': ('audio/mp4', 'audio/x-m4a'),
}


def bearer_token():
    auth_header = request.headers.get('Authorization', '')
    return auth_header[7:].strip() if auth_header.startswith('Bearer ') else None


def audio_metadata(row):
    return {
        'id': row['id'],
        'name': row['name'],
        'mime_type': row['mime_type'],
        'file_size': row['file_size'],
        'duration_seconds': row['duration_seconds'],
        'checksum_sha256': row['checksum_sha256'],
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
    }


def valid_audio_signature(extension, header):
    if extension == '.wav':
        return len(header) >= 12 and header[:4] == b'RIFF' and header[8:12] == b'WAVE'
    if extension == '.ogg':
        return header.startswith(b'OggS')
    if extension == '.m4a':
        return len(header) >= 12 and header[4:8] == b'ftyp'
    if extension == '.mp3':
        return header.startswith(b'ID3') or (
            len(header) >= 2 and header[0] == 0xFF and header[1] & 0xE0 == 0xE0
        )
    return False


def valid_audio_storage_record(audio):
    match = _AUDIO_FILE_PATTERN.fullmatch(audio['storage_filename'])
    return bool(match and match.group(1) == audio['id'])


def room_audio_access(conn, room_id, audio_id):
    return conn.execute(
        '''SELECT a.* FROM audio_files a
           JOIN room_audio ra ON ra.audio_id = a.id
           WHERE ra.room_id = ? AND a.id = ?''',
        (room_id, audio_id),
    ).fetchone()


def reconcile_audio_storage():
    AUDIO_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    conn = db.get_connection()
    try:
        rows = conn.execute('SELECT id, storage_filename, file_size, checksum_sha256 FROM audio_files').fetchall()
    finally:
        conn.close()
    registered = {row['storage_filename']: row for row in rows}
    by_id = {row['id']: row for row in rows}
    now = datetime.now(timezone.utc).timestamp()
    for row in rows:
        if (
            not valid_audio_storage_record(row)
            or row['file_size'] <= 0
            or not re.fullmatch(r'[0-9a-f]{64}', row['checksum_sha256'])
        ):
            app.logger.error('Audio metadata failed integrity checks for record %s', row['id'])
        elif not (AUDIO_STORAGE_DIR / row['storage_filename']).is_file():
            app.logger.error('Audio file is missing for record %s', row['id'])

    for path in AUDIO_STORAGE_DIR.iterdir():
        try:
            age_seconds = now - path.stat().st_mtime
            if path.name.startswith('.upload-') and age_seconds > 3600:
                path.unlink()
                continue
            tombstone_match = re.fullmatch(r'\.deleting-([0-9a-f]{32})', path.name)
            if tombstone_match and age_seconds > 3600:
                audio_id = tombstone_match.group(1)
                row = by_id.get(audio_id)
                if row:
                    original = AUDIO_STORAGE_DIR / row['storage_filename']
                    if not original.exists():
                        os.replace(str(path), str(original))
                    else:
                        path.unlink()
                else:
                    path.unlink()
                continue
            if _AUDIO_FILE_PATTERN.fullmatch(path.name) and path.name not in registered and age_seconds > 3600:
                path.unlink()
        except OSError:
            app.logger.exception('Audio storage reconciliation failed for %s', path.name)


reconcile_audio_storage()

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin and origin.strip() in [o.strip() for o in ALLOWED_ORIGINS]:
        response.headers.add('Access-Control-Allow-Origin', origin)
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,HEAD,PUT,POST,PATCH,DELETE,OPTIONS')
    return response

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'HorrorLink API'}), 200

@app.route('/api', defaults={'path': ''}, methods=['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
@app.route('/api/<path:path>', methods=['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
def unknown_api_route(path):
    return jsonify({
        'success': False,
        'error': {'code': 'NOT_FOUND', 'message': 'API endpoint not found'}
    }), 404

@app.route('/api/rooms', methods=['POST'])
def create_room():
    try:
        for _ in range(100):
            pin = Security.generate_pin()
            pin_hash = Security.hash_pin(pin)
            conn = db.get_connection()
            try:
                row = conn.execute("SELECT id FROM rooms WHERE pin_hash = ? AND status = 'active'", (pin_hash,)).fetchone()
                if not row:
                    break
            finally:
                conn.close()
        else:
            return jsonify({'success': False, 'error': {'code': 'NO_PIN', 'message': 'Could not generate unique PIN'}}), 500
        
        room_id = str(uuid.uuid4())
        host_token = Security.generate_token()
        host_token_hash = Security.hash_token(host_token)
        now = datetime.utcnow().isoformat() + 'Z'
        expires_at = (datetime.utcnow() + timedelta(minutes=ROOM_EXPIRATION_MINUTES)).isoformat() + 'Z'
        
        conn = db.get_connection()
        try:
            conn.execute('BEGIN')
            conn.execute(
                "INSERT INTO rooms (id, pin_hash, status, host_token_hash, created_at, expires_at) VALUES (?, ?, 'active', ?, ?, ?)",
                (room_id, pin_hash, host_token_hash, now, expires_at)
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise
        finally:
            conn.close()
        
        return jsonify({
            'success': True,
            'room': {
                'id': room_id,
                'pin': pin,
                'status': 'active',
                'expires_at': expires_at
            },
            'host_token': host_token
        }), 201
    except Exception as e:
        return jsonify({'success': False, 'error': {'code': 'ERROR', 'message': 'Failed to create room'}}), 500

@app.route('/api/rooms/join', methods=['POST'])
def join_room():
    try:
        data = request.get_json() or {}
        pin = str(data.get('pin', '')).strip()
        device_name = data.get('device_name', 'Speaker')
        
        if not pin or len(pin) != 4 or not pin.isdigit():
            return jsonify({'success': False, 'error': {'code': 'INVALID_PIN', 'message': 'PIN must be 4 digits'}}), 400
        
        ip = request.remote_addr or 'unknown'
        conn = db.get_connection()
        try:
            window_start = (datetime.utcnow() - timedelta(minutes=PIN_RATE_LIMIT_WINDOW_MINUTES)).isoformat() + 'Z'
            attempts = conn.execute("SELECT COUNT(*) as c FROM pin_attempts WHERE ip_address = ? AND attempted_at > ?", (ip, window_start)).fetchone()
            if attempts and attempts['c'] >= MAX_PIN_ATTEMPTS:
                conn.execute("INSERT INTO pin_attempts (ip_address, pin, attempted_at) VALUES (?, ?, ?)", (ip, pin, datetime.utcnow().isoformat() + 'Z'))
                conn.commit()
                return jsonify({'success': False, 'error': {'code': 'RATE_LIMIT', 'message': 'Too many attempts'}}), 429
        finally:
            conn.close()
        
        pin_hash = Security.hash_pin(pin)
        conn = db.get_connection()
        try:
            room = conn.execute("SELECT * FROM rooms WHERE pin_hash = ? AND status = 'active'", (pin_hash,)).fetchone()
            if not room:
                conn.execute("INSERT INTO pin_attempts (ip_address, pin, attempted_at) VALUES (?, ?, ?)", (ip, pin, datetime.utcnow().isoformat() + 'Z'))
                conn.commit()
                return jsonify({'success': False, 'error': {'code': 'INVALID_PIN', 'message': 'Invalid PIN'}}), 404
            expires_at_str = room['expires_at'].replace('Z', '')
            if datetime.utcnow() > datetime.fromisoformat(expires_at_str):
                conn.execute("UPDATE rooms SET status = 'closed' WHERE id = ?", (room['id'],))
                conn.commit()
                return jsonify({'success': False, 'error': {'code': 'EXPIRED', 'message': 'Room expired'}}), 404
        finally:
            conn.close()
        
        device_id = str(uuid.uuid4())
        device_token = Security.generate_token()
        device_token_hash = Security.hash_token(device_token)
        now = datetime.utcnow().isoformat() + 'Z'
        
        conn = db.get_connection()
        try:
            conn.execute('BEGIN')
            conn.execute(
                "INSERT INTO devices (id, room_id, name, role, token_hash, status, ready, last_seen_at, created_at) VALUES (?, ?, ?, 'speaker', ?, 'active', 0, ?, ?)",
                (device_id, room['id'], device_name, device_token_hash, now, now)
            )
            conn.execute("INSERT INTO pin_attempts (ip_address, pin, attempted_at) VALUES (?, ?, ?)", (ip, pin, now))
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise
        finally:
            conn.close()
        
        return jsonify({
            'success': True,
            'room': {'id': room['id'], 'status': 'active'},
            'device': {'id': device_id, 'name': device_name, 'status': 'active'},
            'device_token': device_token
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': {'code': 'ERROR', 'message': 'Failed to join room'}}), 500

def get_host_from_token(token):
    if not token:
        return None
    token_hash = Security.hash_token(token)
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM rooms WHERE host_token_hash = ? AND status = 'active'", (token_hash,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_device_from_token(token):
    if not token:
        return None
    token_hash = Security.hash_token(token)
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM devices WHERE token_hash = ? AND status = 'active'", (token_hash,)).fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


@app.route('/api/audio', methods=['GET', 'POST'])
def audio_library():
    host = get_host_from_token(bearer_token())
    if not host:
        return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401

    if request.method == 'GET':
        conn = db.get_connection()
        try:
            rows = conn.execute(
                '''SELECT a.*, EXISTS(
                       SELECT 1 FROM room_audio ra
                       WHERE ra.room_id = ? AND ra.audio_id = a.id
                   ) AS available_in_room
                   FROM audio_files a WHERE a.owner_room_id = ? ORDER BY a.created_at DESC''',
                (host['id'], host['id']),
            ).fetchall()
            return jsonify({
                'success': True,
                'audio': [
                    {**audio_metadata(row), 'available_in_room': bool(row['available_in_room'])}
                    for row in rows
                ],
            }), 200
        finally:
            conn.close()

    uploaded_file = request.files.get('file')
    name = request.form.get('name', '').strip()
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({'success': False, 'error': {'code': 'INVALID_FILE', 'message': 'Choose an audio file'}}), 400
    name = re.sub(r'[\x00-\x1f\x7f]', '', name).strip()
    if not name or len(name) > 80:
        return jsonify({'success': False, 'error': {'code': 'INVALID_NAME', 'message': 'Name must be between 1 and 80 characters'}}), 400

    extension = Path(uploaded_file.filename).suffix.lower()
    allowed_mimes = AUDIO_FORMATS.get(extension)
    if not allowed_mimes or extension.lstrip('.') not in ALLOWED_AUDIO_FORMATS:
        return jsonify({'success': False, 'error': {'code': 'UNSUPPORTED_FORMAT', 'message': 'Supported formats are MP3, WAV, OGG, and M4A'}}), 415
    submitted_mime = (uploaded_file.mimetype or '').lower()
    if submitted_mime not in allowed_mimes and submitted_mime != 'application/octet-stream':
        return jsonify({'success': False, 'error': {'code': 'UNSUPPORTED_FORMAT', 'message': 'File type does not match its extension'}}), 415

    temp_path = None
    final_path = None
    try:
        AUDIO_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(prefix='.upload-', dir=str(AUDIO_STORAGE_DIR))
        temp_path = Path(temp_name)
        digest = hashlib.sha256()
        file_size = 0
        header = b''
        with os.fdopen(handle, 'wb') as destination:
            while True:
                chunk = uploaded_file.stream.read(64 * 1024)
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > MAX_AUDIO_UPLOAD_BYTES:
                    return jsonify({'success': False, 'error': {'code': 'FILE_TOO_LARGE', 'message': f'Audio must be no larger than {MAX_AUDIO_UPLOAD_BYTES // (1024 * 1024)} MB'}}), 413
                if len(header) < 16:
                    header += chunk[:16 - len(header)]
                digest.update(chunk)
                destination.write(chunk)
        if file_size == 0:
            return jsonify({'success': False, 'error': {'code': 'EMPTY_FILE', 'message': 'The audio file is empty'}}), 400
        if not valid_audio_signature(extension, header):
            return jsonify({'success': False, 'error': {'code': 'INVALID_AUDIO', 'message': 'File contents are not a supported audio format'}}), 415

        audio_id = uuid.uuid4().hex
        storage_filename = f'audio_{audio_id}{extension}'
        final_path = AUDIO_STORAGE_DIR / storage_filename
        os.replace(str(temp_path), str(final_path))
        temp_path = None
        now = datetime.utcnow().isoformat() + 'Z'
        conn = db.get_connection()
        try:
            conn.execute('BEGIN')
            conn.execute(
                '''INSERT INTO audio_files
                   (id, owner_room_id, name, storage_filename, mime_type, file_size,
                    checksum_sha256, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (audio_id, host['id'], name, storage_filename, allowed_mimes[0],
                 file_size, digest.hexdigest(), now, now),
            )
            conn.execute(
                'INSERT INTO room_audio (room_id, audio_id, created_at) VALUES (?, ?, ?)',
                (host['id'], audio_id, now),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        return jsonify({
            'success': True,
            'audio': {**audio_metadata({
                'id': audio_id, 'name': name, 'mime_type': allowed_mimes[0],
                'file_size': file_size, 'duration_seconds': None,
                'checksum_sha256': digest.hexdigest(), 'created_at': now, 'updated_at': now,
            }), 'available_in_room': True},
        }), 201
    except Exception:
        app.logger.exception('Audio upload failed')
        if final_path and final_path.exists():
            try:
                final_path.unlink()
            except OSError:
                app.logger.exception('Could not remove incomplete audio upload')
        return jsonify({'success': False, 'error': {'code': 'UPLOAD_FAILED', 'message': 'Audio upload failed'}}), 500
    finally:
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                app.logger.exception('Could not remove temporary audio upload')


@app.route('/api/audio/<audio_id>', methods=['PATCH', 'DELETE'])
def update_audio(audio_id):
    host = get_host_from_token(bearer_token())
    if not host:
        return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
    conn = db.get_connection()
    try:
        audio = conn.execute(
            'SELECT * FROM audio_files WHERE id = ? AND owner_room_id = ?',
            (audio_id, host['id']),
        ).fetchone()
        if not audio:
            return jsonify({'success': False, 'error': {'code': 'NOT_FOUND', 'message': 'Audio not found'}}), 404

        if request.method == 'PATCH':
            data = request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Expected a JSON object'}}), 400
            raw_name = data.get('name')
            if not isinstance(raw_name, str):
                return jsonify({'success': False, 'error': {'code': 'INVALID_NAME', 'message': 'Name must be between 1 and 80 characters'}}), 400
            name = re.sub(r'[\x00-\x1f\x7f]', '', raw_name.strip()).strip()
            if not name or len(name) > 80:
                return jsonify({'success': False, 'error': {'code': 'INVALID_NAME', 'message': 'Name must be between 1 and 80 characters'}}), 400
            now = datetime.utcnow().isoformat() + 'Z'
            conn.execute('UPDATE audio_files SET name = ?, updated_at = ? WHERE id = ?', (name, now, audio_id))
            conn.commit()
            audio = conn.execute('SELECT * FROM audio_files WHERE id = ?', (audio_id,)).fetchone()
            return jsonify({'success': True, 'audio': audio_metadata(audio)}), 200

        if not valid_audio_storage_record(audio):
            app.logger.error('Audio record %s has an invalid storage filename', audio_id)
            return jsonify({'success': False, 'error': {'code': 'STORAGE_ERROR', 'message': 'Audio storage record is invalid'}}), 500
        source = AUDIO_STORAGE_DIR / audio['storage_filename']
        tombstone = AUDIO_STORAGE_DIR / f'.deleting-{audio_id}'
        moved_file = False
        try:
            if source.exists():
                os.replace(str(source), str(tombstone))
                moved_file = True
            conn.execute('BEGIN')
            now = datetime.utcnow().isoformat() + 'Z'
            conn.execute(
                '''UPDATE commands SET status = 'failed', completed_at = ?, result = 'Audio deleted'
                   WHERE room_id = ? AND sound_id = ? AND action = 'play'
                   AND status IN ('pending', 'processing')''',
                (now, host['id'], audio_id),
            )
            devices = conn.execute(
                "SELECT id FROM devices WHERE room_id = ? AND status = 'active' AND role = 'speaker'",
                (host['id'],),
            ).fetchall()
            expires_at = (datetime.utcnow() + timedelta(minutes=COMMAND_EXPIRATION_MINUTES)).isoformat() + 'Z'
            for device in devices:
                conn.execute(
                    '''INSERT INTO commands
                       (id, room_id, device_id, action, volume, status, created_at, expires_at)
                       VALUES (?, ?, ?, 'stop', 0.8, 'pending', ?, ?)''',
                    (str(uuid.uuid4()), host['id'], device['id'], now, expires_at),
                )
            conn.execute('DELETE FROM audio_files WHERE id = ?', (audio_id,))
            conn.commit()
        except Exception:
            conn.rollback()
            if moved_file and tombstone.exists():
                os.replace(str(tombstone), str(source))
            app.logger.exception('Audio deletion failed')
            return jsonify({'success': False, 'error': {'code': 'DELETE_FAILED', 'message': 'Audio could not be deleted'}}), 500
        finally:
            conn.close()
        if tombstone.exists():
            try:
                tombstone.unlink()
            except OSError:
                app.logger.exception('Unable to remove deleted audio file %s', audio_id)
        return jsonify({'success': True}), 200
    finally:
        if conn:
            conn.close()


@app.route('/api/audio/<audio_id>/content', methods=['GET', 'HEAD'])
def get_audio_content(audio_id):
    token = bearer_token()
    host = get_host_from_token(token)
    device = get_device_from_token(token) if not host else None
    if not host and not device:
        return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
    conn = db.get_connection()
    try:
        if host:
            audio = conn.execute(
                'SELECT * FROM audio_files WHERE id = ? AND owner_room_id = ?',
                (audio_id, host['id']),
            ).fetchone()
        else:
            audio = room_audio_access(conn, device['room_id'], audio_id)
        if not audio:
            return jsonify({'success': False, 'error': {'code': 'NOT_FOUND', 'message': 'Audio not available'}}), 404
        if not valid_audio_storage_record(audio):
            app.logger.error('Audio record %s has an invalid storage filename', audio_id)
            return jsonify({'success': False, 'error': {'code': 'STORAGE_ERROR', 'message': 'Audio storage record is invalid'}}), 500
        path = AUDIO_STORAGE_DIR / audio['storage_filename']
        if not path.is_file():
            return jsonify({'success': False, 'error': {'code': 'NOT_FOUND', 'message': 'Audio file is missing'}}), 404
        response = send_file(
            path, mimetype=audio['mime_type'], as_attachment=False,
            conditional=True, etag=audio['checksum_sha256'],
        )
        response.headers['Content-Disposition'] = 'inline'
        response.headers['Cache-Control'] = 'private, no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    finally:
        conn.close()


@app.route('/api/rooms/<room_id>/audio', methods=['GET', 'POST'])
def room_audio(room_id):
    token = bearer_token()
    host = get_host_from_token(token)
    device = get_device_from_token(token) if not host else None
    if host and host['id'] != room_id:
        return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
    if device and device['room_id'] != room_id:
        return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
    if not host and not device:
        return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
    if request.method == 'POST' and not host:
        return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Host authorization required'}}), 403

    conn = db.get_connection()
    try:
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Expected a JSON object'}}), 400
            audio_ids = data.get('audio_ids')
            if not isinstance(audio_ids, list) or any(not isinstance(item, str) for item in audio_ids):
                return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'audio_ids must be a list'}}), 400
            audio_ids = list(dict.fromkeys(audio_ids))
            owned = conn.execute(
                'SELECT id FROM audio_files WHERE owner_room_id = ?',
                (host['id'],),
            ).fetchall()
            owned_ids = {row['id'] for row in owned}
            if any(item not in owned_ids for item in audio_ids):
                return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Audio selection contains an unavailable sound'}}), 400
            now = datetime.utcnow().isoformat() + 'Z'
            try:
                conn.execute('BEGIN')
                conn.execute('DELETE FROM room_audio WHERE room_id = ?', (room_id,))
                conn.executemany(
                    'INSERT INTO room_audio (room_id, audio_id, created_at) VALUES (?, ?, ?)',
                    [(room_id, item, now) for item in audio_ids],
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        if device:
            rows = conn.execute(
                '''SELECT a.*, c.status AS cache_status FROM audio_files a
                   JOIN room_audio ra ON ra.audio_id = a.id
                   LEFT JOIN device_audio_cache c ON c.audio_id = a.id AND c.device_id = ?
                   WHERE ra.room_id = ? ORDER BY a.created_at''',
                (device['id'], room_id),
            ).fetchall()
        else:
            rows = conn.execute(
                '''SELECT a.*, NULL AS cache_status FROM audio_files a
                   JOIN room_audio ra ON ra.audio_id = a.id
                   WHERE ra.room_id = ? ORDER BY a.created_at''',
                (room_id,),
            ).fetchall()
        return jsonify({
            'success': True,
            'audio': [
                {**audio_metadata(row), 'cache_status': row['cache_status']}
                for row in rows
            ],
        }), 200
    finally:
        conn.close()


@app.route('/api/devices/audio-cache', methods=['POST'])
def update_device_audio_cache():
    device = get_device_from_token(bearer_token())
    if not device:
        return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Expected a JSON object'}}), 400
    room_id = data.get('room_id')
    audio_id = data.get('audio_id')
    status = data.get('status')
    checksum = data.get('checksum_sha256')
    if (
        not isinstance(room_id, str)
        or not isinstance(audio_id, str)
        or room_id != device['room_id']
        or status not in ('downloading', 'ready', 'failed', 'missing')
    ):
        return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Invalid cache report'}}), 400
    conn = db.get_connection()
    try:
        audio = room_audio_access(conn, room_id, audio_id)
        if not audio:
            return jsonify({'success': False, 'error': {'code': 'NOT_FOUND', 'message': 'Audio is no longer available'}}), 404
        if status == 'ready' and checksum != audio['checksum_sha256']:
            return jsonify({'success': False, 'error': {'code': 'CHECKSUM_MISMATCH', 'message': 'Audio checksum does not match'}}), 400
        verified_checksum = audio['checksum_sha256'] if status == 'ready' else None
        now = datetime.utcnow().isoformat() + 'Z'
        conn.execute(
            '''INSERT INTO device_audio_cache
               (device_id, room_id, audio_id, status, checksum_sha256, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(device_id, audio_id) DO UPDATE SET
               room_id = excluded.room_id, status = excluded.status,
               checksum_sha256 = excluded.checksum_sha256, updated_at = excluded.updated_at
               WHERE device_audio_cache.status != excluded.status
                  OR device_audio_cache.checksum_sha256 IS NOT excluded.checksum_sha256''',
            (device['id'], room_id, audio_id, status, verified_checksum, now),
        )
        conn.commit()
        return jsonify({'success': True, 'status': status}), 200
    finally:
        conn.close()


@app.route('/api/rooms/<room_id>/devices', methods=['GET'])
def list_devices(room_id):
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None
        host = get_host_from_token(token)
        if not host or host['id'] != room_id:
            return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
        
        conn = db.get_connection()
        try:
            devices = conn.execute("SELECT * FROM devices WHERE room_id = ? AND role = 'speaker'", (room_id,)).fetchall()
            result = []
            now = datetime.utcnow()
            timeout = timedelta(minutes=DEVICE_ONLINE_TIMEOUT_MINUTES)
            for d in devices:
                last_seen = d['last_seen_at']
                online = False
                if last_seen:
                    try:
                        ls = datetime.fromisoformat(last_seen.replace('Z', ''))
                        online = (now - ls) <= timeout
                    except:
                        pass
                result.append({
                    'id': d['id'],
                    'name': d['name'],
                    'ready': bool(d['ready']),
                    'online': online,
                    'last_seen_at': last_seen,
                    'audio_cache': [
                        dict(row) for row in conn.execute(
                            '''SELECT audio_id, status, updated_at FROM device_audio_cache
                               WHERE device_id = ? ORDER BY audio_id''',
                            (d['id'],),
                        ).fetchall()
                    ],
                })
            return jsonify({'success': True, 'devices': result}), 200
        finally:
            conn.close()
    except Exception as e:
        return jsonify({'success': False, 'error': {'code': 'ERROR', 'message': 'Failed to list devices'}}), 500

@app.route('/api/commands', methods=['POST'])
def create_command():
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None
        host = get_host_from_token(token)
        if not host:
            return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
        
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Expected a JSON object'}}), 400
        targets = data.get('targets') or ([data.get('device_id')] if data.get('device_id') else [])
        action = data.get('action')
        sound_id = data.get('sound_id')
        volume = data.get('volume', 0.8)
        
        if action not in ['play', 'stop']:
            return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Invalid action'}}), 400
        if not isinstance(targets, list) or not targets or any(not isinstance(target, str) or not target for target in targets):
            return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Select at least one valid speaker'}}), 400
        targets = list(dict.fromkeys(targets))
        if action == 'play' and (not isinstance(sound_id, str) or not sound_id):
            return jsonify({'success': False, 'error': {'code': 'INVALID_SOUND', 'message': 'Choose a sound'}}), 400
        try:
            volume = float(volume)
            if not math.isfinite(volume) or volume < 0 or volume > 1:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Invalid volume'}}), 400
        
        now = datetime.utcnow().isoformat() + 'Z'
        expires_at = (datetime.utcnow() + timedelta(minutes=COMMAND_EXPIRATION_MINUTES)).isoformat() + 'Z'
        
        conn = db.get_connection()
        try:
            conn.execute('BEGIN')
            created = []
            for target in targets:
                device = conn.execute("SELECT * FROM devices WHERE id = ? AND room_id = ? AND status = 'active'", (target, host['id'])).fetchone()
                if not device:
                    conn.rollback()
                    return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Invalid target'}}), 400
                if action == 'play' and sound_id not in VALID_SOUNDS:
                    audio = room_audio_access(conn, host['id'], sound_id)
                    if not audio:
                        conn.rollback()
                        return jsonify({'success': False, 'error': {'code': 'INVALID_SOUND', 'message': 'Audio is not available in this room'}}), 400
                cmd_id = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO commands (id, room_id, device_id, action, sound_id, volume, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                    (cmd_id, host['id'], target, action, sound_id if action == 'play' else None, volume, now, expires_at)
                )
                created.append(cmd_id)
            conn.commit()
            return jsonify({'success': True, 'command_ids': created}), 201
        except Exception as e:
            conn.rollback()
            raise
        finally:
            conn.close()
    except Exception as e:
        return jsonify({'success': False, 'error': {'code': 'ERROR', 'message': 'Failed to create command'}}), 500

@app.route('/api/devices/commands', methods=['GET'])
def get_device_commands():
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None
        device = get_device_from_token(token)
        if not device:
            return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
        
        now = datetime.utcnow().isoformat() + 'Z'
        conn = db.get_connection()
        try:
            conn.execute('BEGIN')
            conn.execute("UPDATE devices SET last_seen_at = ? WHERE id = ?", (now, device['id']))
            commands = conn.execute("SELECT * FROM commands WHERE device_id = ? AND status = 'pending' AND expires_at > ?", (device['id'], now)).fetchall()
            result = []
            for cmd in commands:
                audio_id = None
                if cmd['action'] == 'play' and cmd['sound_id'] not in VALID_SOUNDS:
                    audio = room_audio_access(conn, device['room_id'], cmd['sound_id'])
                    cache = conn.execute(
                        '''SELECT status, checksum_sha256 FROM device_audio_cache
                           WHERE device_id = ? AND audio_id = ?''',
                        (device['id'], cmd['sound_id']),
                    ).fetchone()
                    if not audio or not cache or cache['status'] != 'ready' or cache['checksum_sha256'] != audio['checksum_sha256']:
                        conn.execute(
                            "UPDATE commands SET status = 'failed', completed_at = ?, result = 'Audio not ready on speaker' WHERE id = ?",
                            (now, cmd['id']),
                        )
                        continue
                    audio_id = cmd['sound_id']
                conn.execute("UPDATE commands SET status = 'processing' WHERE id = ?", (cmd['id'],))
                expires_at_str = cmd['expires_at'].replace('Z', '')
                if datetime.utcnow() > datetime.fromisoformat(expires_at_str):
                    conn.execute("UPDATE commands SET status = 'expired' WHERE id = ?", (cmd['id'],))
                    continue
                result.append({
                    'id': cmd['id'],
                    'action': cmd['action'],
                    'sound_id': cmd['sound_id'],
                    'audio_id': audio_id,
                    'volume': cmd['volume'],
                    'expires_at': cmd['expires_at']
                })
            conn.commit()
            return jsonify({'success': True, 'commands': result}), 200
        except Exception as e:
            conn.rollback()
            raise
        finally:
            conn.close()
    except Exception as e:
        return jsonify({'success': False, 'error': {'code': 'ERROR', 'message': 'Failed to get commands'}}), 500

@app.route('/api/commands/<command_id>/ack', methods=['POST'])
def acknowledge_command(command_id):
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None
        device = get_device_from_token(token)
        if not device:
            return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
        
        data = request.get_json() or {}
        status = data.get('status', 'succeeded')
        result_msg = str(data.get('result', ''))[:200]
        
        if status not in ['succeeded', 'failed', 'processing']:
            return jsonify({'success': False, 'error': {'code': 'INVALID', 'message': 'Invalid status'}}), 400
        
        conn = db.get_connection()
        try:
            conn.execute('BEGIN')
            cmd = conn.execute("SELECT * FROM commands WHERE id = ?", (command_id,)).fetchone()
            if not cmd or cmd['device_id'] != device['id']:
                conn.rollback()
                return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
            if cmd['status'] in ['succeeded', 'failed']:
                conn.commit()
                return jsonify({'success': True, 'command': {'id': command_id, 'status': cmd['status']}}), 200
            now = datetime.utcnow().isoformat() + 'Z'
            conn.execute("UPDATE commands SET status = ?, acknowledged_at = ?, completed_at = ?, result = ? WHERE id = ?",
                        (status, now, now if status in ['succeeded', 'failed'] else None, result_msg, command_id))
            conn.commit()
            return jsonify({'success': True, 'command': {'id': command_id, 'status': status}}), 200
        except Exception as e:
            conn.rollback()
            raise
        finally:
            conn.close()
    except Exception as e:
        return jsonify({'success': False, 'error': {'code': 'ERROR', 'message': 'Failed to acknowledge'}}), 500

@app.route('/api/rooms/<room_id>/close', methods=['POST'])
def close_room(room_id):
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None
        host = get_host_from_token(token)
        if not host or host['id'] != room_id:
            return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
        
        now = datetime.utcnow().isoformat() + 'Z'
        conn = db.get_connection()
        try:
            conn.execute('BEGIN')
            conn.execute("UPDATE rooms SET status = 'closed', closed_at = ? WHERE id = ?", (now, room_id))
            conn.execute("UPDATE devices SET status = 'revoked' WHERE room_id = ?", (room_id,))
            conn.commit()
            return jsonify({'success': True, 'message': 'Room closed'}), 200
        except Exception as e:
            conn.rollback()
            raise
        finally:
            conn.close()
    except Exception as e:
        return jsonify({'success': False, 'error': {'code': 'ERROR', 'message': 'Failed to close room'}}), 500

@app.route('/api/devices/heartbeat', methods=['POST'])
def heartbeat():
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None
        device = get_device_from_token(token)
        if not device:
            return jsonify({'success': False, 'error': {'code': 'UNAUTHORIZED', 'message': 'Unauthorized'}}), 401
        now = datetime.utcnow().isoformat() + 'Z'
        conn = db.get_connection()
        try:
            conn.execute("UPDATE devices SET last_seen_at = ? WHERE id = ?", (now, device['id']))
            conn.commit()
            return jsonify({'success': True}), 200
        finally:
            conn.close()
    except Exception as e:
        return jsonify({'success': False, 'error': {'code': 'ERROR', 'message': 'Failed'}}), 500

@app.route('/', defaults={'path': ''}, methods=['GET', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'HEAD'])
def serve_frontend(path):
    index_file = FRONTEND_DIST / 'index.html'
    if not index_file.is_file():
        return (
            'Frontend has not been built yet. Run "npm run build" from the frontend directory.',
            503,
            {'Content-Type': 'text/plain; charset=utf-8'},
        )

    if not path:
        return send_file(index_file)

    requested_path = Path(path)
    if any(part.startswith('.') for part in requested_path.parts):
        abort(404)

    blocked_names = {'backend', 'frontend', 'instance', 'tests', '__pycache__', 'logs', 'secrets', 'venv'}
    blocked_extensions = {
        '.db', '.sqlite', '.sqlite3', '.log', '.py', '.pyc', '.pyo',
        '.db-wal', '.db-shm', '.sqlite-wal', '.sqlite-shm',
        '.env', '.pem', '.key', '.crt',
    }
    if any(part.lower() in blocked_names for part in requested_path.parts):
        abort(404)
    if any(suffix.lower() in blocked_extensions for suffix in requested_path.suffixes):
        abort(404)

    dist_root = FRONTEND_DIST.resolve()
    candidate = (dist_root / requested_path).resolve()
    try:
        inside_dist = os.path.commonpath((str(dist_root), str(candidate))) == str(dist_root)
    except ValueError:
        inside_dist = False
    if not inside_dist:
        abort(404)
    if candidate.is_file():
        return send_file(candidate)

    if requested_path.suffix or requested_path.parts[0] == 'assets':
        abort(404)
    return send_file(index_file)

@app.errorhandler(404)
def handle_not_found(error):
    if request.path == '/api' or request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'error': {'code': 'NOT_FOUND', 'message': 'API endpoint not found'}
        }), 404
    return error


@app.errorhandler(413)
def handle_payload_too_large(error):
    if request.path == '/api' or request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'error': {'code': 'FILE_TOO_LARGE', 'message': 'Audio upload exceeds the configured request limit'},
        }), 413
    return error

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
