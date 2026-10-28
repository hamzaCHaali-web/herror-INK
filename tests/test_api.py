import unittest
import os
import tempfile
import json
import io
import hashlib
from pathlib import Path
from unittest.mock import patch
import app as app_module
from app import FRONTEND_DIST, app, db

class HorrorLinkTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, db_path = tempfile.mkstemp(suffix='.db')
        app.config['TESTING'] = True
        db.db_path = os.path.abspath(db_path)
        db.init_db()
        self.client = app.test_client()
        self.previous_audio_dir = app_module.AUDIO_STORAGE_DIR
        self.audio_temp_dir = tempfile.TemporaryDirectory()
        app_module.AUDIO_STORAGE_DIR = Path(self.audio_temp_dir.name)
    
    def tearDown(self):
        os.close(self.db_fd)
        try:
            os.unlink(db.db_path)
        except:
            pass
        for ext in ['-wal', '-shm']:
            try:
                os.unlink(db.db_path + ext)
            except:
                pass
        app_module.AUDIO_STORAGE_DIR = self.previous_audio_dir
        self.audio_temp_dir.cleanup()

    def create_host_and_speaker(self):
        created = self.client.post('/api/rooms', json={}).get_json()
        host_token = created['host_token']
        joined = self.client.post('/api/rooms/join', json={
            'pin': created['room']['pin'],
            'device_name': 'Test speaker',
        }).get_json()
        return created['room']['id'], host_token, joined['device_token']

    def upload_wav(self, token, name='Test sound', payload=b'RIFF\x04\x00\x00\x00WAVEdata'):
        return self.client.post(
            '/api/audio',
            data={'name': name, 'file': (io.BytesIO(payload), 'test.wav', 'audio/wav')},
            headers={'Authorization': f'Bearer {token}'},
            content_type='multipart/form-data',
        )
    
    def test_health(self):
        rv = self.client.get('/api/health')
        self.assertEqual(rv.status_code, 200)
        data = json.loads(rv.data)
        self.assertEqual(data['status'], 'ok')

    def test_unknown_api_route_returns_json_404(self):
        rv = self.client.get('/api/not-a-real-endpoint')
        self.assertEqual(rv.status_code, 404)
        self.assertTrue(rv.is_json)
        self.assertFalse(rv.get_json()['success'])

    def test_frontend_and_assets_are_served(self):
        rv = self.client.get('/')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'<div id="root"></div>', rv.data)
        rv.close()

        asset = next((FRONTEND_DIST / 'assets').glob('*.js'))
        asset_response = self.client.get(f'/assets/{asset.name}')
        self.assertEqual(asset_response.status_code, 200)
        self.assertIn('javascript', asset_response.mimetype)
        asset_response.close()

    def test_frontend_route_falls_back_to_index(self):
        rv = self.client.get('/speaker')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'<div id="root"></div>', rv.data)
        rv.close()

    def test_private_files_are_not_served(self):
        for path in (
            '/app.py',
            '/app.py.backup',
            '/instance/horrorlink.db',
            '/database.db-wal',
            '/logs/server.log',
            '/.env',
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_missing_frontend_build_returns_clear_error(self):
        with patch('app.FRONTEND_DIST', Path(tempfile.gettempdir()) / 'horrorlink-no-build'):
            rv = self.client.get('/')
        self.assertEqual(rv.status_code, 503)
        self.assertIn(b'Frontend has not been built yet', rv.data)

    def test_frontend_serving_does_not_depend_on_working_directory(self):
        original_directory = os.getcwd()
        try:
            os.chdir(tempfile.gettempdir())
            rv = self.client.get('/')
            self.assertEqual(rv.status_code, 200)
            rv.close()
        finally:
            os.chdir(original_directory)
    
    def test_create_room(self):
        rv = self.client.post('/api/rooms', json={})
        self.assertEqual(rv.status_code, 201)
        data = json.loads(rv.data)
        self.assertTrue(data['success'])
        self.assertIn('room', data)
        self.assertIn('pin', data['room'])
        self.assertEqual(len(data['room']['pin']), 4)
        self.assertIn('host_token', data)
    
    def test_join_room(self):
        rv = self.client.post('/api/rooms', json={})
        data = json.loads(rv.data)
        pin = data['room']['pin']
        rv = self.client.post('/api/rooms/join', json={'pin': pin, 'device_name': 'Speaker 01'})
        self.assertEqual(rv.status_code, 200)
        data = json.loads(rv.data)
        self.assertTrue(data['success'])
        self.assertIn('device_token', data)
    
    def test_invalid_pin(self):
        rv = self.client.post('/api/rooms/join', json={'pin': '0000'})
        self.assertEqual(rv.status_code, 404)
        data = json.loads(rv.data)
        self.assertFalse(data['success'])
    
    def test_pin_format(self):
        rv = self.client.post('/api/rooms/join', json={'pin': '123'})
        self.assertEqual(rv.status_code, 400)
        rv = self.client.post('/api/rooms/join', json={'pin': 'abcd'})
        self.assertEqual(rv.status_code, 400)
    
    def test_create_command(self):
        rv = self.client.post('/api/rooms', json={})
        room_data = json.loads(rv.data)
        host_token = room_data['host_token']
        rv = self.client.post('/api/rooms/join', json={'pin': room_data['room']['pin'], 'device_name': 'Speaker 01'})
        speaker_data = json.loads(rv.data)
        speaker_id = speaker_data['device']['id']
        
        rv = self.client.post('/api/commands', 
            json={'targets': [speaker_id], 'action': 'play', 'sound_id': 'creepy_whisper', 'volume': 0.8},
            headers={'Authorization': f'Bearer {host_token}'}
        )
        self.assertEqual(rv.status_code, 201)
        data = json.loads(rv.data)
        self.assertTrue(data['success'])
    
    def test_invalid_sound(self):
        rv = self.client.post('/api/rooms', json={})
        room_data = json.loads(rv.data)
        host_token = room_data['host_token']
        rv = self.client.post('/api/rooms/join', json={'pin': room_data['room']['pin'], 'device_name': 'Speaker 01'})
        speaker_data = json.loads(rv.data)
        speaker_id = speaker_data['device']['id']
        
        rv = self.client.post('/api/commands', 
            json={'targets': [speaker_id], 'action': 'play', 'sound_id': 'invalid'},
            headers={'Authorization': f'Bearer {host_token}'}
        )
        self.assertEqual(rv.status_code, 400)
    
    def test_volume_validation(self):
        rv = self.client.post('/api/rooms', json={})
        room_data = json.loads(rv.data)
        host_token = room_data['host_token']
        rv = self.client.post('/api/rooms/join', json={'pin': room_data['room']['pin'], 'device_name': 'Speaker 01'})
        speaker_data = json.loads(rv.data)
        speaker_id = speaker_data['device']['id']
        
        rv = self.client.post('/api/commands', 
            json={'targets': [speaker_id], 'action': 'play', 'sound_id': 'creepy_whisper', 'volume': 1.5},
            headers={'Authorization': f'Bearer {host_token}'}
        )
        self.assertEqual(rv.status_code, 400)
        invalid_volume = self.client.post(
            '/api/commands',
            json={'targets': [speaker_id], 'action': 'play', 'sound_id': 'creepy_whisper', 'volume': 'nan'},
            headers={'Authorization': f'Bearer {host_token}'},
        )
        self.assertEqual(invalid_volume.status_code, 400)

    def test_audio_upload_list_rename_and_delete(self):
        room_id, token, _ = self.create_host_and_speaker()
        uploaded = self.upload_wav(token)
        self.assertEqual(uploaded.status_code, 201)
        audio = uploaded.get_json()['audio']
        self.assertEqual(audio['file_size'], len(b'RIFF\x04\x00\x00\x00WAVEdata'))
        self.assertEqual(
            audio['checksum_sha256'],
            hashlib.sha256(b'RIFF\x04\x00\x00\x00WAVEdata').hexdigest(),
        )
        self.assertTrue((app_module.AUDIO_STORAGE_DIR / f"audio_{audio['id']}.wav").is_file())

        listed = self.client.get('/api/audio', headers={'Authorization': f'Bearer {token}'})
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.get_json()['audio'][0]['id'], audio['id'])
        self.assertTrue(listed.get_json()['audio'][0]['available_in_room'])

        renamed = self.client.patch(
            f"/api/audio/{audio['id']}",
            json={'name': 'Renamed'},
            headers={'Authorization': f'Bearer {token}'},
        )
        self.assertEqual(renamed.status_code, 200)
        self.assertEqual(renamed.get_json()['audio']['name'], 'Renamed')
        deleted = self.client.delete(
            f"/api/audio/{audio['id']}",
            headers={'Authorization': f'Bearer {token}'},
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertFalse((app_module.AUDIO_STORAGE_DIR / f"audio_{audio['id']}.wav").exists())

    def test_audio_rejects_invalid_unauthorized_and_oversized_uploads(self):
        _, token, _ = self.create_host_and_speaker()
        unauthorized = self.upload_wav('')
        self.assertEqual(unauthorized.status_code, 401)
        empty = self.upload_wav(token, payload=b'')
        self.assertEqual(empty.status_code, 400)
        unsupported = self.client.post(
            '/api/audio',
            data={'name': 'bad', 'file': (io.BytesIO(b'not audio'), 'bad.exe', 'application/octet-stream')},
            headers={'Authorization': f'Bearer {token}'},
            content_type='multipart/form-data',
        )
        self.assertEqual(unsupported.status_code, 415)
        with patch('app.MAX_AUDIO_UPLOAD_BYTES', 8):
            oversized = self.upload_wav(token, payload=b'RIFF\x04\x00\x00\x00WAVE!')
        self.assertEqual(oversized.status_code, 413)
        missing_name = self.upload_wav(token, name='  ')
        self.assertEqual(missing_name.status_code, 400)

    def test_audio_download_reports_missing_server_file(self):
        _, token, device_token = self.create_host_and_speaker()
        audio = self.upload_wav(token).get_json()['audio']
        (app_module.AUDIO_STORAGE_DIR / f"audio_{audio['id']}.wav").unlink()
        missing = self.client.get(
            f"/api/audio/{audio['id']}/content",
            headers={'Authorization': f'Bearer {device_token}'},
        )
        self.assertEqual(missing.status_code, 404)

    def test_audio_isolation_room_access_and_cache_ready_command(self):
        room_id, host_token, device_token = self.create_host_and_speaker()
        uploaded = self.upload_wav(host_token)
        self.assertEqual(uploaded.status_code, 201)
        audio_id = uploaded.get_json()['audio']['id']
        second_room_id, second_host_token, second_device_token = self.create_host_and_speaker()

        isolated = self.client.get('/api/audio', headers={'Authorization': f'Bearer {second_host_token}'})
        self.assertEqual(isolated.get_json()['audio'], [])
        unauthorized_download = self.client.get(
            f'/api/audio/{audio_id}/content',
            headers={'Authorization': f'Bearer {second_device_token}'},
        )
        self.assertEqual(unauthorized_download.status_code, 404)

        available = self.client.get(
            f'/api/rooms/{room_id}/audio',
            headers={'Authorization': f'Bearer {device_token}'},
        )
        self.assertEqual(available.status_code, 200)
        self.assertEqual(available.get_json()['audio'][0]['id'], audio_id)
        content = self.client.get(
            f'/api/audio/{audio_id}/content',
            headers={'Authorization': f'Bearer {device_token}'},
        )
        self.assertEqual(content.status_code, 200)
        self.assertEqual(content.data[:4], b'RIFF')
        content.close()

        devices = self.client.get(
            f'/api/rooms/{room_id}/devices',
            headers={'Authorization': f'Bearer {host_token}'},
        ).get_json()['devices']
        device_id = devices[0]['id']
        command = self.client.post(
            '/api/commands',
            json={'targets': [device_id], 'action': 'play', 'sound_id': audio_id},
            headers={'Authorization': f'Bearer {host_token}'},
        )
        self.assertEqual(command.status_code, 201)
        not_ready = self.client.get('/api/devices/commands', headers={'Authorization': f'Bearer {device_token}'})
        self.assertEqual(not_ready.get_json()['commands'], [])

        ready = self.client.post(
            '/api/devices/audio-cache',
            json={
                'room_id': room_id,
                'audio_id': audio_id,
                'status': 'ready',
                'checksum_sha256': uploaded.get_json()['audio']['checksum_sha256'],
            },
            headers={'Authorization': f'Bearer {device_token}'},
        )
        self.assertEqual(ready.status_code, 200)
        invalid_ready = self.client.post(
            '/api/devices/audio-cache',
            json={
                'room_id': room_id,
                'audio_id': audio_id,
                'status': 'ready',
                'checksum_sha256': '0' * 64,
            },
            headers={'Authorization': f'Bearer {device_token}'},
        )
        self.assertEqual(invalid_ready.status_code, 400)
        command = self.client.post(
            '/api/commands',
            json={'targets': [device_id], 'action': 'play', 'sound_id': audio_id, 'volume': 0.6},
            headers={'Authorization': f'Bearer {host_token}'},
        )
        self.assertEqual(command.status_code, 201)
        commands = self.client.get('/api/devices/commands', headers={'Authorization': f'Bearer {device_token}'})
        self.assertEqual(commands.get_json()['commands'][0]['audio_id'], audio_id)
        self.client.delete(
            f'/api/audio/{audio_id}',
            headers={'Authorization': f'Bearer {host_token}'},
        )
        deleted_command = self.client.post(
            '/api/commands',
            json={'targets': [device_id], 'action': 'play', 'sound_id': audio_id},
            headers={'Authorization': f'Bearer {host_token}'},
        )
        self.assertEqual(deleted_command.status_code, 400)
        self.assertNotEqual(second_room_id, room_id)

if __name__ == '__main__':
    unittest.main()
