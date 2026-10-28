import sqlite3
import os
from datetime import datetime, timedelta

class Database:
    def __init__(self, db_path='instance/horrorlink.db'):
        self.db_path = os.path.abspath(db_path)
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
        self.init_db()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('PRAGMA busy_timeout = 30000')
        return conn
    
    def init_db(self):
        conn = self.get_connection()
        try:
            conn.execute('PRAGMA journal_mode = WAL')
            schema_version = conn.execute('PRAGMA user_version').fetchone()[0]
            if schema_version > 1:
                raise RuntimeError(f'Unsupported database schema version: {schema_version}')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rooms (
                    id TEXT PRIMARY KEY,
                    pin_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    host_token_hash TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    closed_at TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    room_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT,
                    token_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    ready INTEGER DEFAULT 0,
                    last_seen_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (room_id) REFERENCES rooms(id)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id TEXT PRIMARY KEY,
                    room_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    sound_id TEXT,
                    volume REAL DEFAULT 0.8,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    acknowledged_at TEXT,
                    completed_at TEXT,
                    result TEXT,
                    FOREIGN KEY (room_id) REFERENCES rooms(id),
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS audio_files (
                    id TEXT PRIMARY KEY,
                    owner_room_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    storage_filename TEXT NOT NULL UNIQUE,
                    mime_type TEXT NOT NULL,
                    file_size INTEGER NOT NULL CHECK (file_size > 0),
                    duration_seconds REAL,
                    checksum_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (owner_room_id) REFERENCES rooms(id)
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS room_audio (
                    room_id TEXT NOT NULL,
                    audio_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (room_id, audio_id),
                    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
                    FOREIGN KEY (audio_id) REFERENCES audio_files(id) ON DELETE CASCADE
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS device_audio_cache (
                    device_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    audio_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('downloading', 'ready', 'failed', 'missing')),
                    checksum_sha256 TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (device_id, audio_id),
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
                    FOREIGN KEY (room_id, audio_id) REFERENCES room_audio(room_id, audio_id) ON DELETE CASCADE
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS pin_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    pin TEXT NOT NULL,
                    attempted_at TEXT NOT NULL
                )
            ''')
            
            conn.execute('CREATE INDEX IF NOT EXISTS idx_rooms_status ON rooms(status)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_rooms_pin_hash ON rooms(pin_hash)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_devices_room_id ON devices(room_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_commands_device_id ON commands(device_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_commands_room_id ON commands(room_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_commands_status ON commands(status)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_pin_attempts_ip ON pin_attempts(ip_address)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_audio_owner ON audio_files(owner_room_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_room_audio_audio ON room_audio(audio_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_device_audio_room ON device_audio_cache(room_id, audio_id)')
            conn.execute('PRAGMA user_version = 1')
            
            conn.commit()
        finally:
            conn.close()
    
    def execute(self, query, params=(), fetchone=False, fetchall=False, commit=False):
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(query, params)
            if commit:
                conn.commit()
                result = cur.lastrowid
            elif fetchone:
                result = cur.fetchone()
            elif fetchall:
                result = cur.fetchall()
            else:
                result = cur.rowcount
            return result
        except Exception as e:
            conn.rollback()
            raise
        finally:
            conn.close()
