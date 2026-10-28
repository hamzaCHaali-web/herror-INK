# Custom audio storage and access

The Flask app stores uploaded audio under `backend/instance/audio` by default.
Set `AUDIO_STORAGE_DIR` to an absolute path on a persistent, writable volume
for deployments where the application directory is ephemeral. This directory
is private and must not be mounted or copied into `backend/dist`. The SQLite
database is upgraded additively during startup and records schema version 1.

Uploads are limited by `MAX_AUDIO_UPLOAD_BYTES` (50 MiB by default). MP3, WAV,
OGG, and M4A are enabled by default through `ALLOWED_AUDIO_FORMATS` and accepted
after extension, MIME, and file-signature checks.
Supported formats still depend on the receiving browser's decoder.

The browser stores only lightweight audio metadata in localStorage. Speaker
audio bytes are kept in the versioned `horrorlink-audio` IndexedDB database and
verified with SHA-256 before being marked ready. Browser storage can be cleared
or evicted by the browser; it is not a permanent backup.

This application currently issues a Host token per room and has no durable
Host account identity. To preserve the existing authorization boundary, audio
ownership is therefore scoped to the Host's room token; custom library items
cannot be recovered by a newly created room or another browser. A durable
cross-room library requires an authenticated owner identity in the application.
The implementation does not treat the room PIN or a browser-generated public
identifier as proof of ownership.

Serve the application and API over HTTPS in production. Persist both the
configured audio directory and SQLite database across restarts, and grant the
Flask process write access to them.

Playback uses a single active sound per Speaker: a new play command replaces
the current sound, and a stop command halts it.
