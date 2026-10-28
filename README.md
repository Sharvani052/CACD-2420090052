# Adaptive Decoy Security System

This academic prototype protects sensitive files accessed through the application. It combines JWT authentication, AES-256-GCM encryption (12-byte IV and 16-byte authentication tag), SHA-256 integrity verification, explainable behavioral risk scoring, and harmless context-aware decoys for high-risk sessions.

## Threat model and limitation

The system focuses on application-level suspicious access and credential-abused/compromised users who request files through this application. It does not claim to detect every attack, nor to protect a server that an attacker already controls with unrestricted OS or root-level access. A production deployment still needs least privilege, a secrets manager, host monitoring, network segmentation, endpoint security, backups, and incident response.

## Run

Copy `backend/.env.example` to `backend/.env`, provide the existing MySQL connection and separate strong `JWT_SECRET` and `ENCRYPTION_KEY` values, then run:

```powershell
cd backend
npm install
npm start
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

The API health endpoint is `GET http://localhost:5000/api/health`. Risk weights and thresholds are centralized in `backend/config/riskConfig.js` and can also be set with the documented environment variables.

## Demonstration procedure

1. Register or log in, upload a harmless test file, and download it once: the decision is `ALLOW_REAL`.
2. Use a changed user agent/IP once: risk increases but does not by itself cause a decoy.
3. Generate repeated failed logins and repeated downloads, then retry with correct credentials and a changed device context: the combined score reaches `HIGH` and `GET /api/files/:id` returns a harmless decoy without decrypting the real file.
4. Request another user's file ID: the API returns `403` and logs a denied access.
5. For integrity testing, alter a byte of a disposable encrypted file in `backend/storage/real`; access returns `409` and records `FILE_INTEGRITY_FAILURE`. Restore or remove that disposable test file afterward.

The dashboard requires a user record with `role = 'ADMIN'`; ordinary users are explicitly denied `/api/admin/*`.
