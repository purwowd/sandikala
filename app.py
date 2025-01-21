from fastapi import FastAPI, HTTPException, UploadFile, Form, Request, Header, Depends
from fastapi.responses import FileResponse
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.orm import sessionmaker, declarative_base
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = FastAPI()


UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

SECRET_KEY = b"super_secret_key_32_bytes"
DATABASE_URL = "sqlite:///./devices.db"
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    serial_number = Column(String, unique=True, index=True)
    token = Column(String, unique=True)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def derive_key_iv(password: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key_iv = kdf.derive(password)
    return key_iv[:32], key_iv[32:]


def validate_device(serial_number: str, token: str, db):
    device = db.query(Device).filter(Device.serial_number == serial_number, Device.token == token).first()

    if not serial_number or not token:
        raise HTTPException(status_code=401, detail="Invalid device or token!")

    if not device:
        raise HTTPException(status_code=401, detail="Invalid device or token!")


@app.post("/add_device/")
def add_device(serial_number: str = Form(...), token: str = Form(...), db=Depends(get_db)):
    if db.query(Device).filter(Device.serial_number == serial_number).first():
        raise HTTPException(status_code=400, detail="Device already exists!")

    new_device = Device(serial_number=serial_number, token=token)
    db.add(new_device)
    db.commit()
    return {"message": "Device added successfully", "serial_number": serial_number}


@app.post("/encrypt/")
async def encrypt_file(
    request: Request,
    file: UploadFile,
    serial_number: str = Form(...),
    token: str = Header(..., alias="X-Sandikala-Token"),
    db=Depends(get_db),
):
    try:
        validate_device(serial_number, token, db)
        file_data = await file.read()

        salt = os.urandom(16)
        key, iv = derive_key_iv(SECRET_KEY, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        encrypted_filename = f"{os.path.splitext(file.filename)[0]}_encrypted.jpg"
        encrypted_file_path = os.path.join(UPLOAD_DIR, encrypted_filename)
        with open(encrypted_file_path, "wb") as f:
            f.write(encrypted_data)

        metadata_filename = f"{os.path.splitext(file.filename)[0]}_metadata.txt"
        metadata_file_path = os.path.join(UPLOAD_DIR, metadata_filename)
        with open(metadata_file_path, "w") as f:
            f.write(f"serial_number={serial_number}\n")
            f.write(f"salt={base64.b64encode(salt).decode()}\n")

        base_url = str(request.base_url).strip("/")
        return {
            "message": "File terenkripsi berhasil.",
            "encrypted_file": f"{base_url}/files/{encrypted_filename}",
            "metadata_file": f"{base_url}/files/{metadata_filename}",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/decrypt/")
async def decrypt_file(
    request: Request,
    file: UploadFile,
    metadata_file: UploadFile,
    serial_number: str = Form(...),
    token: str = Header(..., alias="X-Sandikala-Token"),
    db=Depends(get_db),
):
    try:
        validate_device(serial_number, token, db)
        metadata_path = os.path.join(UPLOAD_DIR, metadata_file.filename)
        with open(metadata_path, "wb") as f:
            f.write(await metadata_file.read())

        with open(metadata_path, "r") as f:
            lines = f.readlines()
            salt = lines[1].strip().split("=")[1]

        padded_salt = salt + "==="[: (4 - len(salt) % 4) % 4]
        salt_bytes = base64.b64decode(padded_salt, validate=True)
        file_data = await file.read()
        key, iv = derive_key_iv(SECRET_KEY, salt_bytes)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(file_data) + decryptor.finalize()

        decrypted_filename = f"{os.path.splitext(file.filename)[0]}_decrypted.jpg"
        decrypted_file_path = os.path.join(UPLOAD_DIR, decrypted_filename)
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        base_url = str(request.base_url).strip("/")
        return {
            "message": "File terdekripsi berhasil.",
            "decrypted_file": f"{base_url}/files/{decrypted_filename}",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/files/{filename}")
async def serve_file(
    filename: str,
    serial_number: str = Header(None, alias="X-Sandikala-Serial"),
    token: str = Header(None, alias="X-Sandikala-Token"),
    db=Depends(get_db),
):
    if not serial_number or not token:
        raise HTTPException(status_code=401, detail="Invalid token!")

    validate_device(serial_number, token, db)

    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found!")

    return FileResponse(file_path, media_type="application/octet-stream", filename=filename)

