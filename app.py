import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from jose import JWTError, jwt

# ---------- Конфигурация ----------
SECRET_KEY = "supersecretkeychangeinproduction"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DB_NAME = "jobboard.db"

app = FastAPI(title="Биржа труда")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ---------- Хеширование паролей ----------
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256((password + salt).encode('utf-8'))
    return f"{salt}${hash_obj.hexdigest()}"

def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, hash_value = hashed.split('$')
        new_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
        return new_hash == hash_value
    except:
        return False

# ---------- База данных ----------
def get_db():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        DROP TABLE IF EXISTS applications;
        DROP TABLE IF EXISTS vacancies;
        DROP TABLE IF EXISTS users;
        
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT CHECK(role IN ('employer', 'applicant')) NOT NULL,
            resume TEXT DEFAULT ''
        );
        CREATE TABLE vacancies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            requirements TEXT,
            salary INTEGER,
            location TEXT,
            employer_id INTEGER NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employer_id) REFERENCES users(id)
        );
        CREATE TABLE applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vacancy_id INTEGER NOT NULL,
            applicant_id INTEGER NOT NULL,
            message TEXT,
            status TEXT CHECK(status IN ('pending', 'accepted', 'rejected')) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vacancy_id) REFERENCES vacancies(id),
            FOREIGN KEY (applicant_id) REFERENCES users(id)
        );
        """)
    print("База данных пересоздана.")

# ---------- Модели Pydantic ----------
class UserRegister(BaseModel):
    username: str
    password: str
    email: str
    full_name: str
    role: str = Field(..., pattern="^(employer|applicant)$")

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    resume: Optional[str] = None

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    resume: Optional[str] = ""

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str
    role: str

class VacancyCreate(BaseModel):
    title: str
    description: str
    requirements: Optional[str] = None
    salary: Optional[int] = None
    location: Optional[str] = None

class VacancyUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    requirements: Optional[str] = None
    salary: Optional[int] = None
    location: Optional[str] = None
    is_active: Optional[bool] = None

class VacancyOut(BaseModel):
    id: int
    title: str
    description: str
    requirements: Optional[str]
    salary: Optional[int]
    location: Optional[str]
    employer_id: int
    is_active: bool
    created_at: str

class ApplicationCreate(BaseModel):
    vacancy_id: int
    message: Optional[str] = None

class ApplicationOut(BaseModel):
    id: int
    vacancy_id: int
    applicant_id: int
    applicant_name: Optional[str] = ""
    applicant_email: Optional[str] = ""
    applicant_resume: Optional[str] = ""
    message: Optional[str]
    status: str
    created_at: str

# ---------- Утилиты безопасности ----------
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось подтвердить учётные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (token_data.username,)).fetchone()
    if user is None:
        raise credentials_exception
    return dict(user)

# ---------- Эндпоинты ----------
@app.on_event("startup")
def startup():
    init_db()

@app.post("/register", response_model=UserOut)
def register(user: UserRegister):
    db = get_db()
    if db.execute("SELECT id FROM users WHERE username = ?", (user.username,)).fetchone():
        raise HTTPException(status_code=400, detail="Пользователь с таким именем уже существует")
    hashed = hash_password(user.password)
    db.execute(
        "INSERT INTO users (username, password_hash, email, full_name, role, resume) VALUES (?,?,?,?,?,?)",
        (user.username, hashed, user.email, user.full_name, user.role, "")
    )
    db.commit()
    new_user = db.execute("SELECT * FROM users WHERE username = ?", (user.username,)).fetchone()
    return dict(new_user)

@app.post("/token", response_model=Token)
def login(username: str = Query(...), password: str = Query(...)):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Неверное имя пользователя или пароль")
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserOut)
def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.put("/users/me", response_model=UserOut)
def update_profile(update: UserUpdate, current_user: dict = Depends(get_current_user)):
    db = get_db()
    fields = []
    params = []
    if update.full_name is not None:
        fields.append("full_name = ?")
        params.append(update.full_name)
    if update.email is not None:
        fields.append("email = ?")
        params.append(update.email)
    if update.resume is not None:
        fields.append("resume = ?")
        params.append(update.resume)
    if fields:
        params.append(current_user["id"])
        db.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", params)
        db.commit()
    updated = db.execute("SELECT * FROM users WHERE id = ?", (current_user["id"],)).fetchone()
    return dict(updated)

@app.get("/my-applications-vacancy-ids")
def get_my_application_vacancy_ids(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "applicant":
        return []
    db = get_db()
    rows = db.execute(
        "SELECT vacancy_id FROM applications WHERE applicant_id = ?",
        (current_user["id"],)
    ).fetchall()
    return [r["vacancy_id"] for r in rows]

@app.post("/vacancies", response_model=VacancyOut)
def create_vacancy(vacancy: VacancyCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "employer":
        raise HTTPException(status_code=403, detail="Только работодатель может создавать вакансии")
    db = get_db()
    db.execute(
        "INSERT INTO vacancies (title, description, requirements, salary, location, employer_id) VALUES (?,?,?,?,?,?)",
        (vacancy.title, vacancy.description, vacancy.requirements, vacancy.salary, vacancy.location, current_user["id"])
    )
    db.commit()
    last_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    new_vac = db.execute("SELECT * FROM vacancies WHERE id = ?", (last_id,)).fetchone()
    return dict(new_vac)

@app.get("/vacancies", response_model=List[VacancyOut])
def list_vacancies(
    search: Optional[str] = None,
    location: Optional[str] = None,
    min_salary: Optional[int] = None,
    max_salary: Optional[int] = None,
    active_only: bool = True
):
    db = get_db()
    query = "SELECT * FROM vacancies WHERE 1=1"
    params = []
    if active_only:
        query += " AND is_active = 1"
    if search:
        query += " AND title LIKE ?"
        params.append(f"%{search}%")
    if location:
        query += " AND location LIKE ?"
        params.append(f"%{location}%")
    if min_salary is not None:
        query += " AND salary >= ?"
        params.append(min_salary)
    if max_salary is not None:
        query += " AND salary <= ?"
        params.append(max_salary)
    vacancies = db.execute(query, params).fetchall()
    return [dict(v) for v in vacancies]

@app.get("/vacancies/{vacancy_id}", response_model=VacancyOut)
def get_vacancy(vacancy_id: int):
    db = get_db()
    vac = db.execute("SELECT * FROM vacancies WHERE id = ?", (vacancy_id,)).fetchone()
    if not vac:
        raise HTTPException(status_code=404, detail="Вакансия не найдена")
    return dict(vac)

@app.put("/vacancies/{vacancy_id}", response_model=VacancyOut)
def update_vacancy(vacancy_id: int, update: VacancyUpdate, current_user: dict = Depends(get_current_user)):
    db = get_db()
    vac = db.execute("SELECT * FROM vacancies WHERE id = ?", (vacancy_id,)).fetchone()
    if not vac:
        raise HTTPException(status_code=404, detail="Вакансия не найдена")
    if vac["employer_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Вы не владелец этой вакансии")
    fields = []
    params = []
    if update.title is not None:
        fields.append("title = ?")
        params.append(update.title)
    if update.description is not None:
        fields.append("description = ?")
        params.append(update.description)
    if update.requirements is not None:
        fields.append("requirements = ?")
        params.append(update.requirements)
    if update.salary is not None:
        fields.append("salary = ?")
        params.append(update.salary)
    if update.location is not None:
        fields.append("location = ?")
        params.append(update.location)
    if update.is_active is not None:
        fields.append("is_active = ?")
        params.append(1 if update.is_active else 0)
    if fields:
        params.append(vacancy_id)
        db.execute(f"UPDATE vacancies SET {', '.join(fields)} WHERE id = ?", params)
        db.commit()
    updated = db.execute("SELECT * FROM vacancies WHERE id = ?", (vacancy_id,)).fetchone()
    return dict(updated)

@app.delete("/vacancies/{vacancy_id}")
def delete_vacancy(vacancy_id: int, current_user: dict = Depends(get_current_user)):
    db = get_db()
    vac = db.execute("SELECT * FROM vacancies WHERE id = ?", (vacancy_id,)).fetchone()
    if not vac:
        raise HTTPException(status_code=404, detail="Вакансия не найдена")
    if vac["employer_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Вы не владелец этой вакансии")
    db.execute("DELETE FROM applications WHERE vacancy_id = ?", (vacancy_id,))
    db.execute("DELETE FROM vacancies WHERE id = ?", (vacancy_id,))
    db.commit()
    return {"detail": "Вакансия удалена"}

@app.get("/my-vacancies", response_model=List[VacancyOut])
def my_vacancies(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "employer":
        raise HTTPException(status_code=403, detail="Только для работодателей")
    db = get_db()
    vacs = db.execute("SELECT * FROM vacancies WHERE employer_id = ?", (current_user["id"],)).fetchall()
    return [dict(v) for v in vacs]

@app.post("/applications", response_model=ApplicationOut)
def create_application(app_data: ApplicationCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "applicant":
        raise HTTPException(status_code=403, detail="Только соискатель может откликаться")
    db = get_db()
    vac = db.execute("SELECT * FROM vacancies WHERE id = ? AND is_active = 1", (app_data.vacancy_id,)).fetchone()
    if not vac:
        raise HTTPException(status_code=404, detail="Активная вакансия не найдена")
    existing = db.execute(
        "SELECT id FROM applications WHERE vacancy_id = ? AND applicant_id = ?",
        (app_data.vacancy_id, current_user["id"])
    ).fetchone()
    if existing:
        raise HTTPException(status_code=400, detail="Вы уже откликнулись на эту вакансию")
    db.execute(
        "INSERT INTO applications (vacancy_id, applicant_id, message) VALUES (?,?,?)",
        (app_data.vacancy_id, current_user["id"], app_data.message)
    )
    db.commit()
    last_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    new_app = db.execute("SELECT * FROM applications WHERE id = ?", (last_id,)).fetchone()
    result = dict(new_app)
    result["applicant_name"] = current_user["full_name"]
    result["applicant_email"] = current_user["email"]
    result["applicant_resume"] = current_user.get("resume", "")
    return result

@app.get("/applications", response_model=List[ApplicationOut])
def get_applications(vacancy_id: Optional[int] = None, current_user: dict = Depends(get_current_user)):
    db = get_db()
    if current_user["role"] == "employer":
        if vacancy_id:
            vac = db.execute("SELECT * FROM vacancies WHERE id = ? AND employer_id = ?", (vacancy_id, current_user["id"])).fetchone()
            if not vac:
                raise HTTPException(status_code=403, detail="Нет доступа к откликам этой вакансии")
            apps = db.execute("""
                SELECT a.*, u.full_name as applicant_name, u.email as applicant_email, u.resume as applicant_resume
                FROM applications a JOIN users u ON a.applicant_id = u.id
                WHERE a.vacancy_id = ?
            """, (vacancy_id,)).fetchall()
        else:
            apps = db.execute("""
                SELECT a.*, u.full_name as applicant_name, u.email as applicant_email, u.resume as applicant_resume
                FROM applications a JOIN users u ON a.applicant_id = u.id
                JOIN vacancies v ON a.vacancy_id = v.id
                WHERE v.employer_id = ?
            """, (current_user["id"],)).fetchall()
        return [dict(a) for a in apps]
    else:
        apps = db.execute("""
            SELECT a.*, u.full_name as applicant_name, u.email as applicant_email, u.resume as applicant_resume
            FROM applications a JOIN users u ON a.applicant_id = u.id
            WHERE a.applicant_id = ?
        """, (current_user["id"],)).fetchall()
        return [dict(a) for a in apps]

@app.put("/applications/{application_id}/status")
def change_application_status(
    application_id: int,
    status: str = Query(..., pattern="^(accepted|rejected)$"),
    current_user: dict = Depends(get_current_user)
):
    if current_user["role"] != "employer":
        raise HTTPException(status_code=403)
    db = get_db()
    app = db.execute("SELECT * FROM applications WHERE id = ?", (application_id,)).fetchone()
    if not app:
        raise HTTPException(status_code=404, detail="Отклик не найден")
    vac = db.execute("SELECT * FROM vacancies WHERE id = ? AND employer_id = ?", (app["vacancy_id"], current_user["id"])).fetchone()
    if not vac:
        raise HTTPException(status_code=403, detail="Нет прав на изменение статуса")
    db.execute("UPDATE applications SET status = ? WHERE id = ?", (status, application_id))
    db.commit()
    updated = db.execute("SELECT * FROM applications WHERE id = ?", (application_id,)).fetchone()
    return dict(updated)

# ---------- Фронтенд с адаптивной мобильной версией ----------
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Биржа труда</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #eef1f5; min-height: 100vh; }
        .container { max-width: 960px; margin: 0 auto; padding: 24px; }
        .header { background: #2c3e50; color: #fff; padding: 20px 28px; border-radius: 4px; margin-bottom: 20px; }
        .header h1 { font-size: 24px; font-weight: 600; }
        .header p { opacity: 0.7; margin-top: 4px; font-size: 14px; }
        
        /* Навигация */
        nav { background: #fff; padding: 0; border-radius: 4px; margin-bottom: 20px; display: flex; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow: hidden; flex-wrap: wrap; }
        nav a { text-decoration: none; color: #555; padding: 14px 20px; cursor: pointer; font-size: 14px; border-bottom: 2px solid transparent; transition: all 0.2s; white-space: nowrap; }
        nav a:hover { color: #2c3e50; background: #f8f9fa; border-bottom-color: #3498db; }
        nav a.logout-link { margin-left: auto; color: #c0392b; }
        
        /* Карточки */
        .card { background: #fff; border-radius: 4px; padding: 20px 24px; margin-bottom: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); border-left: 3px solid #3498db; }
        .card h3 { font-size: 17px; color: #2c3e50; margin-bottom: 8px; }
        .card p { color: #555; font-size: 14px; line-height: 1.5; margin-bottom: 4px; }
        .card .meta { font-size: 13px; color: #888; margin-top: 6px; }
        
        /* Формы */
        input, select, textarea { width: 100%; padding: 10px 12px; border: 1px solid #dde; border-radius: 4px; font-size: 14px; margin-bottom: 10px; font-family: inherit; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: #3498db; }
        textarea { min-height: 90px; resize: vertical; }
        
        /* Кнопки */
        button { padding: 10px 20px; border: none; border-radius: 4px; font-size: 14px; cursor: pointer; font-weight: 500; transition: background 0.2s; margin-right: 6px; margin-bottom: 6px; }
        .btn-primary { background: #3498db; color: #fff; }
        .btn-primary:hover { background: #2980b9; }
        .btn-secondary { background: #95a5a6; color: #fff; }
        .btn-secondary:hover { background: #7f8c8d; }
        .btn-danger { background: #c0392b; color: #fff; }
        .btn-danger:hover { background: #a93226; }
        .btn-success { background: #27ae60; color: #fff; }
        .btn-success:hover { background: #219a52; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        
        /* Бейджи */
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: 600; }
        .badge-active { background: #d5f5e3; color: #1e8449; }
        .badge-inactive { background: #fadbd8; color: #922b21; }
        .badge-pending { background: #fef9e7; color: #7d6608; }
        .badge-accepted { background: #d5f5e3; color: #1e8449; }
        .badge-rejected { background: #fadbd8; color: #922b21; }
        .badge-applied { background: #d6eaf8; color: #1a5276; }
        
        /* Фильтр */
        .filter-bar { background: #fff; padding: 16px 20px; border-radius: 4px; margin-bottom: 16px; display: flex; gap: 10px; flex-wrap: wrap; align-items: end; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
        .filter-bar input { width: auto; flex: 1; min-width: 140px; margin-bottom: 0; }
        
        /* Остальное */
        .error { background: #fadbd8; color: #922b21; padding: 10px 14px; border-radius: 4px; margin: 8px 0; font-size: 14px; }
        .info-bar { background: #d6eaf8; color: #1a5276; padding: 12px 16px; border-radius: 4px; margin-bottom: 16px; font-size: 14px; }
        .hidden { display: none; }
        .form-card { background: #fff; border-radius: 4px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); max-width: 460px; margin: 0 auto; }
        .form-card h3 { margin-bottom: 18px; color: #2c3e50; font-size: 18px; }
        .btn-group { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
        label { font-size: 14px; color: #555; display: block; margin-bottom: 4px; }
        .resume-block { background: #f8f9fa; border-radius: 4px; padding: 12px 16px; margin: 8px 0; font-size: 14px; white-space: pre-wrap; color: #444; border-left: 3px solid #3498db; }
        .applicant-info { background: #f8f9fa; border-radius: 4px; padding: 12px 16px; margin: 10px 0; }
        .applicant-info p { margin-bottom: 4px; }
        
        /* Медиа-запросы для мобильной версии */
        @media (max-width: 768px) {
            .container { padding: 12px; }
            .header { padding: 16px; border-radius: 0; margin: -12px -12px 16px -12px; }
            .header h1 { font-size: 20px; }
            .header p { font-size: 12px; }
            
            nav { border-radius: 0; margin: 0 -12px 16px -12px; flex-direction: column; }
            nav a { padding: 12px 16px; border-bottom: 1px solid #eee; border-left: none; text-align: center; }
            nav a.logout-link { margin-left: 0; background: #fadbd8; }
            
            .form-card { max-width: 100%; padding: 20px 16px; }
            
            .filter-bar { flex-direction: column; padding: 12px; }
            .filter-bar input { width: 100%; min-width: auto; }
            
            .card { padding: 16px; }
            .card h3 { font-size: 16px; }
            
            .btn-group { flex-direction: column; }
            .btn-group button { width: 100%; margin-right: 0; }
            button { width: 100%; margin-right: 0; padding: 12px; font-size: 15px; }
            
            .applicant-info { padding: 10px; }
            .resume-block { padding: 10px; }
        }
        
        @media (max-width: 480px) {
            body { font-size: 13px; }
            .header h1 { font-size: 18px; }
            .card h3 { font-size: 15px; }
            .card p { font-size: 13px; }
            input, select, textarea, button { font-size: 16px; }
            .badge { font-size: 11px; padding: 2px 6px; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Биржа труда</h1>
        <p>Платформа для поиска работы и подбора персонала</p>
    </div>

    <nav id="mainNav" class="hidden">
        <a onclick="showSection('vacancies')">Все вакансии</a>
        <a onclick="showSection('createVacancy')" id="employerLinkCreate" class="hidden">Создать вакансию</a>
        <a onclick="showSection('myVacancies')" id="employerLinkMy" class="hidden">Мои вакансии</a>
        <a onclick="showSection('myApplications')" id="applicantLinkApps" class="hidden">Мои отклики</a>
        <a onclick="showSection('profile')">Профиль</a>
        <a onclick="logout()" class="logout-link">Выйти</a>
    </nav>

    <div id="authBlock">
        <div id="loginForm" class="form-card">
            <h3>Вход в систему</h3>
            <input type="text" id="loginUsername" placeholder="Логин">
            <input type="password" id="loginPassword" placeholder="Пароль">
            <button class="btn-primary" onclick="login()">Войти</button>
            <button class="btn-secondary" onclick="showRegister()">Регистрация</button>
            <p id="loginError" class="error hidden"></p>
        </div>
        <div id="registerForm" class="form-card hidden">
            <h3>Регистрация</h3>
            <input type="text" id="regUsername" placeholder="Логин">
            <input type="password" id="regPassword" placeholder="Пароль">
            <input type="text" id="regFullName" placeholder="Полное имя">
            <input type="email" id="regEmail" placeholder="Email">
            <select id="regRole">
                <option value="applicant">Соискатель</option>
                <option value="employer">Работодатель</option>
            </select>
            <button class="btn-primary" onclick="register()">Зарегистрироваться</button>
            <button class="btn-secondary" onclick="showLogin()">Назад ко входу</button>
            <p id="regError" class="error hidden"></p>
        </div>
    </div>
    <div id="content" class="hidden"></div>
</div>

<script>
    const API = '';
    let token = localStorage.getItem('token');
    let currentUser = null;
    let myApplicationIds = [];

    function api(endpoint, method='GET', body=null) {
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = 'Bearer ' + token;
        const options = { method, headers };
        if (body) options.body = JSON.stringify(body);
        return fetch(API + endpoint, options).then(r => {
            if (!r.ok) return r.json().then(err => { throw new Error(err.detail || 'Ошибка'); });
            return r.json();
        });
    }

    async function loadUser() {
        if (!token) return false;
        try {
            currentUser = await api('/users/me');
            document.getElementById('authBlock').classList.add('hidden');
            document.getElementById('mainNav').classList.remove('hidden');
            const role = currentUser.role;
            document.getElementById('employerLinkCreate').classList.toggle('hidden', role !== 'employer');
            document.getElementById('employerLinkMy').classList.toggle('hidden', role !== 'employer');
            document.getElementById('applicantLinkApps').classList.toggle('hidden', role !== 'applicant');
            if (role === 'applicant') {
                myApplicationIds = await api('/my-applications-vacancy-ids');
            }
            showSection('vacancies');
            return true;
        } catch(e) {
            token = null;
            localStorage.removeItem('token');
            return false;
        }
    }

    function showSection(name) {
        const content = document.getElementById('content');
        content.classList.remove('hidden');
        switch(name) {
            case 'vacancies': loadVacancies(); break;
            case 'createVacancy': showCreateVacancyForm(); break;
            case 'myVacancies': loadMyVacancies(); break;
            case 'myApplications': loadMyApplications(); break;
            case 'profile': loadProfile(); break;
        }
    }

    async function login() {
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;
        document.getElementById('loginError').classList.add('hidden');
        try {
            const data = await fetch(API + `/token?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`, {method:'POST'}).then(r => r.json());
            if (data.access_token) {
                token = data.access_token;
                localStorage.setItem('token', token);
                await loadUser();
            } else {
                document.getElementById('loginError').textContent = 'Неверный логин или пароль';
                document.getElementById('loginError').classList.remove('hidden');
            }
        } catch(e) {
            document.getElementById('loginError').textContent = 'Ошибка входа';
            document.getElementById('loginError').classList.remove('hidden');
        }
    }

    async function register() {
        const body = {
            username: document.getElementById('regUsername').value,
            password: document.getElementById('regPassword').value,
            full_name: document.getElementById('regFullName').value,
            email: document.getElementById('regEmail').value,
            role: document.getElementById('regRole').value
        };
        document.getElementById('regError').classList.add('hidden');
        try {
            await api('/register', 'POST', body);
            alert('Регистрация успешна. Теперь войдите в систему.');
            showLogin();
        } catch(e) {
            document.getElementById('regError').textContent = e.message;
            document.getElementById('regError').classList.remove('hidden');
        }
    }

    function showRegister() {
        document.getElementById('loginForm').classList.add('hidden');
        document.getElementById('registerForm').classList.remove('hidden');
    }
    function showLogin() {
        document.getElementById('loginForm').classList.remove('hidden');
        document.getElementById('registerForm').classList.add('hidden');
    }

    function logout() {
        token = null;
        currentUser = null;
        myApplicationIds = [];
        localStorage.removeItem('token');
        document.getElementById('authBlock').classList.remove('hidden');
        document.getElementById('mainNav').classList.add('hidden');
        document.getElementById('content').classList.add('hidden');
    }

    async function loadProfile() {
        const user = await api('/users/me');
        let html = '<h2>Профиль</h2><div class="card">';
        html += `<p><strong>Имя:</strong> ${user.full_name}</p>`;
        html += `<p><strong>Email:</strong> ${user.email}</p>`;
        html += `<p><strong>Роль:</strong> ${user.role === 'employer' ? 'Работодатель' : 'Соискатель'}</p>`;
        if (user.role === 'applicant') {
            html += `<p><strong>Резюме:</strong></p><div class="resume-block">${user.resume || 'Не заполнено'}</div>`;
        }
        html += `<button class="btn-primary" onclick="editProfile()">Редактировать</button></div>`;
        document.getElementById('content').innerHTML = html;
    }

    function editProfile() {
        document.getElementById('content').innerHTML = `
            <h2>Редактирование профиля</h2>
            <div class="card">
                <label>Полное имя</label>
                <input id="editFullName" value="${currentUser.full_name}">
                <label>Email</label>
                <input id="editEmail" value="${currentUser.email}">
                ${currentUser.role === 'applicant' ? `
                    <label>Резюме (образование, опыт, навыки)</label>
                    <textarea id="editResume" rows="6">${currentUser.resume || ''}</textarea>
                ` : ''}
                <button class="btn-primary" onclick="saveProfile()">Сохранить</button>
            </div>
        `;
    }

    async function saveProfile() {
        const body = {
            full_name: document.getElementById('editFullName').value,
            email: document.getElementById('editEmail').value
        };
        if (currentUser.role === 'applicant') {
            body.resume = document.getElementById('editResume').value;
        }
        try {
            currentUser = await api('/users/me', 'PUT', body);
            alert('Профиль обновлён');
            loadProfile();
        } catch(e) {
            alert('Ошибка: ' + e.message);
        }
    }

    async function loadVacancies() {
        const search = document.getElementById('searchInput')?.value || '';
        const location = document.getElementById('locationInput')?.value || '';
        const min = document.getElementById('minSalary')?.value || '';
        const max = document.getElementById('maxSalary')?.value || '';
        let params = new URLSearchParams();
        if (search) params.append('search', search);
        if (location) params.append('location', location);
        if (min) params.append('min_salary', min);
        if (max) params.append('max_salary', max);
        const data = await api('/vacancies?' + params.toString());
        let html = `<h2>Список вакансий</h2>
            <div class="filter-bar">
                <input id="searchInput" placeholder="Поиск по названию" value="${search}">
                <input id="locationInput" placeholder="Город" value="${location}">
                <input id="minSalary" type="number" placeholder="Мин. зарплата" value="${min}">
                <input id="maxSalary" type="number" placeholder="Макс. зарплата" value="${max}">
                <button class="btn-primary" onclick="loadVacancies()">Искать</button>
            </div>`;
        if (data.length === 0) html += '<div class="info-bar">Вакансий не найдено</div>';
        data.forEach(v => {
            const alreadyApplied = myApplicationIds.includes(v.id);
            html += `<div class="card">
                <h3>${v.title} <span class="badge ${v.is_active ? 'badge-active' : 'badge-inactive'}">${v.is_active ? 'Активна' : 'Неактивна'}</span></h3>
                <p>${v.description}</p>
                ${v.requirements ? `<p><strong>Требования:</strong> ${v.requirements}</p>` : ''}
                <p class="meta"><strong>Зарплата:</strong> ${v.salary ? v.salary + ' руб.' : 'не указана'} | <strong>Город:</strong> ${v.location || 'не указан'}</p>
                ${currentUser?.role === 'applicant' ? 
                    (alreadyApplied ? 
                        '<span class="badge badge-applied">Отклик отправлен</span>' : 
                        `<button class="btn-primary" onclick="apply(${v.id})">Откликнуться</button>`) 
                    : ''}
            </div>`;
        });
        document.getElementById('content').innerHTML = html;
    }

    async function apply(vacancyId) {
        const msg = prompt('Сопроводительное письмо (необязательно):');
        if (msg === null) return;
        try {
            await api('/applications', 'POST', { vacancy_id: vacancyId, message: msg || '' });
            myApplicationIds.push(vacancyId);
            alert('Отклик успешно отправлен.');
            loadVacancies();
        } catch(e) { alert(e.message); }
    }

    function showCreateVacancyForm() {
        document.getElementById('content').innerHTML = `<h2>Создать вакансию</h2><div class="card">
            <input id="vacTitle" placeholder="Название вакансии">
            <textarea id="vacDesc" placeholder="Описание"></textarea>
            <input id="vacReq" placeholder="Требования к кандидату">
            <input id="vacSalary" type="number" placeholder="Зарплата (руб.)">
            <input id="vacLocation" placeholder="Город">
            <button class="btn-primary" onclick="createVacancy()">Создать</button></div>`;
    }

    async function createVacancy() {
        const body = {
            title: document.getElementById('vacTitle').value,
            description: document.getElementById('vacDesc').value,
            requirements: document.getElementById('vacReq').value,
            salary: document.getElementById('vacSalary').value ? parseInt(document.getElementById('vacSalary').value) : null,
            location: document.getElementById('vacLocation').value
        };
        try {
            await api('/vacancies', 'POST', body);
            alert('Вакансия создана.');
            showSection('myVacancies');
        } catch(e) { alert(e.message); }
    }

    async function loadMyVacancies() {
        const data = await api('/my-vacancies');
        let html = '<h2>Мои вакансии</h2>';
        if (data.length === 0) html += '<div class="info-bar">У вас пока нет вакансий</div>';
        data.forEach(v => {
            html += `<div class="card">
                <h3>${v.title} <span class="badge ${v.is_active ? 'badge-active' : 'badge-inactive'}">${v.is_active ? 'Активна' : 'Неактивна'}</span></h3>
                <p>${v.description}</p>
                <p class="meta"><strong>Зарплата:</strong> ${v.salary ? v.salary + ' руб.' : 'не указана'} | <strong>Город:</strong> ${v.location || 'не указан'}</p>
                <div class="btn-group">
                    <button class="btn-primary" onclick="editVacancy(${v.id})">Редактировать</button>
                    <button class="btn-danger" onclick="deleteVacancy(${v.id})">Удалить</button>
                    <button class="btn-secondary" onclick="viewApplications(${v.id})">Отклики</button>
                </div></div>`;
        });
        document.getElementById('content').innerHTML = html;
    }

    async function editVacancy(id) {
        const vac = await api('/vacancies/' + id);
        document.getElementById('content').innerHTML = `<h2>Редактировать</h2><div class="card">
            <input id="editTitle" value="${vac.title}">
            <textarea id="editDesc">${vac.description}</textarea>
            <input id="editReq" value="${vac.requirements || ''}">
            <input id="editSalary" type="number" value="${vac.salary || ''}">
            <input id="editLocation" value="${vac.location || ''}">
            <label><input type="checkbox" id="editActive" ${vac.is_active ? 'checked' : ''} style="width:auto;"> Вакансия активна</label>
            <button class="btn-primary" onclick="updateVacancy(${id})">Сохранить</button></div>`;
    }

    async function updateVacancy(id) {
        const body = {
            title: document.getElementById('editTitle').value,
            description: document.getElementById('editDesc').value,
            requirements: document.getElementById('editReq').value,
            salary: document.getElementById('editSalary').value ? parseInt(document.getElementById('editSalary').value) : null,
            location: document.getElementById('editLocation').value,
            is_active: document.getElementById('editActive').checked
        };
        try { await api('/vacancies/' + id, 'PUT', body); alert('Обновлено.'); showSection('myVacancies'); }
        catch(e) { alert(e.message); }
    }

    async function deleteVacancy(id) {
        if (confirm('Удалить вакансию?')) {
            await api('/vacancies/' + id, 'DELETE');
            showSection('myVacancies');
        }
    }

    async function viewApplications(vacancyId) {
        const apps = await api('/applications?vacancy_id=' + vacancyId);
        let html = '<h2>Отклики</h2>';
        if (apps.length === 0) html += '<div class="info-bar">Нет откликов</div>';
        apps.forEach(a => {
            html += `<div class="card">
                <div class="applicant-info">
                    <p><strong>Соискатель:</strong> ${a.applicant_name}</p>
                    <p><strong>Email:</strong> ${a.applicant_email}</p>
                    ${a.applicant_resume ? `<p><strong>Резюме:</strong></p><div class="resume-block">${a.applicant_resume}</div>` : '<p>Резюме не заполнено</p>'}
                </div>
                ${a.message ? `<p><strong>Сопроводительное письмо:</strong> ${a.message}</p>` : ''}
                <p><strong>Статус:</strong> <span class="badge badge-${a.status}">${a.status === 'pending' ? 'На рассмотрении' : a.status === 'accepted' ? 'Принят' : 'Отклонён'}</span></p>
                <div class="btn-group">
                    <button class="btn-success" onclick="changeStatus(${a.id}, 'accepted')">Принять</button>
                    <button class="btn-danger" onclick="changeStatus(${a.id}, 'rejected')">Отклонить</button>
                </div></div>`;
        });
        document.getElementById('content').innerHTML = html;
    }

    async function changeStatus(appId, newStatus) {
        try { await api(`/applications/${appId}/status?status=${newStatus}`, 'PUT'); alert('Статус обновлён.'); }
        catch(e) { alert(e.message); }
    }

    async function loadMyApplications() {
        const data = await api('/applications');
        let html = '<h2>Мои отклики</h2>';
        if (data.length === 0) html += '<div class="info-bar">Вы пока не откликались на вакансии</div>';
        data.forEach(a => {
            html += `<div class="card">
                <p><strong>Вакансия ID:</strong> ${a.vacancy_id}</p>
                ${a.message ? `<p><strong>Сообщение:</strong> ${a.message}</p>` : ''}
                <p><strong>Статус:</strong> <span class="badge badge-${a.status}">${a.status === 'pending' ? 'На рассмотрении' : a.status === 'accepted' ? 'Принят' : 'Отклонён'}</span></p>
                </div>`;
        });
        document.getElementById('content').innerHTML = html;
    }

    loadUser();
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return HTML_CONTENT

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
