from datetime import timedelta, datetime, timezone
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request, Form, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.security import OAuth2
from typing import Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from pathlib import Path


router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

SECRET_KEY = '197b2c37c391bed93fe80344fe73b806947a65e36206e05a1a23c2fa12702fe3'
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


class CreateUserRequest(BaseModel):
    username: str
    email: str
    first_name: str
    last_name: str
    password: str
    role: str
    phone_number: str


class Token(BaseModel):
    access_token: str
    token_type: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
db_dependency = Annotated[Session, Depends(get_db)]

# Pages
@router.get("/login-page", response_class=HTMLResponse)
def render_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.get("/register-page", response_class=HTMLResponse)
def render_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})



# Endpoints
class OAuth2PasswordBearerWithCookie(OAuth2):
    def __init__(self, tokenUrl: str, scheme_name: Optional[str] = None):
        flows = {
            "password": {
                "tokenUrl": tokenUrl,
                "scopes": {},
            }
        }
        super().__init__(flows=flows, scheme_name=scheme_name)

    async def __call__(self, request: Request) -> str:
        auth: str = request.headers.get("Authorization")
        if auth:
            scheme, _, param = auth.partition(" ")
            if scheme.lower() == "bearer" and param != "null":
                return param

        # fallback to cookie
        token = request.cookies.get("access_token")
        if token and token.startswith("Bearer "):
            return token[7:]

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )


oauth2_bearer = OAuth2PasswordBearerWithCookie(tokenUrl='auth/token')

def authenticate_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user


def create_access_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id, 'role': role}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        user_role: str = payload.get('role')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate user.')
        return {'username': username, 'id': user_id, 'user_role': user_role}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency,
                      create_user_request: CreateUserRequest):
    create_user_model = Users(
        email=create_user_request.email,
        username=create_user_request.username,
        first_name=create_user_request.first_name,
        last_name=create_user_request.last_name,
        role=create_user_request.role,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        is_active=True,
        phone_number=create_user_request.phone_number
    )

    db.add(create_user_model)
    db.commit()


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')
    token = create_access_token(user.username, user.id, user.role, timedelta(minutes=20))

    return {'access_token': token, 'token_type': 'bearer'}


@router.post("/register")
async def register_user(
    request: Request,
    db: db_dependency,
    username: str = Form(...),
    email: str = Form(...),
    first_name: str = Form(...),
    last_name: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    phone_number: str = Form(...)
):
    hashed_password = bcrypt_context.hash(password)

    user = Users(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        hashed_password=hashed_password,
        role=role,
        phone_number=phone_number,
        is_active=True
    )

    db.add(user)
    db.commit()

    # ✅ Redirect after success
    return RedirectResponse(url="/auth/login-page", status_code=302)

@router.post("/login")
async def login_user(
        request: Request,
        db: db_dependency,
        username: str = Form(...),
        password: str = Form(...)
):
    user = authenticate_user(username, password, db)
    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password"
        })

    token = create_access_token(user.username, user.id, user.role, timedelta(minutes=20))

    response = RedirectResponse(url="/todos/todo-page", status_code=303)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        secure=False,
        samesite="lax"
    )

    return response



@router.get("/test-cookie")
async def test_cookie():
    response = PlainTextResponse("Cookie test")
    response.set_cookie(key="access_token", value="test123", httponly=True, secure=False, samesite="lax")
    return response


