#------------------------------
# for autentication
from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from auth.security import get_current_user, verify_password, get_password_hash, create_access_token  # A

#----------------------------

#----------------------------
# sample script 
from scripts.test1 import test1 as test1_script
#----------------------------

import os

#----------------------------
# Dummy user store for example purposes
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "hashed_password": get_password_hash("secret"),
    }
}
#----------------------------

app = FastAPI();

# Simple home endpoint to verify service is running
@app.get("/")
def hello_world():
    return {"message": "home page"}

# Simple endpoint to test file script
@app.get("/test1")
def test1():
    return test1_script()


@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    print(form_data)
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/validate-token")
def validate_token(user: str = Depends(get_current_user)):
    return {"message": "you are now authenticated", "user": user}


# test jwt token
def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user
