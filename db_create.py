#!flask/bin/python
from app import app, db, models, Base, engine

import os.path
db.create_all()
# Base.metadata.create_all(bind=engine)
