#!/usr/local/bin/python

from auth import models, create_app

app = create_app()
models.init_db(app)
