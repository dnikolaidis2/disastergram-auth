#!/bin/bash

# chmod +x init_db.py
# ./init_db.py

# check if migrations folder exists
if [[ ! -d "$FLASK_APP_MIGRATIONS" ]]; then
	flask db init
fi

flask db upgrade
