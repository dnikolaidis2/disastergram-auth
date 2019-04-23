FROM tiangolo/meinheld-gunicorn:python3.6

WORKDIR /app

COPY ./auth ./auth

COPY requirements.txt .

RUN pip install --no-cache -r requirements.txt

ENV APP_MODULE "auth.__init__:create_app()"
ENV WORKERS_PER_CORE 0.5