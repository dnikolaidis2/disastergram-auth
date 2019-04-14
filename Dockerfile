FROM python:3.6

EXPOSE 5000

RUN mkdir -p /opt/project/instance

COPY instance/config.py /opt/project/instance/

WORKDIR /user/src/app

COPY requirements.txt ./
RUN pip install --no-cache -r requirements.txt

RUN mkdir auth

COPY ./auth ./auth

ENV FLASK_APP /user/src/app/auth
CMD ["flask", "run", "--host", "0.0.0.0"]