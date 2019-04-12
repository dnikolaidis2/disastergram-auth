FROM python:3.6

EXPOSE 5000

RUN mkdir -p /opt/project/instance

COPY instance/config.py /opt/project/instance/

WORKDIR /user/src/app

COPY requirements.txt ./
RUN pip install --no-cache -r requirements.txt

COPY ./auth .

ENV FLASK_APP /user/src/app/auth
#ENV FLASK_ENV development
#ENV FLASK_DEBUG 1
CMD ["flask", "run"]