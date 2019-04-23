FROM python:3.6

EXPOSE 5000

WORKDIR /user/src/app

COPY requirements.txt ./
RUN pip install --no-cache -r requirements.txt

RUN mkdir auth
RUN mkdir instance

COPY ./auth ./auth
COPY ./instance ./instance

ENV FLASK_APP /user/src/app/auth
ENV FLASK_ENV development
ENV FLASK_DEBUG 1
CMD ["flask", "run", "--host", "0.0.0.0"]