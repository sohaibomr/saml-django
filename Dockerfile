FROM ghcr.io/extremenetworks/web-controller/base_images/python:3.8-slim
RUN mkdir /code
WORKDIR /code
COPY requirements.txt .
RUN apt-get update
RUN apt-get install -y pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl libffi-dev gcc make libevent-dev build-essential

# install requirements
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]