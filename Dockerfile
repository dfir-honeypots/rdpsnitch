FROM alpine:latest

WORKDIR /app

RUN apk add python3
RUN pip3 install --upgrade pip

COPY rdp-snitch.py .
COPY constants.py .
COPY requirements.txt .

RUN pip3 install -r requirements.txt

CMD [ "python3", "rdp-snitch.py"]
