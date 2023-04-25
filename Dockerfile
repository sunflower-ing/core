FROM python:3.9.15-alpine3.15

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apk update \
    && apk --no-cache add postgresql-dev python3-dev musl-dev gcc linux-headers build-base pkgconfig \
    && rm -rf /var/cache/apk/*

COPY ./requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /sunflower
WORKDIR /sunflower

ENV PYTHONPATH=/sunflower

EXPOSE 8080

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
