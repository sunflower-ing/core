import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sunflower.settings")

app = Celery("sunflower")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f"Request: {self.request!r}")


app.conf.beat_schedule = {
    "sync-kc-users": {
        "task": "subjects.tasks.sync_kc",
        "schedule": crontab(minute=30, hour=23),
        # "args": (),
    },
}
