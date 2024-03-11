import math

from subjects.models import SOURCE_KEYCLOAK, SUBJECT_USER, Subject
from sunflower.celery import app
from utils.keycloak import kc_connect, kc_get_users, kc_get_users_count


@app.task(bind=True, ignore_result=True)
def sync_kc(_):
    page = 100
    first = 0
    session = kc_connect()
    total_users = kc_get_users_count(session=session)
    print(total_users)
    for _ in range(math.ceil(total_users / page)):
        users = kc_get_users(session=session, first=first, page=page)
        first += page
        for user in users:
            subj, _ = Subject.objects.get_or_create(
                type=SUBJECT_USER,
                source=SOURCE_KEYCLOAK,
                source_id=user.get("id"),
            )
            subj.enabled = user.get("enabled")
            subj.data = user
            subj.save()
