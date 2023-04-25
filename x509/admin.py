from django.contrib import admin

from .models import CSR, Certificate, Key

admin.site.register(Key)
admin.site.register(CSR)
admin.site.register(Certificate)
