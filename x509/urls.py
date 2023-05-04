from django.urls import path

from . import views

app_name = 'x509'
urlpatterns = [
    path('certificates/', views.certificates_list, name='certificates_list'),
    path(
        'certificates/<int:certificate_id>',
        views.certificate_detail,
        name='certificate_detail',
    ),
    path('certificates/new', views.certificate_new, name='certificate_new'),
    path('keys/', views.keys_list, name='keys_list'),
    path('keys/<int:key_id>', views.key_detail, name='key_detail'),
    path('keys/new', views.key_new, name='key_new'),
    path('csrs/', views.csr_list, name='csrs_list'),
    path('csrs/<int:csr_id>', views.csr_detail, name='csr_detail'),
    path('csrs/new', views.csr_new, name='csr_new'),
]
