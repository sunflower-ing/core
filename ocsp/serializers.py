from rest_framework import serializers

from .models import Source, RequestLog


class SourceSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Source
        fields = ("id", "name", "host", "addr")


class RequestLogSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = RequestLog
        fields = ("id", "date", "cert", "host", "addr")
