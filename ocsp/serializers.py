from rest_framework import serializers

from .models import RequestLog, Source


class SourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Source
        fields = ("id", "name", "host", "addr")


class RequestLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = RequestLog
        fields = (
            "id",
            "date",
            "cert",
            "host",
            "addr",
            "result",
            "result_display",
        )
