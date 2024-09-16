from rest_framework import serializers

from .models import OVPNTemplate


class OVPNTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = OVPNTemplate
        fields = ("id", "name", "body", "created_at")
