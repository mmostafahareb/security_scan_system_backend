from rest_framework import serializers
from .models import *

class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = '__all__'

class TeamsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Teams
        fields = '__all__'

class ProjectsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Projects
        fields = '__all__'

class BomSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bom
        fields = '__all__'


class VulnerabilitiesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerabilities
        fields = '__all__'


class Hardcoded_CredsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hardcoded_Creds
        fields = '__all__'

class ScansSerializer(serializers.ModelSerializer):
    bom = BomSerializer(many=True, read_only=True)
    vulnerabilities = VulnerabilitiesSerializer(many=True, read_only=True)
    hardcoded_creds = Hardcoded_CredsSerializer(many=True, read_only=True)

    class Meta:
        model = Scans
        fields = '__all__'