from django.db import models


class Teams(models.Model):
    team_id = models.AutoField(primary_key=True)
    team_name = models.CharField(max_length=100)
    group_email = models.EmailField()

class Users(models.Model):
    user_id = models.AutoField(primary_key=True)
    email = models.EmailField()
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=50)
    team_id = models.ForeignKey(Teams, on_delete=models.CASCADE)
class Projects(models.Model):
    project_id = models.AutoField(primary_key=True)
    project_directory = models.TextField()
    assigned_team_id = models.ForeignKey(Teams, on_delete=models.CASCADE)


class ScansManager(models.Manager):
    def create_scan(self, project):
        scan_id = project.project_id * 1000 + project.scans_set.count()
        return self.create(scan_id=scan_id, project_id=project)

class Scans(models.Model):
    scan_id = models.IntegerField(primary_key=True)
    project_id = models.ForeignKey(Projects, on_delete=models.CASCADE)
    bom = models.ManyToManyField("Bom", blank=True)
    vulnerabilities = models.ManyToManyField("Vulnerabilities", blank=True)
    hardcoded_creds = models.ManyToManyField("Hardcoded_Creds", blank=True)

    objects = ScansManager()

class Bom(models.Model):
    bom_id = models.AutoField(primary_key=True)
    source = models.CharField(max_length=100)
    version = models.CharField(max_length=50)
    artifact = models.CharField(max_length=200)

class Vulnerabilities(models.Model):
    vuln_id = models.AutoField(primary_key=True)
    type = models.CharField(max_length=50)
    file_location = models.CharField(max_length=200)
    line_of_code = models.CharField(max_length=50)
    severity = models.CharField(max_length=50)
    cve_id = models.CharField(max_length=50)
    description = models.TextField()
    suggested_fix = models.TextField()

class Hardcoded_Creds(models.Model):
    cred_id = models.AutoField(primary_key=True)
    file_location = models.CharField(max_length=200)
    line_of_code = models.CharField(max_length=50)
