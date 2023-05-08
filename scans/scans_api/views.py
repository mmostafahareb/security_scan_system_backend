import os
import zipfile
import tempfile
import shutil
from git import Repo
from django.core.files.storage import default_storage
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from .models import *
from .serializers import *
from .utils import *
import time
class UsersViewSet(viewsets.ModelViewSet):
    queryset = Users.objects.all()
    serializer_class = UsersSerializer

class TeamsViewSet(viewsets.ModelViewSet):
    queryset = Teams.objects.all()
    serializer_class = TeamsSerializer

class ProjectsViewSet(viewsets.ModelViewSet):
    queryset = Projects.objects.all()
    serializer_class = ProjectsSerializer
    def create(self, request, *args, **kwargs):
        raise PermissionDenied("Directly posting a new project is not allowed")

    @action(detail=False, methods=['post'])
    def create_from_git(self, request):
        git_url = request.data.get('git_url')
        project_directory = os.path.basename(git_url.rstrip('.git/').rstrip('/'))
        assigned_team_id = request.data.get('assigned_team_id')

        # ...
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                Repo.clone_from(git_url, temp_dir)
            except Exception as e:
                return Response({"error": f"Error cloning the repository: {str(e)}"},
                                status=status.HTTP_400_BAD_REQUEST)

            # Your logic for processing the cloned repository goes here
            # For example, you can store the repository files or extract relevant information

        project = Projects.objects.create(project_id=int(time.time()), project_directory=project_directory)
        serializer = ProjectsSerializer(project)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def create_from_zip(self, request):
        zip_file = request.FILES.get('zip_file')
        project_directory = os.path.splitext(zip_file.name)[0]

        # ...
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                with zipfile.ZipFile(zip_file, 'r') as zf:
                    zf.extractall(temp_dir)

                # Your logic for processing the unzipped files goes here
                # For example, you can store the files or extract relevant information

            except Exception as e:
                return Response({"error": f"Error unzipping the file: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
            finally:
                default_storage.delete(zip_file)

        project = Projects.objects.create(project_id=int(time.time()), project_directory=project_directory)
        serializer = ProjectsSerializer(project)
        return Response(serializer.data, status=status.HTTP_200_OK)
    @action(detail=True, methods=['post'])
    def trigger_scan(self, request, pk=None):
        try:
            project_id = int(pk)
        except ValueError:
            return Response({"error": "Invalid project ID"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            project = Projects.objects.get(pk=project_id)
        except Projects.DoesNotExist:
            return Response({"error": "Project not found"}, status=status.HTTP_404_NOT_FOUND)

        # Create a new Scans object
        scan = Scans.objects.create_scan(project)

        # Set the directory attribute based on the project object
        directory = project.project_directory

        scan_response = scan_project(scan, directory)
        return Response(scan_response.data, status=status.HTTP_200_OK)
class ScansViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Scans.objects.all()
    serializer_class = ScansSerializer
