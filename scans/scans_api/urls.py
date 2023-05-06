from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'users', views.UsersViewSet)
router.register(r'teams', views.TeamsViewSet)
router.register(r'projects', views.ProjectsViewSet)
router.register(r'scans', views.ScansViewSet)  # Add this line

urlpatterns = [
    path('', include(router.urls)),
]