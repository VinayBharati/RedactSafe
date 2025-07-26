from django.urls import path

from . import views

urlpatterns = [
    path("", views.Signup, name="overview"),  # Root opens Signup page
    path("Dashboard.html", views.index, name="Dashboard"),
    path("Login.html", views.Login, name="Login"),
    path("LoginAction", views.LoginAction, name="LoginAction"),
    path("Signup.html", views.Signup, name="Signup"),
    path("SignupAction", views.SignupAction, name="SignupAction"),
    path("SharedData.html", views.SharedData, name="SharedData"),
    path("SharedDataAction", views.SharedDataAction, name="SharedDataAction"),
    path("ViewSharedMessages", views.ViewSharedMessages, name="ViewSharedMessages"),
    path("Graph", views.Graph, name="communication_graph"),
    path("DownloadFileDataRequest", views.DownloadFileDataRequest, name="DownloadFileDataRequest"),
    path("SendRequest", views.SendRequest, name="SendRequest"),
    path("ViewRequest", views.ViewRequest, name="ViewRequest"),
    path("Permission", views.Permission, name="Permission"),
    path("Redaction.html", views.redact_document, name="redact_document"),
]
