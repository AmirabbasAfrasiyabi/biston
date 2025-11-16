from django.urls import path
from . import  views

urlpatterns = [
    path('submit/expense/', views.submit_expense, name='submit_expense'),
    path('edit/expense/' , views.edit_expense, name='edit_expense'),
    path('submit/income/', views.submit_income, name='submit_income'),
    path('edit/income/' , views.edit_income, name='edit_income'),
    path('generalstat' , views.generalstat, name='generalstat'),
    path('incomes' , views.query_incomes, name='query_incomes'),
    path('expenses' , views.query_expenses, name='query_expenses'),
    path('accounts/register', views.register, name='register'),
    path('accounts/whoami', views.whoami, name='whoami'),
    path('accounts/login', views.login, name='login'),
    path('accounts/logout', views.logout, name='logout'),
    path('', views.index, name='index'),
    path('news' , views.news, name='news'),
]