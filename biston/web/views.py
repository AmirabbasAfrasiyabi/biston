from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse , JsonResponse
import json
from django.shortcuts import render
# Create your views here.
from django.views.decorators.csrf import csrf_exempt
from web.models import *
from datetime import datetime



@csrf_exempt
def submit_income(request):
    """submit an income."""

    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'msg': 'POST required'})

    this_token = request.POST.get('token')

    if not this_token:
        return JsonResponse({'status': 'error', 'msg': 'Token missing'})

    try:
        this_user = User.objects.filter(token__token=this_token).get()
    except User.DoesNotExist:
        return JsonResponse({'status': 'error', 'msg': 'Invalid token'})

    Income.objects.create(
        user=this_user,
        text=request.POST['text'],
        amount=request.POST['amount'],
        date=datetime.now()
    )

    print("Iam in submit expense")
    print(request.POST)
    print("we are here")

    return JsonResponse({'status': 'ok'}, encoder=DjangoJSONEncoder)




@csrf_exempt
def submit_expense(request):
    """User submit request."""

    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'msg': 'POST required'})

    this_token = request.POST.get('token')

    if not this_token:
        return JsonResponse({'status': 'error', 'msg': 'Token missing'})

    try:
        this_user = User.objects.filter(token__token=this_token).get()
    except User.DoesNotExist:
        return JsonResponse({'status': 'error', 'msg': 'Invalid token'})

    Expense.objects.create(
        user=this_user,
        text=request.POST['text'],
        amount=request.POST['amount'],
        date=datetime.now()
    )

    print("Iam in submit expense")
    print(request.POST)
    print("we are here")

    return JsonResponse({'status': 'ok'}, encoder=DjangoJSONEncoder)
