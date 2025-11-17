# -*- coding: utf-8 -*-

from json import JSONEncoder
from datetime import datetime, timedelta
import functools

from django.core import serializers
from django.core.cache import cache
from django.conf import settings
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.hashers import make_password, check_password
from django.db.models import Sum, Count, Prefetch
from django.http import JsonResponse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth import logout as auth_logout
from django.shortcuts import redirect
from django.core.mail import send_mail  # اضافه برای ایمیل

from .models import User, Token, Expense, Income, Passwordresetcodes, News
from .utils import grecaptcha_verify, RateLimited


# کش ساده برای توکن‌ها (کاهش Query)
def get_user_by_token(token):
    """دریافت کاربر با کش کردن توکن"""
    cache_key = f'user_token_{token}'
    user = cache.get(cache_key)

    if user is None:
        user = get_object_or_404(User, token__token=token)
        cache.set(cache_key, user, 300)  # کش 5 دقیقه‌ای

    return user


@csrf_exempt
def news(request):
    """اخبار با کش"""
    cache_key = 'news_list'
    news_serialized = cache.get(cache_key)

    if news_serialized is None:
        news = News.objects.all().order_by('-date')[:11]
        news_serialized = serializers.serialize("json", news)
        cache.set(cache_key, news_serialized, 60)  # کش 1 دقیقه‌ای

    return JsonResponse(news_serialized, encoder=JSONEncoder, safe=False)


@csrf_exempt
@require_POST
def login(request):
    if 'username' in request.POST and 'password' in request.POST:
        username = request.POST['username']
        password = request.POST['password']

        # استفاده از select_related برای کاهش query
        try:
            this_user = User.objects.select_related('token').get(username=username)
        except User.DoesNotExist:
            context = {'result': 'error', 'message': 'کاربر یافت نشد'}
            return JsonResponse(context, encoder=JSONEncoder)

        if not this_user.is_active:  # اضافه: چک فعال بودن
            context = {'result': 'error', 'message': 'حساب کاربری شما فعال نیست. لطفاً ایمیل فعال‌سازی را چک کنید.'}
            return JsonResponse(context, encoder=JSONEncoder)

        if check_password(password, this_user.password):
            try:
                token = this_user.token.token
            except Token.DoesNotExist:
                context = {'result': 'error', 'message': 'توکن یافت نشد'}
                return JsonResponse(context, encoder=JSONEncoder)

            context = {'result': 'ok', 'token': token}
            return JsonResponse(context, encoder=JSONEncoder)
        else:
            context = {'result': 'error', 'message': 'رمز عبور اشتباه است'}
            return JsonResponse(context, encoder=JSONEncoder)

    context = {'result': 'error', 'message': 'نام کاربری و رمز عبور الزامی است'}
    return JsonResponse(context, encoder=JSONEncoder)


def logout(request):
    auth_logout(request)
    return redirect('index')


def register(request):
    if 'requestcode' in request.POST:
        email = request.POST.get('email', '')
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')

        # بررسی با یک query
        existing = User.objects.filter(email=email).exists()
        if existing:
            context = {
                'message': 'متاسفانه این ایمیل قبلا استفاده شده است.'
            }
            return render(request, 'register.html', context)

        if User.objects.filter(username=username).exists():
            context = {
                'message': 'متاسفانه این نام کاربری قبلا استفاده شده است.'
            }
            return render(request, 'register.html', context)

        # ساخت hashed password
        hashed_password = make_password(password)
        now = datetime.now()

        # ساخت کاربر با is_active=False (ذخیره در جدول users)
        newuser = User.objects.create(
            username=username,
            password=hashed_password,
            email=email,
            is_active=False  # غیرفعال تا verify
        )

        # ساخت کد موقت و ذخیره در Passwordresetcodes (هم‌زمان)
        code = get_random_string(length=32)
        temporarycode = Passwordresetcodes(
            email=email,
            time=now,
            code=code,
            username=username,
            password=hashed_password,  # hashed رو هم ذخیره می‌کنیم (طبق درخواست)
            user=newuser  # لینک به کاربر جدید
        )
        temporarycode.save()

        # ارسال ایمیل فعال‌سازی
        activation_url = f"{request.build_absolute_uri('/accounts/register/')}?code={code}"
        subject = 'فعال‌سازی حساب کاربری بستون'
        message = f'سلام {username}،\n\nبرای فعال کردن حساب خود روی لینک زیر کلیک کنید:\n{activation_url}\n\nاین لینک تا ۲۴ ساعت معتبر است.\n\nبا تشکر، تیم بستون'
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            context = {
                'message': f'ثبت‌نام با موفقیت انجام شد. لینک فعال‌سازی به ایمیل {email} ارسال شد. لطفاً ایمیل خود را چک کنید (شامل Spam).'
            }
        except Exception as e:
            # اگر ایمیل نشد، لینک رو در صفحه نشون بده (fallback)
            html_message = f'سلام {username}،<br><br>برای فعال کردن حساب روی لینک کلیک کنید: <a href="{activation_url}">فعال‌سازی</a><br><br>این لینک تا ۲۴ ساعت معتبر است.'
            context = {
                'message': f'ثبت‌نام انجام شد اما ارسال ایمیل با مشکل مواجه شد (خطا: {str(e)}). لطفاً از لینک زیر استفاده کنید: <br>{html_message}'
            }

        return render(request, 'register.html', context)

    elif 'code' in request.GET:
        code = request.GET['code']
        try:
            new_temp_user = Passwordresetcodes.objects.get(code=code)
            # چک expire (کمتر از ۲۴ ساعت)
            if timezone.now() - new_temp_user.time > timedelta(hours=24):
                context = {
                    'message': 'این کد فعال‌سازی منقضی شده است. لطفاً دوباره ثبت‌نام کنید.'
                }
                return render(request, 'register.html', context)

            # کاربر از قبل ساخته شده، فقط فعال کن
            newuser = new_temp_user.user
            if newuser.is_active:
                context = {
                    'message': 'حساب شما قبلاً فعال شده است. می‌توانید لاگین کنید.'
                }
                return render(request, 'register.html', context)

            newuser.is_active = True
            newuser.save()

            # ساخت token
            this_token = get_random_string(length=48)
            Token.objects.create(user=newuser, token=this_token)

            # حذف کد موقت
            Passwordresetcodes.objects.filter(code=code).delete()

            context = {
                'message': f'اکانت شما فعال شد. توکن شما {this_token} است. آن را ذخیره کنید! حالا می‌توانید لاگین کنید.'
            }
            return render(request, 'index.html', context)

        except Passwordresetcodes.DoesNotExist:
            context = {
                'message': 'این کد فعال سازی معتبر نیست.'
            }
            return render(request, 'register.html', context)
    else:
        context = {'message': ''}
        return render(request, 'register.html', context)


@csrf_exempt
@require_POST
def whoami(request):
    if 'token' in request.POST:
        this_token = request.POST['token']
        this_user = get_user_by_token(this_token)

        return JsonResponse({
            'user': this_user.username,
        }, encoder=JSONEncoder)
    else:
        return JsonResponse({
            'message': 'لطفا token را نیز ارسال کنید.',
        }, encoder=JSONEncoder)


@csrf_exempt
@require_POST
def query_expenses(request):
    this_token = request.POST.get('token', '')
    num = int(request.POST.get('num', 10))

    this_user = get_user_by_token(this_token)

    # محدود کردن تعداد برای جلوگیری از query سنگین
    num = min(num, 100)

    expenses = Expense.objects.filter(user=this_user).order_by('-date')[:num]
    expenses_serialized = serializers.serialize("json", expenses)

    return JsonResponse(expenses_serialized, encoder=JSONEncoder, safe=False)


@csrf_exempt
@require_POST
def query_incomes(request):
    this_token = request.POST.get('token', '')
    num = int(request.POST.get('num', 10))

    this_user = get_user_by_token(this_token)

    # محدود کردن تعداد
    num = min(num, 100)

    incomes = Income.objects.filter(user=this_user).order_by('-date')[:num]
    incomes_serialized = serializers.serialize("json", incomes)

    return JsonResponse(incomes_serialized, encoder=JSONEncoder, safe=False)


@csrf_exempt
@require_POST
def generalstat(request):
    this_token = request.POST.get('token', '')
    this_user = get_user_by_token(this_token)

    # کش کردن آمار کلی (معمولاً کم تغییر می‌کنه)
    cache_key = f'generalstat_{this_user.id}'
    stats = cache.get(cache_key)

    if stats is None:
        income = Income.objects.filter(user=this_user).aggregate(
            Count('amount'), Sum('amount'))
        expense = Expense.objects.filter(user=this_user).aggregate(
            Count('amount'), Sum('amount'))

        stats = {'expense': expense, 'income': income}
        cache.set(cache_key, stats, 30)  # کش 30 ثانیه‌ای

    return JsonResponse(stats, encoder=JSONEncoder)


def index(request):
    context = {}
    return render(request, 'index.html', context)


@csrf_exempt
@require_POST
def edit_expense(request):
    this_text = request.POST.get('text', '')
    this_amount = request.POST.get('amount', '0')
    this_pk = request.POST.get('id', '-1')
    this_token = request.POST.get('token', '')

    this_user = get_user_by_token(this_token)
    this_expense = get_object_or_404(Expense, pk=this_pk, user=this_user)

    # فقط در صورت تغییر، update کن
    if this_expense.text != this_text or str(this_expense.amount) != this_amount:
        this_expense.text = this_text
        this_expense.amount = this_amount
        this_expense.save(update_fields=['text', 'amount'])

        # پاک کردن کش آمار
        cache.delete(f'generalstat_{this_user.id}')

    return JsonResponse({'status': 'ok'}, encoder=JSONEncoder)


@csrf_exempt
@require_POST
def edit_income(request):
    this_text = request.POST.get('text', '')
    this_amount = request.POST.get('amount', '0')
    this_pk = request.POST.get('id', '0')
    this_token = request.POST.get('token', '')

    this_user = get_user_by_token(this_token)
    this_income = get_object_or_404(Income, pk=this_pk, user=this_user)

    if this_income.text != this_text or str(this_income.amount) != this_amount:
        this_income.text = this_text
        this_income.amount = this_amount
        this_income.save(update_fields=['text', 'amount'])

        # پاک کردن کش آمار
        cache.delete(f'generalstat_{this_user.id}')

    return JsonResponse({'status': 'ok'}, encoder=JSONEncoder)


@csrf_exempt
@require_POST
def submit_income(request):
    this_date = request.POST.get('date', timezone.now())
    this_text = request.POST.get('text', '')
    this_amount = request.POST.get('amount', '0')
    this_token = request.POST.get('token', '')

    this_user = get_user_by_token(this_token)

    Income.objects.create(
        user=this_user,
        amount=this_amount,
        text=this_text,
        date=this_date
    )

    # پاک کردن کش آمار
    cache.delete(f'generalstat_{this_user.id}')

    return JsonResponse({'status': 'ok'}, encoder=JSONEncoder)


@csrf_exempt
@require_POST
def submit_expense(request):
    this_date = request.POST.get('date', timezone.now())
    this_text = request.POST.get('text', '')
    this_amount = request.POST.get('amount', '0')
    this_token = request.POST.get('token', '')

    this_user = get_user_by_token(this_token)

    Expense.objects.create(
        user=this_user,
        amount=this_amount,
        text=this_text,
        date=this_date
    )

    cache.delete(f'generalstat_{this_user.id}')

    return JsonResponse({'status': 'ok'}, encoder=JSONEncoder)