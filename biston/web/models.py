from __future__ import unicode_literals
from django.utils.crypto import get_random_string
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone  # برای now

class News(models.Model):
    title = models.CharField(max_length=250)
    text = models.TextField()
    date = models.DateTimeField()

    class Meta:
        ordering = ['-date']
        verbose_name = 'News'
        verbose_name_plural = 'News'
        indexes = [
            models.Index(fields=['-date'], name='news_date_idx'),
        ]

    def __unicode__(self):
        return self.title

    def __str__(self):
        return self.title

class Passwordresetcodes(models.Model):
    code = models.CharField(max_length=32)
    email = models.CharField(max_length=120)
    time = models.DateTimeField()
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=128)  # hashed password (افزایش طول برای امنیت)
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)  # لینک به User جدید

    class Meta:
        verbose_name = 'Password Reset Code'
        verbose_name_plural = 'Password Reset Codes'
        indexes = [
            models.Index(fields=['code'], name='pwd_reset_code_idx'),
            models.Index(fields=['email', 'time'], name='pwd_reset_email_time_idx'),
        ]

    def __unicode__(self):
        return f"{self.email} - {self.code}"

    def __str__(self):
        return f"{self.email} - {self.code}"

class Token(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=48)

    class Meta:
        verbose_name = 'Token'
        verbose_name_plural = 'Tokens'
        indexes = [
            models.Index(fields=['token'], name='token_idx'),
        ]

    def __unicode__(self):
        return "{}_token".format(self.user)

    def __str__(self):
        return f"{self.user.username}_token"

class Expense(models.Model):
    text = models.CharField(max_length=255)
    date = models.DateTimeField()
    amount = models.BigIntegerField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        ordering = ['-date']
        verbose_name = 'Expense'
        verbose_name_plural = 'Expenses'
        indexes = [
            models.Index(fields=['user', '-date'], name='expense_user_date_idx'),
            models.Index(fields=['-date'], name='expense_date_idx'),
        ]

    def __unicode__(self):
        return "{}-{}-{}".format(self.date, self.user, self.amount)

    def __str__(self):
        return f"{self.user.username} - {self.amount} - {self.date.strftime('%Y-%m-%d')}"

class Income(models.Model):
    text = models.CharField(max_length=255)
    date = models.DateTimeField()
    amount = models.BigIntegerField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        ordering = ['-date']
        verbose_name = 'Income'
        verbose_name_plural = 'Incomes'
        indexes = [
            models.Index(fields=['user', '-date'], name='income_user_date_idx'),
            models.Index(fields=['-date'], name='income_date_idx'),
        ]

    def __unicode__(self):
        return "{}-{}-{}".format(self.date, self.user, self.amount)

    def __str__(self):
        return f"{self.user.username} - {self.amount} - {self.date.strftime('%Y-%m-%d')}"