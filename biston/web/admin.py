from django.contrib import admin
from  .models import Expense , Income , Token , Passwordresetcodes , News
# Register your models here.

admin.site.register(Expense)
admin.site.register(Income)
admin.site.register(Token)
admin.site.register(Passwordresetcodes)
admin.site.register(News)