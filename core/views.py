from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from .models import User, FA
from .forms import RegisterForm
import random
import requests
from django_ratelimit.decorators import ratelimit


from django.contrib.auth import get_user_model
User = get_user_model()

@ratelimit(key='ip', rate='5/m', block=True)
def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            token = request.POST.get('g-recaptcha-response')
            verify = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={'secret': settings.RECAPTCHA_SECRET_KEY, 'response': token}
            ).json()
            if not verify.get("success"):
                messages.error(request, "Captcha failed")
                return render(request, "index.html", {"form": form})


            user_obj, created = User.objects.get_or_create(
                email=cd["email"],
                defaults={"username": cd["username"]}
            )


            request.session['data'] = {
                'username': cd['username'],
                'email': cd['email'],
                'password': cd['password'],
            }


            code = str(random.randint(10000, 99999))
            request.session["fa_code"] = code


            FA.objects.filter(user=user_obj).delete()
            FA.objects.create(user=user_obj, code=code)


            send_mail(
                'Your 2FA Code',
                f'Your 2FA code is: {code}',
                settings.DEFAULT_FROM_EMAIL,
                [cd["email"]],
                fail_silently=False
            )

            return redirect("/FA")

    else:
        form = RegisterForm()

    return render(request, "index.html", {"form": form})

def dash(request):
    return render(request, 'dash.html')

def home(request):
    form = RegisterForm()
    return render(request, 'index.html', {'form': form})

def fa_view(request):
    return render(request, 'FA.html')

def register2(request):
    reg_data = request.session.get('data')
    fa_code = request.session.get('fa_code')

    if not reg_data or not fa_code:
        messages.error(request, "Missing code or data. Try registering again.")
        return redirect("/")

    if request.method == "POST":
        input_code = request.POST.get('2fa', '').strip()
        if input_code == fa_code:
            try:
                user = User(
                    username=reg_data['username'],
                    email=reg_data['email'],
                )
                user.set_password(reg_data['password'])
                user.save()

                request.session.pop('data', None)
                request.session.pop('fa_code', None)

                messages.success(request, "Registration complete. Welcome!")
                return redirect("/dash")
            except Exception as e:
                messages.error(request, "Error creating user. Please try again.")
                return redirect("/")
        else:
            messages.error(request, "Invalid 2FA code. Please try again.")

    return render(request, "FA.html")



