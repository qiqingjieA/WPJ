

from django.conf.urls.defaults import *



from HelloW.view import hello

urlpatterns = patterns('',
	(r'^hello/$', hello),
)




















