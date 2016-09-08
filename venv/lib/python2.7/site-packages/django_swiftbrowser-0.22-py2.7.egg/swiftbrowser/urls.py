from django.conf.urls import patterns, url
from swiftbrowser.views import containerview, objectview, download_dec,\
    download_enc, delete_object, login, tempurl, upload, create_pseudofolder,\
    create_container, delete_container, public_objectview, toggle_public,\
    edit_acl, put_object

urlpatterns = patterns(
    'swiftbrowser.views',
    url(r'^login/$', login, name="login"),
    url(r'^$', containerview, name="containerview"),
    url(r'^public/(?P<account>.+?)/(?P<container>.+?)/(?P<prefix>(.+)+)?$',
        public_objectview, name="public_objectview"),
    url(r'^toggle_public/(?P<container>.+?)/$', toggle_public,
        name="toggle_public"),
    url(r'^tempurl/(?P<container>.+?)/(?P<objectname>.+?)$', tempurl,
        name="tempurl"),
    url(r'^upload/(?P<container>.+?)/(?P<prefix>.+)?$', upload, name="upload"),
    url(r'^put_object/(?P<container>.+?)/(?P<prefix>.+)?$', put_object, name="put_object"),
    url(r'^create_pseudofolder/(?P<container>.+?)/(?P<prefix>.+)?$',
        create_pseudofolder, name="create_pseudofolder"),
    url(r'^create_container$', create_container, name="create_container"),
    url(r'^delete_container/(?P<container>.+?)$', delete_container,
        name="delete_container"),
    url(r'^download_enc/(?P<container>.+?)/(?P<objectname>.+?)$', download_enc,
        name="download_enc"),
    url(r'^download_dec/(?P<container>.+?)/(?P<objectname>.+?)$', download_dec,
        name="download_dec"),
    url(r'^delete/(?P<container>.+?)/(?P<objectname>.+?)$', delete_object,
        name="delete_object"),
    url(r'^objects/(?P<container>.+?)/(?P<prefix>(.+)+)?$', objectview,
        name="objectview"),
    url(r'^acls/(?P<container>.+?)/$', edit_acl, name="edit_acl"),
)
