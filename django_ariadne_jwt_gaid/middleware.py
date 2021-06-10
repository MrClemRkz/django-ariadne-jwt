"""ariadne_django_jwt middleware module"""
from django.contrib.auth import authenticate
from django.contrib.auth.models import AnonymousUser
from .utils import get_token_from_http_header
import logging

__all__ = ["JSONWebTokenMiddleware"]

logger = logging.getLogger(__name__)

class JSONWebTokenMiddleware(object):
    """Middleware to be used in conjuction with ariadne grapqh_* methods"""

    def resolve(self, next, root, info, **kwargs):
      """Performs the middleware relevant operations"""
      request = info.context["request"]

      token = get_token_from_http_header(request)
      if token is not None:
          # user = info.context["user"]
          user = request.user
          logging.debug(f'User:{user}')
          logging.debug(f'Request:{request}')
          logging.debug(f'context: {info.context}')

          if user is None or isinstance(user, AnonymousUser):
              user = authenticate(request=request, token=token)

          if user is not None:
              info.context["user"] = user
              info.context["request"].user = user

      return next(root, info, **kwargs)