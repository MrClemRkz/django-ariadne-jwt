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
          user = getattr(info.context, "user", None)

          if user is None or isinstance(user, AnonymousUser):
              user = authenticate(request=request, token=token)
              logger.debug(f'User is now: {user}')

          if user is not None:
              info.context["user"] = user
              info.context.request.user = user
              logger.debug(f'Info context user: {info.context["user"]}')

      return next(root, info, **kwargs)