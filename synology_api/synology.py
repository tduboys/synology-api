#!/usr/bin/python3

import functools
import json
import logging
import pprint

import requests

LOG = logging.getLogger("synology-api")

"""
This is used by the api_call function to mark methods which need to be
modified at class creation.
"""


class _api_deco:
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.decorate = True
        self.deco_args = args
        self.deco_kwargs = kwargs
        functools.update_wrapper(self, self.func)

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)


"""
Decorator function marking methods as calls to the synology api. Meant for use
with methods in classes which inherit from the Synology class. Needed as a
function separate from _api_deco so that arguments can be added as attributes
to methods of Synology's child classes. These attributes are then passed to
Synology.api_call as arguments.

api_call should only be used to decorate methods of classes who inherit from
the Synology class. It is defined outside of the Synology class so that is not
limited to the scope of a class method, which would be the case otherwise.
"""


def api_call(*args, **kwargs):
    def deco_func(func):
        return _api_deco(func, *args, **kwargs)

    return deco_func


class Synology:
    class AlreadyLoggedInError(ConnectionRefusedError):
        pass

    class NotLoggedInError(PermissionError):
        pass

    class LoginError(Exception):
        pass

    # These attributes must be defined here so that they can be accessed
    # from class methods (specifically, _add_api_method).
    app_api_dict = {}
    full_api_dict = {}
    sid = None

    def __init__(self):
        pass

    @classmethod  # decorator redundant, added for clarity
    def __init_subclass__(cls, *args, **kwargs):
        super().__init_subclass__(*args, **kwargs)
        for attrname in dir(cls):
            attr = getattr(cls, attrname)
            if "decorate" in dir(attr):
                if attr.decorate:
                    cls._add_api_method(attr, *attr.deco_args, **attr.deco_kwargs)

    """
    method: app
    raises: NotImplementedError
    This method is a placeholder to be overridden in classes that inherit
    the 'Synology' class. In those classes it should return a string with the
    name of the class's associated application. Here it will raise a
    NotImplementedError.
    """

    @property
    def app(self):
        raise NotImplementedError("Application undefined.")

    @classmethod
    def login(
        cls, user, passwd, ipaddr=None, port=5000, base_url="http://127.0.0.1:5000",
    ):
        if ipaddr:
            cls.base_url = "http://{ip}:{p}/".format(ip=ipaddr, p=port)
        elif base_url.endswith("/"):
            cls.base_url = base_url
        else:
            cls.base_url = "{bu}/".format(bu=base_url)
        """
        Factory class method
        """
        params = {
            "api": "SYNO.API.Auth",
            "version": "2",
            "method": "login",
            "account": user,
            "passwd": passwd,
            "session": cls.app,
            "format": "sid",
        }
        cls.url = "{bu}webapi".format(bu=cls.base_url)
        print(params)
        try:
            session = requests.get("{url}/auth.cgi".format(url=cls.url), params=params)
            if session.status_code >= 300:
                raise Synology.LoginError(
                    "Request for login returned wrong status : {}".format(
                        session.status_code
                    )
                )
            jsession = session.json()
            cls.sid = None
            if not jsession.get("success"):
                raise Synology.LoginError(
                    "Login session did not return success : {}".format(
                        json.dumps(jsession)
                    )
                )

            if jsession.get("data"):
                cls.sid = jsession.get("data").get("sid")

            if not cls.sid:
                raise Synology.LoginError("Unable to get Session ID from login page")

        except (json.decoder.JSONDecodeError) as ex:
            raise Synology.LoginError(
                "Error during decoding login json response : {e}".format(e=repr(ex))
            )
        except (requests.ConnectionError, requests.HTTPError) as ex:
            raise Synology.LoginError(
                "Error during login request : {e}".format(e=repr(ex))
            )
        except (KeyError, ValueError) as ex:
            raise Synology.LoginError(
                "Error during parsing login response : {e}".format(e=repr(ex))
            )

        cls.session_expire = False
        return cls()

    def logout(self):
        params = {
            "api": "SYNO.API.Auth",
            "version": "2",
            "method": "logout",
            "session": self.app,
        }

        response = requests.get("{url}/auth.cgi".format(url=self.url), params=params)
        self.session_expire = True
        self.sid = None
        respjson = response.json()
        if "success" in respjson.keys():
            return respjson["success"]
        else:
            raise KeyError("No 'success' field in response.")

    def populate_api_dict(self, app=None):
        querydict = {"version": "1", "method": "query", "query": "all"}

        response = requests.get(self.url + "/query.cgi?api=SYNO.API.Info", querydict)

        self.full_api_dict = response.json()["data"]
        if self.app is not None:
            for key in self.full_api_dict:
                if app.lower() in key.lower():
                    self.app_api_dict[key] = self.full_api_dict[key]
        else:
            self.app_api_dict = self.full_api_dict

    def json_response(self):
        if self.full_api_dict is {}:
            self.populate_api_dict(None)

        for key in self.full_api_dict.keys():
            for subkey in self.full_api_dict[key].keys():
                if self.full_api_dict[key][subkey] == "JSON":
                    return self.full_api_dict[key]

    def search_by_app(self, app):
        data = []
        check = 0
        for key in self.full_api_dict:
            if app.lower() in key.lower():
                data.append(key)
        return data

    def api_request(self, api_name: str, api_method: str, param=None):
        """
        api_request acta as a factory for constructing request data objects.
        It is intended to be called as the return value of methods decorated
        by 'Synology.api_call'.
        
        Args:
            api_name (str): Which API to use.
            api_method (str): Which method of the API to use.
            param: Defaults to None. If provided, should be a dict containing
                   any of the api method's parameters.

        Returns:
            api_request: a request data object
        """
        r = {"app": self.app(), "api_name": api_name, "api_method": api_method}
        if param is not None:
            r.update(param)
        return r

    @classmethod
    def _add_api_method(cls, func, method="get", response_json=True):
        setattr(func, "method", method)
        setattr(func, "response_json", response_json)
        """
        _add_api_method is used to call the methods of various API's provided
        by DSM. It is intended to be used by methods decorated by the
        'api_call' function (see above) that are members of classes which
        inherit from the Synology class.

        Methods decorated by api_call should return a call to
        'Synology.api_request', which acts as a factory for the request data
        object. Classes which inherit the Synology class will of course call
        'self.api_request' instead, but note that the decoration for the method
        will remain 'Synology.api_call'.

        Arg:
            method (str or None): 'post' or 'get', defaults to None. If None,
                                  or if not 'post' or 'get', use 'get'.
            response_json (bool): Defaults to True. Determines Whether the
                                  response should be in json format.

        Returns:
            api_call: a decorator function (which returns a wrapper function).
        """

        @functools.wraps(func)
        def wrap_api_method(self, *args, **kwargs):
            method = func.method
            response_json = func.response_json
            reqdata = func(self, *args, **kwargs)
            api_str = "SYNO.{a}.{m}".format(a=reqdata["app"], m=reqdata["api_name"])
            api_data = cls.app_api_dict[api_str]
            api_path = api_data["path"]
            req_param = {
                "version": api_data["maxVersion"],
                "method": reqdata["api_method"],
            }  # http method, not api
            if method not in ["post", "get"]:
                method = "get"

            # synology expects strings "true" and "false" for bools
            for k, v in req_param.items():
                if isinstance(v, bool):
                    req_param[k] = str(v).lower()

            req_param["_sid"] = cls.sid

            response = None
            requrl = "{u}/{p}?api={s}".format(u=self.url, p=api_path, s=api_str,)

            if method == "get":
                response = requests.get(requrl, req_param)
            else:
                response = requests.post(requrl, req_param)

            if response_json:
                return response.json()
            else:
                return response

        setattr(cls, func.__name__, wrap_api_method)
