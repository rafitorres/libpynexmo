#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2013 Marco Londero <marco.londero@linux.it>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

import urllib
import urllib2
import urlparse
import json


class NexmoException(Exception):
    pass


class NexmoRequest(object):
    reqtypes = [
        'json',
        'xml'
    ]

    def __init__(self, api_key, api_secret, request_type, *args, **kwargs):
        if request_type not in self.reqtypes:
            raise NexmoException("Unknown request type.")

        self.api_key = api_key
        self.api_secret = api_secret
        self.request_type = request_type

    @property
    def filtered_params(self):
        return {k:v for (k,v) in self.params.items() if v is not None}

    def build_request(self):
        raise NotImplementedError

    def check_request(self):
        # mandatory parameters for all requests
        if not getattr(self, 'api_key', None) or not getattr(self, 'api_secret', None):
            raise NexmoException("API key or secret not set")

    def send_request(self):
        if not self.build_request():
            return False
        if self.request_type == 'json':
            return self.send_request_json()
        elif self.request_type == 'xml':
            return self.send_request_xml()

    def send_request_json(self):
        url = self.request
        req = urllib2.Request(url=url)
        req.add_header('Accept', 'application/json')
        try:
            return json.load(urllib2.urlopen(req))
        except ValueError:
            return False

    def send_request_xml(self):
        return "XML request not implemented yet."


class Nexmo2FA(NexmoRequest):
    def __init__(self, api_key, api_secret, to_number, pin, request_type, *args, **kwargs):
        super(Nexmo2FA, self).__init__(api_key, api_secret, request_type, *args, **kwargs)
        self.to_number = to_number
        self.pin = pin

    def build_request(self):
        self.check_request()

        server = "%s/sc/us/2fa/%s" % (self.server_url, self.request_type)
        self.params = {
                    'api_key': self.api_key,
                    'api_secret': self.api_secret,
                    'to': self.to_number,
                    'pin': self.pin
        }
        self.request = server + "?" + urllib.urlencode(self.filtered_params)
        return self.request


class NexmoMessage(NexmoRequest):
    smstypes = [
        'text',
        'binary',
        'wappush',
        'vcal',
        'vcard',
        'unicode'
    ]
    apireqs = [
        'balance',
        'pricing',
        'numbers'
    ]
    server_url = "https://rest.nexmo.com"

    def __init__(self, api_key, api_secret, from_number, to_number, request_type, text, *args, **kwargs):
        super(NexmoMessage, self).__init__(api_key, api_secret, request_type)
        self.from_number = from_number
        self.to_number = to_number
        self.set_text_info(text)

    def build_request(self):
        self.check_request()

        # check SMS logic
        if not self.check_sms():
            return False
        elif self.sms_type in self.apireqs:
            # developer API
            # balance
            if self.sms_type == 'balance':
                self.request = "%s/account/get-balance/%s/%s" \
                    % (self.server_url, self.api_key, self.api_secret)
            # pricing
            elif self.sms_type == 'pricing':
                self.request = "%s/account/get-pricing/outbound/%s/%s/%s" \
                    % (self.server_url, self.api_key,
                       self.api_secret, self.country)
            # numbers
            elif self.sms_type == 'numbers':
                self.request = "%s/account/numbers/%s/%s" \
                    % (self.server_url, self.api_key, self.api_secret)
            return self.request
        else:
            # standard requests
            server = "%s/sms/%s" % (self.server_url, self.request_type)
            self.params = {
                'api_key': self.api_key,
                'api_secret': self.api_secret,
                'from': self.from_number,
                'to': self.to_number,
                'type': self.sms_type,
                'text': self.text
            }
            self.request = server + "?" + urllib.urlencode(self.filtered_params)
            return self.request

    def check_sms(self):
        # API requests handling
        if self.sms_type in self.apireqs:
            if self.sms_type == 'balance' or sms_type == 'numbers':
                return True
            elif self.sms_type == 'pricing' and \
                not getattr(self, 'country', None):
                raise NexmoException("Pricing needs country")
            return True
        # SMS logic, check Nexmo doc for details
        elif self.sms_type not in self.smstypes:
            raise NexmoException("Unknown type")
        elif self.sms_type == 'text' and not self.text:
            raise NexmoException("text missing")
        elif self.sms_type == 'binary' and \
            (not getattr(self, 'body', None) or
                not getattr(self, 'udh', None)):
            raise NexmoException("Binary payload missing")
        elif self.sms_type == 'wappush' and \
            (not getattr(self, 'title', None) or
            not getattr(self, 'url', None)):
            raise NexmoException("Title or URL missing")
        elif self.sms_type == 'vcal' and not getattr(self, 'vcal', None):
            raise NexmoException("vCal data missing")
        elif self.sms_type == 'vcard' and not getattr(self, 'vcard', None):
            raise NexmoException("vCard data missing")
        elif not getattr(self, 'from_number', None) or not getattr(self, 'to_number', None):
            raise NexmoException("From or to missing")
        return True

    def get_details(self):
        return self.__dict__

    def set_bin_info(self, body, udh):
        # automatically transforms msg to binary SMS
        self.sms_type = 'binary'
        self.body = body
        self.udh = udh

    def set_text_info(self, text):
        # automatically transforms msg to text SMS
        self.sms_type = 'text'
        # if message have unicode symbols send as unicode
        try:
            text.decode('ascii')
        except:
            self.sms_type = 'unicode'
            if isinstance(text, unicode):
                text = text.encode('utf8')
        self.text = text

    def set_vcal_info(self, vcal):
        # automatically transforms msg to vcal SMS
        self.sms_type = 'vcal'
        self.vcal = vcal

    def set_vcard_info(self, vcard):
        # automatically transforms msg to vcard SMS
        self.sms_type = 'vcard'
        self.vcard = vcard

    def set_wappush_info(self, title, url, validity=False):
        # automatically transforms msg to wappush SMS
        self.sms_type = 'wappush'
        self.title = title
        self.url = url
        self.validity = validity

class NexmoVerificationRequest(NexmoRequest):
    server_url = "https://api.nexmo.com"

    def __init__(self, api_key, api_secret, request_type, number, *args, **kwargs):
        super(NexmoVerificationRequest, self).__init__(api_key, api_secret, request_type, *args, **kwargs)
        self.number = number
        self.sender_id = kwargs.get('sender_id')
        self.brand = kwargs.get('brand')
        self.code_length = kwargs.get('code_length')
        self.lg = kwargs.get('lg')

    def build_request(self):
        self.check_request()

        server = "%s/verify/%s" % (self.server_url, self.request_type)
        self.params = {
            'api_key': self.api_key,
            'api_secret': self.api_secret,
            'number': self.number,
            'sender_id': self.sender_id,
            'brand': self.brand,
            'code_length': self.code_length,
            'lg': self.lg
        }
        self.request = server + "?" + urllib.urlencode(self.filtered_params)
        return self.request


class NexmoVerificationCheckRequest(NexmoRequest):
    server_url = "https://api.nexmo.com"

    def __init__(self, api_key, api_secret, request_type, request_id, code, *args, **kwargs):
        super(NexmoVerificationCheckRequest, self).__init__(api_key, api_secret, request_type, *args, **kwargs)
        self.request_id = request_id
        self.code = code
        self.ip = kwargs.get('ip')

    def build_request(self):
        self.check_request()

        server = "%s/verify/check/%s" % (self.server_url, self.request_type)
        self.params = {
            'api_key': self.api_key,
            'api_secret': self.api_secret,
            'request_id': self.request_id,
            'code': self.code,
            'ip': self.ip
        }
        self.request = server + "?" + urllib.urlencode(self.filtered_params)
        return self.request
