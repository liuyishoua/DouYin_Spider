"""Allowlisted send diagnostics: never retain response strings or credentials."""
import json
from google.protobuf.empty_pb2 import Empty
from google.protobuf.unknown_fields import UnknownFieldSet
from google.protobuf.message import DecodeError


class SendUncertain(RuntimeError):
    def __init__(self, diagnostic):
        self.diagnostic = diagnostic
        super().__init__('发送结果未确认')


def exception_diagnostic(exc):
    from curl_cffi.requests.exceptions import RequestException, Timeout
    from google.protobuf.message import DecodeError
    reason = 'internal_error'
    if isinstance(exc, (TimeoutError, Timeout)):
        reason = 'network_timeout'
    elif isinstance(exc, (ConnectionError, RequestException)):
        reason = 'network_error'
    elif isinstance(exc, DecodeError):
        reason = 'protobuf_decode_error'
    return {'reason': reason, 'exception_type': type(exc).__name__}


def response_diagnostic(response):
    unknown = []
    def visit(message, prefix=''):
        for field in UnknownFieldSet(message):
            unknown.append({'path': prefix + str(field.field_number), 'wire_type': field.wire_type})
        for descriptor, value in message.ListFields():
            if descriptor.message_type:
                children = value if descriptor.is_repeated else [value]
                for child in children:
                    visit(child, prefix + str(descriptor.number) + '.')
    visit(response)
    # Decode the send envelope independently: legacy Response.proto has the
    # wrong wire type for field 3 and omits ResponseBody.send_message_body=100.
    # Field names match the IM SDK; field numbers are backed by local captures.
    codes = {}
    send = {}
    def wire_codes(data, prefix=''):
        for field in UnknownFieldSet(Empty.FromString(data)):
            path = prefix + str(field.field_number)
            if field.wire_type == 0 and path in ('3', '6.100.3', '6.100.5'):
                codes[path] = field.data
            elif field.wire_type == 0 and path == '6.100.1':
                send['server_message_id'] = str(field.data)
            elif field.wire_type == 2 and path == '6.100.6':
                try:
                    detail = json.loads(field.data)
                    code = detail.get('status_code') if isinstance(detail, dict) else None
                    if type(code) is int:
                        send['business_code'] = code
                except (ValueError, UnicodeError):
                    pass
            elif field.wire_type == 2 and path in ('6', '6.100'):
                wire_codes(field.data, path + '.')
    unreadable = False
    try:
        wire_codes(response.SerializeToString())
    except DecodeError:
        unreadable = True
    result = {'message_ok': response.message == 'OK', 'has_error_desc': bool(response.error_desc),
              'unknown_fields': unknown, 'wire_codes': codes, 'wire_codes_unreadable': unreadable,
              **send}
    result['outer_status'] = codes.get('3')
    result['send_status'] = codes.get('6.100.3')
    result['check_code'] = codes.get('6.100.5')
    code = send.get('business_code')
    statuses = [result[k] for k in ('outer_status', 'send_status', 'check_code')]
    if code == 7180:
        reason = 'rate_limited'
    elif any(s is not None and s != 0 for s in statuses) or not result['message_ok'] or result['has_error_desc']:
        reason = 'platform_rejected'
    elif code == 8101:
        reason = 'business_anomaly'
    elif code is not None and code != 0:
        reason = 'platform_rejected'
    elif not unreadable and statuses == [0, 0, 0] and code == 0 and int(send.get('server_message_id', '0')) > 0:
        reason = 'interface_accepted'
    else:
        reason = 'incomplete_response'
    result['reason'] = reason
    return result
