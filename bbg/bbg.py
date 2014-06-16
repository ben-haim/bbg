# -*- coding: utf-8 -*-
"""
Created on Wed Jun 04 17:44:27 2014

@author: Brian Jacobowski <bjacobowski.dev@gmail.com>
"""

import time
import collections
import blpapi as bb
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import datetime as dt
from optparse import OptionParser
from functools import wraps
from contextlib import contextmanager

pd.options.display.mpl_style = 'default'

TODAY = dt.date.today()
UUID = 12126269

BBG_PRODUCT_TYPES = ['GOVT', 'CORP', 'MTGE', 'M-MKT', 'MUNI', 'PFD',
                     'EQUITY', 'CMDTY', 'INDEX', 'CURNCY']

SVC_REF =  '//blp/refdata'
SVC_MKT =  '//blp/mktdata'
SVC_VWAP = '//blp/mktvwap'
SVC_BAR =  '//blp/mktbar'
SVC_FLDS = '//blp/apiflds'
SVC_PAGE = '//blp/pagedata'
SVC_TECH = '//blp/tasvc'
SVC_AUTH = '//blp/apiauth'

REQ_REF_HIST =   'HistoricalDataRequest'
REQ_REF_DATA =   'ReferenceDataRequest'
REQ_FLD_INFO =   'FieldInfoRequest'
REQ_FLD_SRCH =   'FieldSearchRequest'
REQ_FLD_CAT =    'CategorizedFieldSearchRequest'
REQ_AUTH =       'AuthorizationRequest'
REQ_AUTH_LOGON = 'LogonStatusRequest'

RESP_REF_HIST = bb.Name('HistoricalDataResponse')
RESP_REF_DATA = bb.Name('ReferenceDataResponse')
RESP_FLD =      bb.Name('FieldResponse')
RESP_FLD_CAT =  bb.Name('CategorizedFieldResponse')
RESP_AUTH =     bb.Name('AuthorizationResponse')
RESP_LOGON =    bb.Name('LogonStatusResponse')

EL_REF_SEC_DATA = 'ReferenceSecurityData'
EL_REF_FLD_DATA = 'ReferenceFieldData'
EL_REF_HIST_TBL = 'HistoricalDataTable'
EL_REF_HIST_ROW = 'HistoricalDataRow'

NM_SEC_DATA =           bb.Name('securityData')
NM_SEC =                bb.Name('security')
NM_SECS =               bb.Name('securities')
NM_FLDS =               bb.Name('fields')
NM_EIDS =               bb.Name('returnEids')
NM_RTN_FMT =            bb.Name('returnFormattedValue')
NM_ST_DT =              bb.Name('startDate')
NM_END_DT =             bb.Name('endDate')
NM_PER_ADJ =            bb.Name('periodicityAdjustment')
NM_PER_SEL =            bb.Name('periodicitySelection')
NM_CUR =                bb.Name('currency')
NM_OVD =                bb.Name('override')
NM_OVDS =               bb.Name('overrides')
NM_OVD_OPT =            bb.Name('overrideOption')
NM_PX_OPT =             bb.Name('pricingOption')
NM_NON_TRD_DY_OPT =     bb.Name('nonTradingDayFillOption')
NM_NON_TRD_DY_FILL =    bb.Name('nonTradingDayFillMethod')
NM_MAX_DATA =           bb.Name('maxDataPoints')
NM_REL_DT =             bb.Name('returnRelativeDate')
NM_ADJ_NORM =           bb.Name('adjustmentNormal')
NM_ADJ_ABNORM =         bb.Name('adjustmentAbnormal')
NM_ADJ_SPLIT =          bb.Name('adjustmentSplit')
NM_ADJ_FOLLOW =         bb.Name('adjustmentFollowDPDF')
NM_CAL_OVD =            bb.Name('calendarCodeOverride')
NM_CAL_OVDS_INFO =      bb.Name('calendarOverridesInfo')
NM_CAL_OVDS =           bb.Name('calendarOverrides')
NM_CAL_OVDS_OP =        bb.Name('calendarOverridesOperation')
NM_SEQ =                bb.Name('sequenceNumber')
NM_FLD_DATA =           bb.Name('fieldData')
NM_FLD_ID =             bb.Name('fieldId')
NM_FLD_INFO =           bb.Name('fieldInfo')
NM_FLD_OVD =            bb.Name('FieldOverride')
NM_REL_DT =             bb.Name('relativeDate')
NM_VAL =                bb.Name('value')
NM_ID =                 bb.Name('id')
NM_MNEMONIC =           bb.Name('mnemonic')
NM_DATA_TP =            bb.Name('datatype')
NM_CAT_NM =             bb.Name('categoryName')
NM_DESC =               bb.Name('description')
NM_DOC =                bb.Name('documentation')
NM_PPTY =               bb.Name('property')
NM_SRC =                bb.Name('source')
NM_MSG =                bb.Name('message')
NM_CODE =               bb.Name('code')
NM_CAT =                bb.Name('category')
NM_SUBCAT =             bb.Name('Subcategory')
NM_UUID =               bb.Name('uuid')
NM_IP_ADDRESS =         bb.Name('ipAddress')
NM_AUTH_SUCCUESS =      bb.Name('AuthorizationSuccess')

NM_ERR_RESP =           bb.Name('responseError')
NM_ERR_FLDSRCH =        bb.Name('fieldSearchError')
NM_ERR_SEC =            bb.Name('securityError')
NM_ERR_FLD =            bb.Name('fieldError')
NM_EXC_FLD =            bb.Name('fieldException')
NM_INFO_ERR =           bb.Name("errorInfo")
NM_FAIL_AUTH =          bb.Name('AuthorizationFailure')
NM_REASON =             bb.Name('reason')

FUNC_CONT_NM = {
    RESP_REF_DATA: NM_SEC_DATA,
    NM_SEC_DATA:   NM_FLD_DATA,
    NM_EXC_FLD:    NM_INFO_ERR,
    RESP_REF_HIST: NM_SEC_DATA
}

ELEMENT_DATATYPE_NAMES = {
    bb.DataType.BOOL:           "BOOL",
    bb.DataType.CHAR:           "CHAR",
    bb.DataType.BYTE:           "BYTE",
    bb.DataType.INT32:          "INT32",
    bb.DataType.INT64:          "INT64",
    bb.DataType.FLOAT32:        "FLOAT32",
    bb.DataType.FLOAT64:        "FLOAT64",
    bb.DataType.STRING:         "STRING",
    bb.DataType.BYTEARRAY:      "BYTEARRAY",
    bb.DataType.DATE:           "DATE",
    bb.DataType.TIME:           "TIME",
    bb.DataType.DECIMAL:        "DECIMAL",
    bb.DataType.DATETIME:       "DATETIME",
    bb.DataType.ENUMERATION:    "ENUMERATION",
    bb.DataType.SEQUENCE:       "SEQUENCE",
    bb.DataType.CHOICE:         "CHOICE",
    bb.DataType.CORRELATION_ID: "CORRELATION_ID"
}

OvdNamedTuple = collections.namedtuple('override', 'fieldId value')

BBG_FORMAT_DT_OP = '%m/%d/%Y'

def _bbg_dt_op(dt_str):
    """convert bb date string to datetime.date object"""
    if isinstance(dt_str, (dt.date, dt.datetime)):
        rtn = dt_str
    elif isinstance(dt_str, str):
        rtn = dt.datetime.strptime(dt_str, BBG_FORMAT_DT_OP).date()
    else:
        rtn = None
    return rtn


BBG_FORMAT_DT_IP = '%Y%m%d'

def _bbg_dt_ip(dt_date):
    """convert datetime.date object to bb date string"""
    if isinstance(dt_date, (dt.date, dt.datetime)):
        rtn = dt.datetime.strftime(dt_date, BBG_FORMAT_DT_IP)
    elif isinstance(dt_date, str):
        rtn = dt_date
    else:
        rtn = None
    return rtn


FUNC_STR_TO_VAL = {
    'BOOL':      bool,
    'DATE':      _bbg_dt_op,
    'DT':        _bbg_dt_op,
    'FLOAT':     float,
    'FLOAT32':   float,
    'FLOAT64':   float,
    'VALUE':     float,
    'INTEREST':  float,
    'PRINCIPAL': float,
    'PRICE':     float,
    'PX':        float,
    'BALANCE':   float,
    'BYTE':      int,
    'INT32':     int,
    'INT64':     long,
    'PERIOD':    int,
    'NUMBER':    int,
    'CHAR':      str,
    'STR':       str,
    'STRING':    str,
    'TEXT':      str,
    'DESC':      str,
    'DOC':       str
}

def _memo(func):
    """decorator to memoize a function"""
    cache = {}
    @wraps(func)
    def wrap(*args, **kw):
        "session is removed as it isn't relevant to response"
        try:
            key = tuple(args)
            if len(kw) > 0:
                temp = kw.copy()
                temp.pop('session', None)
                key += tuple(temp)
            return cache[key]
        except TypeError:
            return func(*args, **kw)
        except KeyError:
            rtn = cache[key] = func(*args, **kw)
            return rtn
    return wrap


@contextmanager
def _ignored(*exceptions):
    """decorator to ignore errors for a function"""
    try:
        yield
    except exceptions:
        pass


def _get_ip_address():
    """get computer's ip address"""
    import socket
    return socket.gethostbyname(socket.gethostname())


class _Timer(object):
    """decorator to time a function using 'with _Timer() as var:'"""
    def __init__(self):
        self.start = None
        self.end = None
        self.interval = None

    def __enter__(self):
        self.start = time.clock()
        return self

    def __exit__(self, etype, value, traceback):
        self.end = time.clock()
        self.interval = self.end - self.start

    def __str__(self):
        minute, second = divmod(self.interval, 60)
        hour, minute = divmod(minute, 60)
        return '{:.0f}:{:02.0f}:{:05.2f}'.format(hour, minute, second)


class _Error(Exception):
    """Base class for module exceptions"""
    def __init__(self, msg=''):
        super(_Error, self).__init__(msg)


class _bbgError(_Error):
    """generic bloomberg error"""
    pass

class _IOError(_Error):
    pass

class _elementError(_Error):
    """Base bloomberg element error"""
    def __init__(self, errElement):
        super(self.__class__, self).__init__()
        self.source = errElement.getElementValue(NM_SRC)
        self.code = errElement.getElementValue(NM_CODE)
        self.category = errElement.getElementValue(NM_CAT)
        self.message = errElement.getElementValue(NM_MSG)
        if errElement.hasElement(NM_SUBCAT):
            self.subcategory = errElement.getElementValue(NM_SUBCAT)

    def __str__(self):
        return ('{0}: {1}({2})'.format(self.__class__.__name__,
                self.message, self.code))


class _errorContainer(_Error):
    """Base container for errors potentially containing multiple errors"""
    def __init__(self, errCont, errType=None):
        super(self.__class__, self).__init__()
        self.errors = []
        if errType is None:
            errType = _elementError

        if errCont.isArray():
            for err in errCont.elements():
                self.errors.append(errType(err))
        else:
            self.errors.append(errType(errCont))

    def __str__(self):
        return '\n'.join([str(e) for e in self.errors])


class InputError(_Error):
    pass

class ResponseError(_elementError):
    pass

class FieldSearchError(_elementError):
    pass

class SecurityError(_elementError):
    pass

class SecurityErrors(_errorContainer):
    def __init__(self, errCont):
        super(self.__class__, self).__init__(errCont, SecurityError)


class FieldError(_elementError):
    pass

class FieldException(_elementError):
    """Bloomberg fieldException"""
    def __init__(self, errElement):
        super(self.__class__, self).__init__(
              errElement.getElement(NM_INFO_ERR))
        self.fieldId = errElement.getElementValue(NM_FLD_ID)
        self.field_msg = errElement.getElementValue(NM_MSG)

    def __str__(self):
        return ('{0}: {1}\n{2}: {3}'.format(self.fieldId, self.field_msg,
                self.source, self.message))


class FieldExceptions(_errorContainer):
    """container for multiple fieldExceptions"""
    def __init__(self, errCont):
        super(self.__class__, self).__init__(errCont, FieldException)


ExceptNotFound = bb.exception.NotFoundException
ExceptIxOutOfRng = bb.exception.IndexOutOfRangeException
ExceptInvArg = bb.exception.InvalidArgumentException

def _parse_cmd_line():
    """adds options to the command line option parser"""
    parser = OptionParser()

    parser.add_option("-a",
                      "--ip",
                      dest="host",
                      help="server name or IP (default: %default)",
                      metavar="ipAddress",
                      default="localhost")
    parser.add_option("-p",
                      dest="port",
                      type="int",
                      help="server port (default: %default)",
                      metavar="tcpPort",
                      default=8194)

    options, __ = parser.parse_args()
    return options

class _SessionOptions(bb.SessionOptions):
    """
    set bloomberg session options
    """
    def __init__(self):
        self.options = _parse_cmd_line()
        super(self.__class__, self).__init__()
        self.setServerHost(self.options.host)
        self.setServerPort(self.options.port)

SESSION_OPTIONS = _SessionOptions()

class Session(bb.Session):
    """sub-class adding functionality to bb.Session"""
    def __init__(self, eventHandler=None, eventDispatcher=None):
        super(self.__class__, self).__init__(SESSION_OPTIONS,
              eventHandler, eventDispatcher)
        self.event_handler = eventHandler
        self.correlation_ids = {}
        self.subscription_list = bb.SubscriptionList()

        try:
            if eventHandler is None:
                session_started = bb.Session.start(self)
            else:
                session_started = bb.Session.startAsync(self)
            if not session_started:
                raise _bbgError("Can't start session.")
            print 'Session started...'
        except _bbgError as err:
            print err


    def getService(self, service_name):
        """overrides the bb function to open/get service in one step"""
        try:
            rtn = super(self.__class__, self).getService(service_name)
        except ExceptNotFound as err:
            try:
                rtn = None
                if not self.openService(service_name):
                    raise _bbgError("Failed to open {0}".format(service_name))
                rtn = bb.Session.getService(self, service_name)
            except (_bbgError, ExceptNotFound) as err:
                print err
        return rtn


    def __enter__(self):
        """pass"""
        return self


    def __exit__(self, etype, value, traceback):
        """pass"""
        try:
            if not self.subscription_list is None:
                with _ignored(Exception):
                    self.unsubscribe(self.subscription_list)
            if self.event_handler is None:
                with _ignored(Exception):
                    self.stop()
            else:
                with _ignored(Exception):
                    self.stopAsync()
        finally:
            pass


def _session_decorator(func):
    """start a session if one hasn't been started yet"""
    @wraps(func)
    def wrap(*args, **kwargs):
        """wrapped"""
        if kwargs['session'] is None:
            with Session() as session:
                kwargs['session'] = session
                rtn = func(*args, **kwargs)
        else:
            rtn = func(*args, **kwargs)
        return rtn
    return wrap


def _proc_events(session):
    """first step in receiving a response from bb"""
    rtn = {}
    while True:
        event = session.nextEvent(500)
        data = FUNC_EVENT[event.eventType()](event)
#        _proc_print_basic(event)
        if not data is None:
            rtn.update(data)
        if event.eventType() == bb.Event.RESPONSE:
            break
    return rtn


def _proc_events_admin(event):
    """process bb admin event"""
    pass

def _proc_events_status(event):
    """process bb status event"""
    pass

def _proc_events_resp(event):
    """process bb response/partial response event"""
    rtn = {}
    for msg in event:
        try:
            rtn.update(_proc_message(msg))
        except ResponseError as err:
            print err
    return rtn


def _proc_events_sub_data(event):
    """process bb subscription event"""
    pass

def _proc_events_timeout(event):
    """process bb timeout event"""
    pass

def _proc_events_pass(event):
    """process to pass on bb event"""
    pass

def _proc_print_basic(event):
    """debugging process to print out an event"""
    try:
        for msg in event:
            print msg
    finally:
        pass


FUNC_EVENT = {
    bb.Event.ADMIN: _proc_events_admin,
    bb.Event.SESSION_STATUS: _proc_events_status,
    bb.Event.SUBSCRIPTION_STATUS: _proc_events_status,
    bb.Event.REQUEST_STATUS: _proc_events_status,
    bb.Event.RESPONSE: _proc_events_resp,
    bb.Event.PARTIAL_RESPONSE: _proc_events_resp,
    bb.Event.SUBSCRIPTION_DATA: _proc_events_sub_data,
    bb.Event.SERVICE_STATUS: _proc_events_status,
    bb.Event.TIMEOUT: _proc_events_timeout,
    bb.Event.AUTHORIZATION_STATUS: _proc_events_status,
    bb.Event.RESOLUTION_STATUS: _proc_events_status,
    bb.Event.TOPIC_STATUS: _proc_events_status,
    bb.Event.TOKEN_STATUS: _proc_events_status,
    bb.Event.REQUEST: _proc_events_pass,
    bb.Event.UNKNOWN: _proc_events_pass,
    'print': _proc_print_basic
}

def _proc_message(message):
    """process bb message"""
    return FUNC_RESPONSE[message.messageType()](message)


#def _proc_msg_ref_hist(message):
#    pass

def _proc_msg_ref(message):
    """process bb refdata message"""
    rtn = collections.defaultdict(dict)

    if message.hasElement(NM_ERR_RESP):
        raise ResponseError(message.getElement(NM_ERR_RESP))
    try:
        m_def = message.asElement().elementDefinition()
#        print m_def
        msg_type = message.messageType()
#        sec_data = message.getElement(NM_SEC_DATA)
#            sec_def = sec_data.elementDefinition()
#            print sec_def.name(), sec_def.alternateNames()
        if msg_type == RESP_REF_DATA:
            for sec in message.getElement(NM_SEC_DATA).values():
                sec_id = sec.getElementValue(NM_SEC)
#                seq = sec.getElementValue(NM_SEQ)
                rtn[sec_id].update(_proc_msg_sec(sec, msg_type))
        elif msg_type == RESP_REF_HIST:
            sec = message.getElement(NM_SEC_DATA)
            sec_id = sec.getElementValue(NM_SEC)
#            seq = sec.getElementValue(NM_SEQ)
            rtn[sec_id] = _proc_msg_sec(sec, msg_type)
    except SecurityErrors as err:
        print err
    return rtn


def _proc_msg_fld(message):
    """process bb field response"""
    pass

def _proc_msg_fld_cat(message):
    """process bb categorized field response"""
    pass

def _proc_msg_auth(message):
    """process bb authorization response"""
    pass

def _proc_msg_auth_logon(message):
    """process bb logon response"""
    pass

FUNC_RESPONSE = {
    RESP_REF_HIST: _proc_msg_ref,
    RESP_REF_DATA: _proc_msg_ref,
    RESP_FLD: _proc_msg_fld,
    RESP_FLD_CAT: _proc_msg_fld_cat,
    RESP_AUTH: _proc_msg_auth,
    RESP_LOGON: _proc_msg_auth_logon
}

def _proc_msg_sec(sec, msg_type):
    """process bb security"""
    try:
        if sec.hasElement(NM_ERR_SEC):
            raise SecurityErrors(sec.getElement(NM_ERR_SEC))
        try:
            if sec.hasElement(NM_EXC_FLD):
                raise FieldExceptions(sec.getElement(NM_EXC_FLD))
        except FieldException as err:
            print err
        fld_data = sec.getElement(NM_FLD_DATA)
#        a = fld_data.elementDefinition()
#        b = a.typeDefinition()
#        print 'Element type name: ', b.name()
        if msg_type == RESP_REF_DATA:
            rtn = {}
            for fld in fld_data.elements():
                rtn[str(fld.name())] = _proc_msg_sec_data_fld(fld)
        elif msg_type == RESP_REF_HIST:
            rtn = None
            rtn = _proc_msg_sec_hist_fld(fld_data)
    except SecurityError as err:
        print err
    return rtn


def _proc_msg_sec_data_fld(field):
    """process bb security field data"""
    rtn = []
    if field.datatype() == bb.DataType.SEQUENCE:
        lst = []
        row = None
        for val in field.values():
            if row is None:
                row, val_func = create_row_namedtuple(val)
                fld_names = row._fields
            data = []
            for i, element in enumerate(val.elements()):
                try:
                    el_value = val_func[i](element.getValue())
                except ValueError:
                    el_value = None
                data.append(el_value)
            lst.append(row._make(data))
        remove_str_header(lst)
        df_idx = [x for x in fld_names if 'DATE' in x.upper()]
        rtn = pd.DataFrame(lst, columns=fld_names)
        rtn.set_index(df_idx, inplace=True)
    else:
        rtn.append(field.getValue())
    try:
        if len(rtn) == 1:
            rtn = rtn[0]
    except Exception as err:
        print err, type(err)
    return rtn


#def _proc_element(element):
#    """Process securityData element"""
#    if element.isArray():
#        for elem in element.elements():
#            rtn = _proc_element_sec(elem)
#    else:
#        'rtn = _proc_element_fld_data(field_data)'
#    return rtn


def _proc_element_fld_data(element):
    """Process field data"""
    assert element.name() == NM_FLD_DATA, (
        'element type: {0}, expected securityData'.format(element.name()))


def _proc_element_val(element, name, d_type, attempt_convert=False):
    """
    Process element that should contain an element 'name'
    If element exists return it, optionally attempting to convert it from
    a string to another data type (bb data tables often contain headers
    requiring entire table to be sent as string type)
    Return None if element doesn't exist.
    """
    val = None
    if element.hasElement(name):
        field = element.getElement(name)
        fld_complex = field.isComplexType()
        fld_array = field.isArray()
        fld_type = str(field.datatype())
        fld_exp_type = str(d_type)
        fld_val = field.getValue()

        assert field.isValid() and not fld_complex and not fld_array, (
            'field is a complex type or array, expected single value')
        if (attempt_convert and d_type == bb.DataType.STRING and
            fld_type != fld_exp_type):
            try:
                val = FUNC_STR_TO_VAL[fld_exp_type](fld_val)
            except (KeyError, TypeError):
                val = fld_val
        else:
            val = fld_val
    return val


def _proc_element_tbl(element, row_tuple, lst_types):
    """
    Process element containing a data table by rows
    row_tuple: named tuple w/ the field names for the columns
    lst_types: list of datatype conversion functions to use on columns
    Return table as pandas dataframe or None.
    """
    df_tbl = None
    assert element.datatype() == bb.DataType.SEQUENCE, (
        'Data table element of wrong type. Should be SEQUENCE')
    fld_names = row_tuple._fields
    tbl = []
    for row in element.values():
        row_lst = []
        for i, name in enumerate(fld_names):
            row_lst.append(_proc_element_val(element, name,
                                             lst_types[i], True))
        tbl.append(row_tuple._make(row_lst))
    remove_str_header(tbl)
    df_idx = [x for x in fld_names if 'DATE' in x.upper()]
    df_tbl = pd.DataFrame(tbl, columns=fld_names)
    df_tbl.set_index(df_idx, inplace=True)
    return df_tbl


def _proc_msg_sec_hist_fld(field_data):
    """process bb security historical field data"""
    rtn = []
    lst = []
    row = None
    for fld in field_data.values():
        if row is None:
            row, val_func = create_row_namedtuple(fld)
            fld_names = row._fields
        data = []
        for i, element in enumerate(fld.elements()):
            try:
                el_value = val_func[i](element.getValue())
            except (ValueError, TypeError):
                el_value = None
            data.append(el_value)
        lst.append(row._make(data))
    remove_str_header(lst)
    df_idx = [x for x in fld_names if 'DATE' in x.upper()]
    rtn = pd.DataFrame(lst, columns=fld_names)
    rtn.set_index(df_idx, inplace=True)
    return rtn


def create_row_namedtuple(element):
    """self explanotory"""
    names = [str(x.name()).replace(' ', '_') for x in element.elements()]
    func = FUNC_STR_TO_VAL
    val_func = [func[next((k for k in func if k in n.upper()), 'FLOAT')]
                for n in names]
    row = collections.namedtuple('row', names, rename=True)
    return row, val_func


def remove_str_header(lst):
    """bloomberg responses sometimes include header rows, this removes them"""
    if (all([isinstance(x, (str, type(None))) for x in lst[0]]) and
        not all([isinstance(x, (str, type(None))) for x in lst[1]])):
        lst = lst[1:]


def ref_req_data(identifiers=(),
                 fields=(),
                 overrides=(),
                 session=None):
    """wrapper function to normalize inputs for refdata request"""
    kwargs = locals().copy()
    try:
        rtn = None
        flds = tuple(fields) + ('ID_CUSIP', 'NAME')
        kwargs.update(_ref_req_inputs(identifiers, flds, overrides))
        rtn = _ref_req_data(**kwargs)
    except Exception as err:
        print err
    return rtn


@_memo
@_session_decorator
def _ref_req_data(identifiers=(),
                  fields=(),
                  overrides=(),
                  session=None):
    """main function to create a refdata request"""
    try:
        rtn = None
        req = _get_ref_req(session, REQ_REF_DATA)
        _ref_req_base(req, identifiers, fields, overrides)
        print 'Sending to bb...'#, '\n', req
        session.sendRequest(req)
        rtn = _proc_events(session)
    except _Error as err:
        print err
    return rtn


def ref_req_hist(identifiers=(),
                 fields=(),
                 overrides=(),
                 session=None,
                 startDate=dt.date(TODAY.year, TODAY.month - 1,
                                  TODAY.day).strftime("%Y%m%d"),
                 endDate=TODAY.strftime("%Y%m%d"),
                 periodicityAdjustment=None,
                 periodicitySelection=None,
                 currency=None,
                 overrideOption=None,
                 pricingOption=None,
                 nonTradingDayFillOption=None,
                 nonTradingDayFillMethod=None,
                 maxDataPoints=None,
                 returnEids=None,
                 returnRelativeDate=None,
                 adjustmentNormal=None,
                 adjustmentAbnormal=None,
                 adjustmentSplit=None,
                 adjustmentFollowDPDF=None,
                 calendarCodeOverride=None,
                 calendarOverrides=(),
                 calendarOverridesOperation='CDR_AND'):
    """wrapper function to normalize inputs for historical refdata request"""
    kwargs = locals().copy()
    try:
        rtn = None
        kwargs['startDate'] = _bbg_dt_ip(startDate)
        kwargs['endDate'] = _bbg_dt_ip(endDate)

        kwargs.update(_ref_req_inputs(identifiers, fields, overrides))
        rtn = _ref_req_hist(**kwargs)
    except Exception as err:
        print err, type(err)
    return rtn


@_memo
@_session_decorator
def _ref_req_hist(identifiers=None,
                  fields=None,
                  overrides=None,
                  session=None,
                  startDate=dt.date(TODAY.year, TODAY.month - 1,
                                   TODAY.day).strftime("%Y%m%d"),
                  endDate=TODAY.strftime("%Y%m%d"),
                  **kw):
    """main function to create historical refdata request"""
    kwargs = locals().copy()
    element_dict = kwargs.copy()
    cal_ovds = element_dict.pop('calendarOverrides', None)
    cal_ovds_op = element_dict.pop('calendarOverridesOperation', None)
    pop_list = ['identifiers', 'fields', 'overrides', 'session', 'kw']
    for already_processed in pop_list:
        element_dict.pop(already_processed, None)

    try:
        rtn = None
        req = _get_ref_req(session, REQ_REF_HIST)
        _ref_req_base(req, identifiers, fields, overrides)
        _req_set_elements(req, element_dict)
        _add_calendar_overrides(req, cal_ovds, cal_ovds_op)

        print 'Sending to bb...'#, '\n', req
        session.sendRequest(req)
        rtn = _proc_events(session)
    except _Error as err:
        print err
    return rtn


def _ref_req_inputs(identifiers=None,
                    fields=None,
                    overrides=None):
    """normalize base inputs - tuples used to allow memoization"""
    rtn = locals().copy()
    try:
        if identifiers is not None and fields is not None:
            rtn['identifiers'] = _sorted_unq_tuple(identifiers)
            rtn['fields'] = _sorted_unq_tuple(fields)
            if overrides is not None:
                try:
                    if type(overrides) == dict:
                        rtn['overrides'] = tuple(sorted({OvdNamedTuple(f, v)
                                     for f, v in overrides.items()},
                                     key=lambda fld: fld.fieldId))
                    else:
                        rtn['overrides'] = tuple(sorted({OvdNamedTuple(f, v)
                                     for f, v in overrides},
                                     key=lambda fld: fld.fieldId))
                except Exception as err:
                    print err
    except Exception as err:
        print err
    return rtn


def _get_ref_req(session, req_type):
    """get bb service"""
    service = session.getService(SVC_REF)
    req = service.createRequest(req_type)
    return req


def _ref_req_base(request,
                  identifiers,
                  fields,
                  overrides=None):
    """add the base inputs to refdata request"""
    secs = request.getElement(NM_SECS)
    _append_value(secs, identifiers, "Error with Identifier input values")

    flds = request.getElement(NM_FLDS)
    _append_value(flds, fields, "Error with Field input values")

    if overrides is not None:
        ovds = request.getElement(NM_OVDS)
        _append_overrides(ovds, overrides)


def _append_value(element, values, err_msg=''):
    """append values to request"""
    try:
        map(element.appendValue, values)
    except Exception as err:
        print err
        raise InputError(err_msg)


def _append_overrides(ovds_elem, overrides):
    """append overrides to request"""
    def _add_ovd(ovd_tuple):
        """append override to overrides"""
        ovd = ovds_elem.appendElement()
        ovd.setElement(NM_FLD_ID, ovd_tuple.fieldId)
        ovd.setElement(NM_VAL, ovd_tuple.value)

    try:
        if overrides is not None:
            map(_add_ovd, overrides)
    except Exception as err:
        print err
        raise InputError("Error with Override input values")


def _add_calendar_overrides(request,
                            ovds_lst=(),
                            ovds_op='CDR_AND'):
    """"append calendar overrides to historical request"""
    try:
        if ovds_lst:
            cdr_ovds_info = request.getElement(NM_CAL_OVDS_INFO)
            cdr_ovds_info.setElement(NM_CAL_OVDS_OP, ovds_op)
            cdr_ovds = cdr_ovds_info.getElement(NM_CAL_OVDS)
            for ovd in ovds_lst:
                cdr_ovds.appendValue(ovd)
    except Exception as err:
        print err
        raise InputError("Error with Calendar Override input values")


def _req_set_elements(request, kw_dict):
    """set element values for request"""
    for key, val in kw_dict.items():
        if val is not None:
            request.set(bb.Name(key), val)


def _sorted_unq_tuple(itr):
    """create a tuple of sorted unique values"""
    try:
        return tuple(sorted({x.upper() for x in itr}))
    except Exception as err:
        print err, type(err)


def _test_ref_data(num_trials=1):
    """test refdata request..."""
    secs = ['31392DR20 Mtge', '31394CCV2 Mtge', '31395NE86 Mtge',
            '38377YLW8 Mtge', '31392MEN8 Mtge']
#    secs = ['31392DR20 Mtge']
    flds = ['PX_BID', 'NAME', 'SETTLE_DT', 'PX_BID', 'MTG_CASH_FLOW']
    ovds = [('MTG_PREPAY_TYP', 'CPR'), ('PREPAY_SPEED_VECTOR', '18 24 R 10')]

    trials = []
    tic = time.clock()
    try:
        with Session() as session:
            for i in xrange(num_trials):
                with _Timer() as timer:
                    rtn = ref_req_data(secs, flds, ovds, session)
                trials.append(timer.interval)
    finally:
        pass
    print rtn
    for key, val in rtn.items():
        print key, len(val)
    print ('Total time for {:d} trials: {:.2f} Average time: {:.2f}'.format(
           num_trials, time.clock() - tic, np.average(trials)))


def _test_ref_hist(num_trials=1):
    """test historical refdata request..."""
    secs = ['XMIYX US Equity', 'XBLJX US Equity', 'NUJ US Equity',
            'NEA US Equity', 'PZC US Equity']
#    secs = ['XMIYX US Equity', 'XBLJX US Equity']
    flds = ['PX_LAST', 'PX_VOLUME']
    ovds = []

    trials = []
    tic = time.clock()
    try:
        with Session() as session:
            for i in xrange(num_trials):
                with _Timer() as timer:
                    rtn = ref_req_hist(secs, flds, ovds, session,
                                       dt.date(2011, 03, 01))
                trials.append(timer.interval)
    finally:
        pass
#    print rtn
    for key, val in rtn.items():
        df1 = val['PX_LAST']
        df2 = pd.rolling_mean(df1, 30)
        df3 = pd.rolling_std(df1, 30)
#        df3 = val['PX_VOLUME']

        plt.figure(1)
        df1.plot()

        plt.figure(2)
        df2.plot()

        plt.figure(3)
        df3.plot()

#        print key, type(val), len(val)
    print ('Total time for {:d} trials: {:.2f} Average time: {:.2f}'.format(
           num_trials, time.clock() - tic, np.average(trials)))


def run_tests(num_trials=1):
    """run the tests..."""
    tic = time.clock()
#    _test_ref_data(num_trials)
    _test_ref_hist(num_trials)
    print ('Total time for {:d} trials: {:.2f}'.format(
           num_trials, time.clock() - tic))


def main():
    """main function..."""
    run_tests(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "Ctrl+C pressed. Stopping..."
