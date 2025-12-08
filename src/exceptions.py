# -*- coding: utf-8 -*-
from __future__ import annotations


class VulnParserError(Exception):
    pass


class DriverNotFoundError(VulnParserError):
    pass


class PageLoadError(VulnParserError):
    pass


class PageNotFoundError(VulnParserError):
    pass


class ParseError(VulnParserError):
    pass


class SaveToExcelError(VulnParserError):
    pass
