#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple Sanic example that jinja2 to process html files async
Author: Arjan de Haan (Vepnar)
Version: 0.1
Last edited: 05-02-2020
"""

import psutil
import jinja2
from sanic import Sanic, response

APP = Sanic(name='Html fomatter example')

ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader('./templates'),
    enable_async=True
)

async def format_html(html_file, **kwargs):
    """Format a html file with just the name and kwargs"""
    template = ENV.get_template(html_file)
    formatted_template = await template.render_async(**kwargs)
    return response.html(formatted_template)

@APP.route('/')
async def index(_):
    """Listen to the root directory on the web server"""
    return await format_html(
        'index.html', usage=psutil.net_io_counters()._asdict()
        )

if __name__ == '__main__':
    APP.run(host='0.0.0.0', port=8000)
