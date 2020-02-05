#!/usr/bin/env python3
"""
Simple Sanic example that uses websockets to show the processor usage on a website
Author: Arjan de Haan (Vepnar)
Version: 0.1
Last edited: 05-02-2020
"""

import asyncio
import psutil
from sanic import Sanic
from sanic.response import file
from sanic.websocket import WebSocketProtocol

APP = Sanic(name='Sanic websocket example')

@APP.route('/')
async def index(_):
    """Send a html file as root"""
    return await file('websocket.html')

@APP.websocket('/socket')
async def socket(_, websocket):
    """Process websocket requests at /socket"""
    while True:
        await asyncio.sleep(1)
        item = psutil.cpu_percent(interval=1, percpu=False)
        await websocket.send(str(item))

if __name__ == '__main__':
    APP.run(host='0.0.0.0', port=8000, protocol=WebSocketProtocol)
