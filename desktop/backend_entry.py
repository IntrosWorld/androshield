"""Private desktop server. No effect on the normal uvicorn/web entry point."""
import asyncio
import hmac
import json
import os
from pathlib import Path
import socket
import sys
import threading


class DesktopGate:
    def __init__(self, app, token):
        self.app, self.token = app, token

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http':
            headers = dict(scope['headers'])
            supplied = headers.get(b'x-desktop-token', b'').decode('ascii', errors='replace')
            if not hmac.compare_digest(supplied, self.token):
                await send({'type': 'http.response.start', 'status': 403, 'headers': []})
                await send({'type': 'http.response.body', 'body': b'Forbidden'})
                return
        await self.app(scope, receive, send)


def main():
    # Configuration travels over the parent pipe, never command-line arguments.
    config = json.loads(sys.stdin.readline())
    data = Path(config['data']).resolve()
    data.mkdir(parents=True, exist_ok=True)
    os.environ['DATABASE_URL'] = 'sqlite:///' + (data / 'analyzer.db').as_posix()
    os.environ['APK_FRONTEND_DIR'] = config['frontend']
    os.environ['APK_DESKTOP_DATA_DIR'] = str(data)
    if getattr(sys, 'frozen', False):
        os.environ['APK_DESKTOP_RESOURCE_DIR'] = sys._MEIPASS
    os.environ['PYTHONUNBUFFERED'] = '1'
    if not getattr(sys, 'frozen', False):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
    import uvicorn
    from app.main import app
    server = uvicorn.Server(uvicorn.Config(DesktopGate(app, config['token']),
        host='127.0.0.1', port=0, log_level='warning', access_log=False, loop='asyncio'))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    sock.listen(128)

    def parent_watch():
        # EOF also stops the backend if Electron crashes.
        sys.stdin.readline()
        server.should_exit = True
    threading.Thread(target=parent_watch, daemon=True).start()

    async def serve():
        task = asyncio.create_task(server.serve(sockets=[sock]))
        while not server.started and not task.done():
            await asyncio.sleep(0.05)
        if server.started:
            print(json.dumps({'port': sock.getsockname()[1]}), flush=True)
        await task
    asyncio.run(serve())


if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()
    main()
