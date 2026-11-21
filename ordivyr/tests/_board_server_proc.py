"""Test helper: ONE Board server process (API + lease API + scheduler/reaper loop) over a shared PostgreSQL database. Prints {"api":port,"lease":port} then runs until killed."""
import json, sys, time
from ordivyr.board.service import Board
from ordivyr.board.api import serve
from ordivyr.board.coordinator import BoardCoordinator

home, dsn = sys.argv[1], sys.argv[2]
b = Board(home, dsn=dsn); co = BoardCoordinator(b, port=0).start(); api = serve(b, "127.0.0.1", 0); b.lease_url = f"http://127.0.0.1:{co.port}"; b.allow_local_endpoints = True; b.fleet_lease_s = 3.0; b.start_loop(0.5)
print(json.dumps({"api": api.server_address[1], "lease": co.port}), flush=True)
while True: time.sleep(3600)
