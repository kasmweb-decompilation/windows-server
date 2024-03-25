# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.19 (default, Mar 25 2024, 14:51:23) 
# [GCC 12.2.0]
# Embedded file name: server.py
import os, io, argparse, yaml, re, logging, traceback, requests, sys, socket, json, threading
if os.name != "nt":
    from os import statvfs
else:
    import shutil
from util import get_aspect_ratio, get_safe_filename
from flask import Flask, abort, request, make_response, jsonify, send_file, send_from_directory, render_template
from werkzeug.exceptions import HTTPException
from subprocess import run
import psutil, jwt
from functools import wraps
from PIL import Image
from agents.windows_agent import WindowsAgent
from log_handler import KasmLogHandler
app = Flask(__name__)
listing_blacklist_expression = re.compile("^[$]")
agent = None
logger = logging.getLogger(__name__)

def token_required(f):

    @wraps(f)
    def wrapped(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].replace("Bearer ", "")
        if not token:
            return make_response("Token is missing", 401)
        try:
            decoded_token = jwt.decode(token, (agent.public_key), algorithms=["RS256"])
        except Exception as ex:
            logger.error(f"Invalid token recieved: {ex}")
            return make_response("Invalid token", 401)
        else:
            username = decoded_token["system_username"] if "system_username" in decoded_token else None
            setattr(request, "username", username)
            setattr(request, "fully_qualified_username", request.username)
            if username:
                request.username = request.username.split("@")[0]
            setattr(request, "user_id", decoded_token["user_id"] if "user_id" in decoded_token else None)
            return f(*args, **kwargs)

    return wrapped


@app.route("/__healthcheck", methods=["GET", "OPTIONS"])
@token_required
def healthcheck():
    if request.method == "OPTIONS":
        return make_response(('ok', 200))
    if request.method == "GET":
        memory_stats = psutil.virtual_memory()
        disk_stats = psutil.disk_usage("/")
        stats = {'cpu_usage':(psutil.cpu_percent)(), 
         'memory_usage':memory_stats.percent, 
         'disk_usage':disk_stats.percent}
        return make_response((jsonify(stats), 200))


@app.route("/session_start", methods=["POST", "OPTIONS"])
@token_required
def session_start():
    if request.method == "OPTIONS":
        return make_response(('ok', 200))
    logger.debug("Session start initiated.")
    payload = json.loads(request.data)
    threading.Thread(target=(agent.session_start), args=(payload,)).start()
    return make_response(('ok', 200))


@app.route("/session_end", methods=["POST", "OPTIONS"])
@token_required
def session_end():
    if request.method == "OPTIONS":
        return make_response(('ok', 200))
    logger.debug("Session end initiated.")
    payload = json.loads(request.data)
    threading.Thread(target=(agent.session_end), args=(payload,)).start()
    return make_response(('ok', 200))


@app.route("/upload", methods=["POST", "OPTIONS"])
@token_required
def upload():
    if request.method == "OPTIONS":
        return make_response(('ok', 200))
    if request.method == "POST":
        logger.debug(f"Upload request from {request.username}")
        upload_dir = agent.get_user_downloads_dir(request.username)
        if not (upload_dir and os.path.isdir(upload_dir)):
            upload_dir = agent.default_upload_dir
        if not (upload_dir and os.path.isdir(upload_dir)):
            logger.error("Invalid upload directory (%s)" % upload_dir)
            return make_response("Invalid upload directory path", 500)
        file = request.files["file"]
        current_chunk = int(request.form["dzchunkindex"])
        save_path = os.path.join(upload_dir, get_safe_filename(file.filename))
        if os.path.exists(save_path):
            if current_chunk == 0:
                return make_response(('File already exists', 400))
            save_path = os.path.join(upload_dir, "." + get_safe_filename(file.filename) + ".uploading")
            if os.path.exists(save_path):
                if current_chunk == 0:
                    os.remove(save_path)
                    logger.info("Incomplete file %s has been deleted" % file)
                if current_chunk == 0:
                    if os.name != "nt":
                        syssize = statvfs(upload_dir)
                        space = syssize.f_bsize * syssize.f_bavail
                        if space - int(request.form["dztotalfilesize"]) < 0:
                            return make_response(('No Space available', 400))
                    else:
                        (total, used, free) = shutil.disk_usage(upload_dir)
                        space = 8 * free
                        if space - int(request.form["dztotalfilesize"]) < 0:
                            return make_response(('No Space available', 400))
        try:
            with open(save_path, "ab") as f:
                f.seek(int(request.form["dzchunkbyteoffset"]))
                f.write(file.stream.read())
        except OSError:
            logger.error("Could not write to file")
            return make_response(("Couldn't write the file to disk", 500))
        else:
            total_chunks = int(request.form["dztotalchunkcount"])
            if current_chunk + 1 == total_chunks:
                if os.path.getsize(save_path) != int(request.form["dztotalfilesize"]):
                    logger.error("File %s was completed, but has a size mismatch.Was %s but we expected %s " % (
                     file.filename, os.path.getsize(save_path), request.form["dztotalfilesize"]))
                    os.remove(save_path)
                    logger.info("Incomplete file %s has been deleted" % file.filename)
                    return make_response(('Size mismatch', 500))
                os.rename(save_path, os.path.join(upload_dir, get_safe_filename(file.filename)))
                logger.info("File %s has been uploaded successfully" % file.filename)
            else:
                logger.debug("Chunk %d of %d for file %s complete" % (
                 current_chunk + 1, total_chunks, file.filename))
            return make_response(('uploaded Chunk', 200))


@app.route("/Downloads/Downloads/", methods=["GET", "OPTIONS"])
@app.route("/Downloads/Downloads/<path:path>", methods=["GET", "OPTIONS"])
@token_required
def list_or_download(path='./'):
    if request.method == "OPTIONS":
        return make_response(('ok', 200))
    if request.method == "GET":
        download_dir = agent.get_user_downloads_dir(request.username)
        if not (download_dir and os.path.isdir(download_dir)):
            download_dir = agent.default_download_dir
        if not (download_dir and os.path.isdir(download_dir)):
            logger.error("Invalid download directory (%s)" % download_dir)
            return make_response("Invalid download directory path", 500)
        full_path = os.path.abspath(os.path.join(download_dir, path))
        full_path_common_prefix = os.path.commonprefix([os.path.realpath(full_path), download_dir])
        if full_path_common_prefix != download_dir:
            logger.error("A traversal path was used: %s" % path)
            abort(404)
        show_hidden_files = request.args.get("show_hidden", 0, int) == 1
        if os.path.isdir(full_path):
            listing = []
            for name in os.listdir(full_path):
                if listing_blacklist_expression.match(name):
                    pass
                else:
                    if not show_hidden_files or agent.is_file_hidden(os.path.join(full_path, name)):
                        pass
                    else:
                        listing.append({'type':"dir" if (os.path.isdir(os.path.join(download_dir, path, name))) else "file", 
                         'name':name})
                    return render_template("listing.html", directory=path, listing=listing)

            return send_from_directory(download_dir, path)


@app.route("/screenshot", methods=["POST", "OPTIONS"])
@token_required
def take_screenshot():
    if request.method == "OPTIONS":
        return make_response(('ok', 200))
    if request.method == "POST" or request.method == "GET":
        if agent.is_multi_user:
            if not agent.is_user_sso:
                return make_response("Screenshots are disabled for this user", 403)
        screenshot_path = agent.screenshot(request.username)
        if screenshot_path:
            try:
                image = Image.open(screenshot_path)
                width = int(request.args.get("width", 300))
                height = int(width * get_aspect_ratio())
                image = image.resize((width, height), Image.Resampling.LANCZOS)
                image_data = io.BytesIO()
                image.save(image_data, "PNG")
                image_data.seek(0)
                return send_file(image_data, mimetype="image/png")
            except Exception as e:
                logger.error(f"Error creating screenshot: {e}")
                return make_response((str(e), 500))

    else:
        return make_response(('Screenshot not found.', 404))


@app.errorhandler(Exception)
def log_errors(e):
    code = 500
    if isinstance(e, HTTPException):
        code = e.code
    tb = traceback.format_exc()
    logger.error("%s %s %s - %s\n %s", request.remote_addr, request.method, request.full_path, code, tb)
    return (
     jsonify(error=(str(e))), code)


@app.after_request
def log_request(response):
    if response.status_code >= 400 and response.status_code <= 431:
        logger.error("%s %s %s %s %s - %s", request.remote_addr, request.method, request.scheme, request.full_path, response.status, str(response.data))
    elif response.status_code >= 200:
        if response.status_code <= 307:
            logger.info("%s %s %s %s %s", request.remote_addr, request.method, request.scheme, request.full_path, response.status)
    return response


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--cfg", dest="cfg", required=False, help="Path to app config", default="config.yaml")
        parser.add_argument("--debug", dest="debug", required=False, help="Debug mode", default=0)
        parser.add_argument("--register-token", dest="register_token", required=False, help="Register agent with Kasm Workspaces deployment.", default=None)
        parser.add_argument("--register-host", dest="register_host", required=False, help="Hostname of the Kasm Workspaces deployment.", default=None)
        parser.add_argument("--register-port", dest="register_port", required=False, help="Port number of the Kasm Workspaces deployment.", default=443)
        parser.add_argument("--server-id", dest="server_id", required=False, help="The ServerID in Kasm Workspaces for this server.", default=None)
        (args, unknown) = parser.parse_known_args()
        log_level = logging.DEBUG if args.debug == "1" else logging.INFO
        if log_level == logging.DEBUG or args.register_token:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
            logger.addHandler(handler)
        agent = WindowsAgent(args.cfg, logger)
        handler = KasmLogHandler(agent.agent_jwt_token, agent.api_host, agent.api_port, agent.hostname)
        logger.addHandler(handler)
        if agent.debug:
            log_level = logging.DEBUG
        logger.setLevel(log_level)
        if agent.log_file:
            handler = logging.FileHandler(agent.log_file)
            handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
            logger.addHandler(handler)
        if args.register_token and args.register_host and args.server_id:
            if agent.register(args.register_token, args.server_id, args.register_host, args.register_port):
                logger.info("Server agent successfully registered, be sure to restart the service.")
                sys.exit(0)
            else:
                sys.exit(1)
        else:
            if args.register_token or args.register_host:
                logger.error("To register the server, you must provide the --register-token, --register-host, and --server-id arguments.")
                sys.exit(1)
        agent.startup()
        threading.Thread(target=(agent.ready)).start()
        logger.info(f"Starting Kasm Upload Server On Port {agent.port}")
        if agent.ssl:
            app.run(debug=(args.debug == "1"), host="0.0.0.0", port=(agent.port), ssl_context=(agent.server_public_key, agent.server_private_key))
        else:
            app.run(debug=(args.debug == "1"), host="0.0.0.0", port=(agent.port))
    except Exception as e:
        try:
            tb = traceback.format_exc()
            print(tb)
            logger.error(tb)
        finally:
            e = None
            del e

# okay decompiling agent/server.pyc
